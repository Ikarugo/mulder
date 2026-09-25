"""Scheduled tasks read from their XML and from the SOFTWARE hive's TaskCache.

Without a parser, a task's command line was only known if an agent thought
of opening the XML file; on one run it did not, and the report inferred the
command "from timing". These tests pin ``parse_scheduled_tasks`` on a
triage collection: the XML and TaskCache decoders, the checks that need
both (hidden tasks, deleted XML, tampered registry actions) and the
transparency of what was not read.

The Actions and DynamicInfo byte strings are the examples published in
"Windows Registry Analysis - Today's Episode: Tasks" (cyber.wtf, 2022).
"""

from __future__ import annotations

import struct
import uuid
from pathlib import Path
from typing import Any

import pytest

from mulder.server.tools.extract import scheduled_tasks as st
from tests.regf_builder import Key, build_hive

_TASKCACHE = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"

# Exec action "calc", context "Author" (cyber.wtf).
_CALC_ACTIONS = bytes.fromhex(
    "0300"
    "0c000000" + "41007500740068006f007200"
    "6666"
    "00000000"
    "08000000" + "630061006c006300"
    "00000000"
    "00000000"
    "0000"
)
# Last run failed with 0x80070002 (cyber.wtf).
_FAILED_DYNAMIC_INFO = bytes.fromhex(
    "03000000e9792df1311cd8016276133b331cd80100000000020007804c30753b331cd801"
)


def _bstr(text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return struct.pack("<I", len(raw)) + raw


def _exec_blob(command: str, arguments: str = "", context: str = "Author") -> bytes:
    return (
        struct.pack("<H", 3)
        + _bstr(context)
        + struct.pack("<H", 0x6666)
        + _bstr("")
        + _bstr(command)
        + _bstr(arguments)
        + _bstr("")
        + b"\x00\x00"
    )


def _filetime(iso: str) -> int:
    from datetime import datetime, timezone

    dt = datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((dt - epoch).total_seconds()) * 10_000_000


def _dynamic_info(registered: str, last_run: str | None = None) -> bytes:
    last = _filetime(last_run) if last_run else 0
    return struct.pack("<IQQII", 3, _filetime(registered), last, 0, 0) + struct.pack("<Q", last)


def _task_xml(
    command: str,
    arguments: str = "",
    *,
    author: str = "WS01\\bob",
    date: str = "2024-11-06T01:58:00",
    user: str = "S-1-5-21-1-2-3-1001",
    hidden: bool = False,
    encoding: str = "utf-16",
) -> bytes:
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{date}</Date>
    <Author>{author}</Author>
    <URI>\\Whatever</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>2024-11-06T01:58:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <LogonTrigger><Enabled>false</Enabled><UserId>WS01\\bob</UserId></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings><Enabled>true</Enabled><Hidden>{"true" if hidden else "false"}</Hidden></Settings>
  <Actions Context="Author">
    <Exec><Command>{command}</Command><Arguments>{arguments}</Arguments></Exec>
  </Actions>
</Task>
"""
    return xml.encode(encoding)


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


class TestDecoders:
    def test_published_actions_example(self) -> None:
        decoded = st.parse_actions_blob(_CALC_ACTIONS)
        assert decoded["version"] == 3
        assert decoded["context"] == "Author"
        assert decoded["actions"] == [
            {"type": "exec", "command": "calc", "arguments": "", "working_directory": ""}
        ]
        assert "error" not in decoded

    def test_published_dynamic_info_example(self) -> None:
        info = st.parse_dynamic_info(_FAILED_DYNAMIC_INFO)
        assert info["last_result"] == "0x80070002"
        assert str(info["registered_utc"]).startswith("2022-")
        assert info["registered_utc"] < info["last_run_utc"]  # type: ignore[operator]
        assert "last_success_utc" in info

    def test_com_handler_action(self) -> None:
        clsid = uuid.UUID("{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}")
        blob = (
            struct.pack("<H", 3)
            + _bstr("LocalSystem")
            + struct.pack("<H", 0x7777)
            + _bstr("")
            + clsid.bytes_le
            + _bstr("<Data/>")
        )
        (action,) = st.parse_actions_blob(blob)["actions"]
        assert action == {
            "type": "com",
            "class_id": "{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}",
            "data": "<Data/>",
        }

    def test_legacy_action_types_stop_decoding_and_say_so(self) -> None:
        blob = (
            struct.pack("<H", 3)
            + _bstr("Author")
            + struct.pack("<H", 0x8888)
            + _bstr("")
            + _bstr("to@example.org")
        )
        decoded = st.parse_actions_blob(blob)
        assert decoded["actions"] == [{"type": "email"}]
        assert "not decoded" in decoded["error"]

    def test_truncated_actions_keep_what_was_read_and_say_so(self) -> None:
        blob = _exec_blob("a.exe") + struct.pack("<H", 0x6666) + struct.pack("<I", 400)
        decoded = st.parse_actions_blob(blob)
        assert [a["command"] for a in decoded["actions"]] == ["a.exe"]
        assert "overruns" in decoded["error"]

    @pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-8"])
    def test_task_xml_in_any_encoding(self, encoding: str) -> None:
        task = st.parse_task_xml(_task_xml("powershell.exe", "-File x.ps1", encoding=encoding))
        assert task["actions"][0]["command"] == "powershell.exe"
        assert task["principal"] == {
            "user_id": "S-1-5-21-1-2-3-1001",
            "logon_type": "InteractiveToken",
            "run_level": "HighestAvailable",
        }
        time_trigger, logon_trigger = task["triggers"]
        assert time_trigger["repeat_every"] == "PT5M"
        assert logon_trigger["enabled"] is False
        assert task["author"] == "WS01\\bob"

    def test_not_task_xml(self) -> None:
        import xml.etree.ElementTree as ET

        with pytest.raises(ET.ParseError):
            st.parse_task_xml(b"<Other/>")
        with pytest.raises(ET.ParseError):
            st.parse_task_xml(b"\x00\x01garbage")


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


@pytest.fixture()
def case(tmp_path: Path) -> Path:
    """An open case over a triage collection; returns the volume root."""
    from mulder.server.app import _tool_dispatch_sync, init_server

    root = tmp_path / "evidence" / "WS01" / "C"
    (root / "Windows" / "System32" / "config").mkdir(parents=True)
    (root / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"regf")
    init_server(db_dir=tmp_path / "cases")
    result = _tool_dispatch_sync["scan_evidence"](
        evidence_path=str(tmp_path / "evidence"), case_id="tasks"
    )
    assert result["status"] == "success", result
    return root


def _call(name: str, **kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync[name](**kwargs)  # type: ignore[no-any-return]


def _parse(root: Path) -> dict[str, Any]:
    """Run the tool; returns its payload with the top-level status copied in."""
    result = _call("parse_scheduled_tasks", image_path=str(root))
    payload: dict[str, Any] = dict(result.get("results") or {})
    payload["status"] = result["status"]
    for key in ("tool_warning", "error_type", "error_message"):
        if key in result:
            payload[key] = result[key]
    return payload


def _indexed_text() -> str:
    """Everything indexed as tasks.scheduled, unabridged."""
    from mulder.server.app import get_ctx

    windows = get_ctx().db.get_windows_by_source_prefix("tasks.scheduled")
    return "\n".join(w.raw_text for w in windows)


def _write_task(root: Path, task_path: str, data: bytes) -> None:
    path = root / "Windows" / "System32" / "Tasks" / task_path.strip("\\").replace("\\", "/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _cache_task(
    hive: Key,
    task_path: str,
    guid: str,
    actions: bytes,
    *,
    registered: str = "2024-11-06T01:58:15",
    last_run: str | None = None,
    sd: bool = True,
    category: str = "Plain",
) -> None:
    tree = hive.key(_TASKCACHE + "\\Tree" + task_path)
    tree.sz("Id", guid).dword("Index", 3)
    if sd:
        tree.binary("SD", b"\x01\x00\x04\x80" + b"\x00" * 16)
    hive.key(_TASKCACHE + "\\Tasks\\" + guid).sz("Path", task_path).binary(
        "Actions", actions
    ).binary("DynamicInfo", _dynamic_info(registered, last_run))
    hive.key(_TASKCACHE + "\\" + category + "\\" + guid)


def _software(root: Path, hive: Key, *, dirty: bool = False) -> None:
    build_hive(root / "Windows" / "System32" / "config" / "SOFTWARE", hive, dirty=dirty)


def _by_task(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {t["task"]: t for t in result["to_review"]}


_EVIL_ARGS = (
    "-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Users\\bob\\AppData\\Local\\Temp\\u.ps1"
)


class TestParseScheduledTasks:
    def test_xml_and_taskcache_are_merged(self, case: Path) -> None:
        _write_task(case, "\\Updater", _task_xml("powershell.exe", _EVIL_ARGS))
        _write_task(
            case,
            "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
            _task_xml("%windir%\\system32\\defrag.exe", "-c -h -o", author="Microsoft"),
        )
        hive = Key()
        _cache_task(
            hive,
            "\\Updater",
            "{A4F7ED3E-0000-0000-0000-000000000001}",
            _exec_blob("powershell.exe", _EVIL_ARGS),
            last_run="2024-11-06T02:52:01",
        )
        _cache_task(
            hive,
            "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
            "{00000000-0000-0000-0000-000000000002}",
            _exec_blob("%windir%\\system32\\defrag.exe", "-c -h -o"),
            category="Maintenance",
        )
        _software(case, hive)

        result = _parse(case)
        assert result["status"] == "success", result
        assert result["tasks"] == 2
        assert result["from_xml"] == 2 and result["from_taskcache"] == 2

        review = _by_task(result)
        assert set(review) == {"\\Updater"}  # the built-in task is not flagged
        updater = review["\\Updater"]
        assert updater["actions"] == [f"exec powershell.exe {_EVIL_ARGS}"]
        assert updater["registered_utc"] == "2024-11-06T01:58:15Z"
        assert updater["last_run_utc"] == "2024-11-06T02:52:01Z"
        assert updater["guid"] == "{A4F7ED3E-0000-0000-0000-000000000001}"
        reasons = " ".join(updater["reasons"])
        assert updater["notes"] == ["outside the \\Microsoft\\ folder"]
        assert "user-writable path" in reasons
        assert "powershell.exe with script, download or evasion arguments" in reasons

        hits = _call("search", query="Updater", source="tasks.scheduled")
        assert hits["result_count"] >= 1
        text = _indexed_text()
        assert "exec powershell.exe -ExecutionPolicy Bypass" in text
        assert "[REVIEW:" in text
        assert "triggers: TimeTrigger start=2024-11-06T01:58:00 repeat_every=PT5M" in text

    def test_hidden_deleted_and_tampered_tasks(self, case: Path) -> None:
        benign = _task_xml("%windir%\\system32\\defrag.exe")
        _write_task(case, "\\Microsoft\\Windows\\Hidden", benign)
        _write_task(case, "\\Microsoft\\Windows\\Tampered", benign)
        _write_task(case, "\\Microsoft\\Windows\\Unregistered", benign)
        hive = Key()
        blob = _exec_blob("%windir%\\system32\\defrag.exe")
        _cache_task(hive, "\\Microsoft\\Windows\\Hidden", "{G1}", blob, sd=False)
        _cache_task(hive, "\\Microsoft\\Windows\\Tampered", "{G2}", _exec_blob("cmd.exe", "/c x"))
        _cache_task(hive, "\\Microsoft\\Windows\\Ghost", "{G3}", blob)
        _software(case, hive)

        review = _by_task(_parse(case))
        assert any("Tarrask" in r for r in review["\\Microsoft\\Windows\\Hidden"]["reasons"])
        assert (
            "actions in the XML and in the registry differ"
            in (review["\\Microsoft\\Windows\\Tampered"]["reasons"])
        )
        ghost = review["\\Microsoft\\Windows\\Ghost"]
        assert any("XML file is missing" in r for r in ghost["reasons"])
        assert ghost["actions"] == ["exec %windir%\\system32\\defrag.exe"]
        assert (
            "XML file present but not registered in TaskCache"
            in (review["\\Microsoft\\Windows\\Unregistered"]["reasons"])
        )
        text = _indexed_text()
        assert "registry actions: exec cmd.exe /c x" in text

    def test_joined_by_guid_and_orphans_reported(self, case: Path) -> None:
        _write_task(case, "\\Microsoft\\Windows\\A", _task_xml("%windir%\\system32\\a.exe"))
        hive = Key()
        blob = _exec_blob("%windir%\\system32\\a.exe")
        # Tree -> GUID join works even when Tasks\{GUID} has no Path value.
        hive.key(_TASKCACHE + "\\Tree\\Microsoft\\Windows\\A").sz("Id", "{GA}").binary(
            "SD", b"\x01"
        )
        hive.key(_TASKCACHE + "\\Tasks\\{GA}").binary("Actions", blob).binary(
            "DynamicInfo", _dynamic_info("2024-01-01T00:00:00")
        )
        # A second, stale Tasks entry claiming the same path.
        hive.key(_TASKCACHE + "\\Tasks\\{GB}").sz("Path", "\\Microsoft\\Windows\\A").binary(
            "Actions", _exec_blob("evil.exe")
        )
        _software(case, hive)
        result = _parse(case)
        assert result["tasks"] == 2
        review = result["to_review"]
        (orphan,) = [t for t in review if any("not referenced" in r for r in t["reasons"])]
        assert orphan["actions"] == ["exec evil.exe"]
        assert not any("missing" in r for r in orphan["reasons"])
        live = [t for t in review if t is not orphan]
        assert live == []  # the live task is consistent: nothing to review
        assert "registered_utc=2024-01-01T00:00:00Z" in _indexed_text()

    def test_built_in_tasks_are_not_flagged(self, case: Path) -> None:
        _write_task(
            case,
            "\\Microsoft\\Windows\\Autochk\\Proxy",
            _task_xml(
                "%windir%\\system32\\rundll32.exe", "/d acproxy.dll,PerformAutochkOperations"
            ),
        )
        _write_task(
            case,
            "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan",
            _task_xml(
                "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MpCmdRun.exe",
                "Scan -ScheduleJob",
            ),
        )
        result = _parse(case)
        assert result["to_review"] == []

    def test_encoded_command_abbreviations(self, case: Path) -> None:
        _write_task(
            case,
            "\\Microsoft\\Windows\\Blend",
            _task_xml("powershell", "-nop -en SQBFAFgA"),
        )
        (task,) = _parse(case)["to_review"]
        assert "powershell.exe with script, download or evasion arguments" in task["reasons"]

    def test_most_serious_first(self, case: Path) -> None:
        benign = _task_xml("%windir%\\system32\\defrag.exe")
        _write_task(case, "\\ThirdParty", benign)
        _write_task(case, "\\Microsoft\\Windows\\Hidden", benign)
        hive = Key()
        blob = _exec_blob("%windir%\\system32\\defrag.exe")
        _cache_task(hive, "\\ThirdParty", "{G1}", blob, registered="2020-01-01T00:00:00")
        _cache_task(
            hive, "\\Microsoft\\Windows\\Hidden", "{G2}", blob, sd=False, registered="2024-01-01"
        )
        _software(case, hive)
        review = _parse(case)["to_review"]
        assert [t["task"] for t in review] == ["\\Microsoft\\Windows\\Hidden", "\\ThirdParty"]
        assert review[1]["reasons"] == [] and review[1]["notes"]

    def test_migrated_copies_are_not_merged(self, case: Path) -> None:
        _write_task(case, "\\T", _task_xml("a.exe"))
        migrated = case / "Windows" / "System32" / "Tasks_Migrated"
        migrated.mkdir(parents=True)
        (migrated / "T").write_bytes(_task_xml("old.exe"))
        hive = Key()
        _cache_task(hive, "\\T", "{G}", _exec_blob("a.exe"))
        _software(case, hive)
        result = _parse(case)
        assert result["migrated_task_files"] == 1
        assert "exec a.exe" in _indexed_text() and "old.exe" not in _indexed_text()
        assert all(not t["reasons"] for t in result["to_review"])

    def test_a_file_not_read_is_not_reported_missing(
        self, case: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(st, "_MAX_XML_BYTES", 100)
        _write_task(case, "\\Big", _task_xml("a.exe"))
        hive = Key()
        _cache_task(hive, "\\Big", "{G}", _exec_blob("a.exe"))
        _software(case, hive)
        result = _parse(case)
        assert "found but not read" in result["tool_warning"]
        assert not any("missing" in r for t in result["to_review"] for r in t["reasons"])
        assert "xml_not_read=" in _indexed_text()

    def test_hive_without_taskcache_flags_nothing_as_unregistered(self, case: Path) -> None:
        _write_task(case, "\\Microsoft\\Windows\\T", _task_xml("%windir%\\system32\\a.exe"))
        hive = Key()
        hive.key("Microsoft\\Windows\\CurrentVersion").sz("ProgramFilesDir", "C:\\Program Files")
        _software(case, hive)
        result = _parse(case)
        assert result["to_review"] == []
        assert "TaskCache is empty or missing" in result["tool_warning"]

    def test_persistence_composite_lists_flagged_tasks(self, case: Path) -> None:
        _write_task(case, "\\Updater", _task_xml("powershell.exe", _EVIL_ARGS))
        _write_task(case, "\\Microsoft\\Windows\\Ok", _task_xml("%windir%\\system32\\a.exe"))
        _parse(case)
        result = _call("find_persistence_mechanisms")
        text = str(result)
        assert "scheduled_task_definition" in text
        assert "task=\\\\Updater" in text or "task=\\Updater" in text
        assert "Microsoft\\\\Windows\\\\Ok" not in text

    def test_without_the_software_hive_the_gap_is_stated(self, case: Path) -> None:
        _write_task(case, "\\Updater", _task_xml("powershell.exe", _EVIL_ARGS))
        result = _parse(case)
        assert result["status"] == "partial"
        assert "SOFTWARE hive not found" in result["tool_warning"]
        (updater,) = result["to_review"]
        # Without TaskCache, a missing registration is unknown, not a finding.
        assert not any("TaskCache" in r for r in updater["reasons"])

    def test_dirty_hive_is_reported(self, case: Path) -> None:
        _write_task(case, "\\T", _task_xml("a.exe"))
        hive = Key()
        _cache_task(hive, "\\T", "{G}", _exec_blob("a.exe"))
        _software(case, hive, dirty=True)
        result = _parse(case)
        assert result["status"] == "partial"
        assert "is dirty" in result["tool_warning"]

    def test_registry_only_collection(self, case: Path) -> None:
        hive = Key()
        _cache_task(hive, "\\T", "{G}", _CALC_ACTIONS)
        _software(case, hive)
        result = _parse(case)
        assert result["tasks"] == 1
        assert "No task XML" in result["tool_warning"]
        # The XML folder was not collected: its absence is not a finding.
        assert not any("missing" in r for t in result["to_review"] for r in t["reasons"])

    def test_unreadable_xml_is_listed(self, case: Path) -> None:
        _write_task(case, "\\Broken", b"\x00\x01\x02 not xml")
        result = _parse(case)
        assert "not readable task XML: \\Broken" in result["tool_warning"]

    def test_staged_copies_and_legacy_jobs_are_listed_not_parsed(self, case: Path) -> None:
        _write_task(case, "\\T", _task_xml("a.exe"))
        staged = case / "Users" / "Public" / "Registry" / "C" / "Windows" / "System32" / "Tasks"
        staged.mkdir(parents=True)
        (staged / "Copy").write_bytes(_task_xml("b.exe"))
        jobs = case / "Windows" / "Tasks"
        jobs.mkdir(parents=True)
        (jobs / "At1.job").write_bytes(b"\x00" * 80)
        result = _parse(case)
        assert result["tasks"] == 1
        assert result["other_task_folders_not_read"] == ["Users/Public/Registry/C/"]
        assert result["legacy_job_files"] == ["Windows/Tasks/At1.job"]

    def test_nothing_collected(self, case: Path) -> None:
        result = _parse(case)
        assert result["status"] == "error"
        assert result["error_type"] == "artifact_missing"

    def test_second_call_is_skipped(self, case: Path) -> None:
        _write_task(case, "\\T", _task_xml("a.exe"))
        _parse(case)
        again = _call("parse_scheduled_tasks", image_path=str(case))
        assert "Already indexed" in str(again)
