"""Scheduled tasks: every task definition, read from its XML and from the registry cache.

Windows keeps each task twice:

- ``Windows\\System32\\Tasks\\<path>``: the task XML (author, date, principal,
  triggers, actions);
- the SOFTWARE hive, ``Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache``:
  ``Tree\\<path>`` (the task GUID, and the security descriptor ``SD`` that
  ``schtasks`` needs to list it) and ``Tasks\\{GUID}`` (registration and
  last-run times in ``DynamicInfo``, the actions in a binary ``Actions``
  value). The ``Boot``, ``Logon``, ``Plain`` and ``Maintenance`` subkeys
  list the GUIDs by kind of trigger.

Reading both catches what reading one misses: a task hidden from
``schtasks`` by deleting its ``SD`` value (Tarrask), a task whose XML was
deleted, a task whose registry actions were edited so they no longer match
the XML, and the UTC registration and last-run times that the XML lacks.

Binary layouts (cyber.wtf, "Windows Registry Analysis - Today's Episode:
Tasks", 2022): strings are a uint32 byte count then UTF-16LE.

``Actions``::

    uint16 version, string context
    then per action: uint16 magic, string id, and
      0x6666 exec:    string command, string arguments, string working dir,
                      uint16 flags (version >= 3)
      0x7777 COM:     16-byte CLSID, string data
      0x8888 e-mail, 0x9999 message box (legacy; not decoded further)

``DynamicInfo``::

    0x00 uint32 version, 0x04 FILETIME created, 0x0C FILETIME last run,
    0x14 uint32 state, 0x18 uint32 last result, 0x1C FILETIME last success
"""

from __future__ import annotations

import logging
import re
import struct
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import (
    IcatFailure,
    _cleanup_tsk_extract_dir,
    _tsk_extract_files,
    add_extraction_failures,
    nothing_extracted_response,
)

__all__ = [
    "SRC_TASKS",
    "TaskCache",
    "parse_actions_blob",
    "parse_dynamic_info",
    "parse_scheduled_tasks",
    "parse_task_xml",
    "read_taskcache",
]

logger = logging.getLogger(__name__)

SRC_TASKS = "tasks.scheduled"
TASKCACHE_KEY = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"

_TASK_DIR = "windows/system32/tasks/"
#: Pre-upgrade copies kept by Windows feature updates: stale, never merged
#: with the live definitions.
_MIGRATED_DIR = "windows/system32/tasks_migrated/"
_LEGACY_JOB_DIR = "windows/tasks/"
_SOFTWARE_HIVE = "windows/system32/config/software"
_MAX_XML_BYTES = 1024 * 1024
_MAX_REVIEW_LISTED = 40
_TEXT_CAP = 600
_ACTIONS_DIFFER = "actions in the XML and in the registry differ"
_OUTSIDE_MICROSOFT = "outside the \\Microsoft\\ folder"
#: Order of the review list: the reasons an attacker's hiding produces first.
_SEVERITY = (
    "Tarrask",
    _ACTIONS_DIFFER,
    "XML file is missing",
    "TaskCache",
    "arguments",
    "user-writable",
    "not registered",
    _OUTSIDE_MICROSOFT,
)

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_XML_DECL_RE = re.compile(r"^\s*<\?xml[^>]*\?>", re.IGNORECASE)

#: Places where a user or a dropped payload can write: a task that runs from
#: one of them is worth a look whatever its folder.
_TRUSTED_WRITABLE_RE = re.compile(
    r"(?:\\programdata|%programdata%)\\microsoft\\windows defender\\", re.IGNORECASE
)
_WRITABLE_PATH_RE = re.compile(
    r"\\users\\|\\programdata\\|\\temp\\|\\tmp\\|\\appdata\\|\\perflogs\\|"
    r"\\windows\\tasks\\|\\recycle|%temp%|%tmp%|%appdata%|%localappdata%|%public%|"
    r"%userprofile%|%programdata%",
    re.IGNORECASE,
)
_INTERPRETERS = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msbuild.exe",
        "installutil.exe",
        "curl.exe",
        "wmic.exe",
        "forfiles.exe",
        "conhost.exe",
    }
)
_SUSPICIOUS_ARGS_RE = re.compile(
    # PowerShell accepts any unambiguous prefix: -e, -ec, -en, -enc, -encodedcommand.
    r"(?:^|\s)[-/](?:e|ec|en[a-z]*)\s|bypass|(?:^|\s)[-/]w[a-z]*\s+(?:h[a-z]*|1)\b|"
    r"\biex\b|invoke-expression|downloadstring|downloadfile|invoke-webrequest|\biwr\b|"
    r"frombase64string|https?://|\\\\[\w.-]+\\|javascript:|vbscript:|"
    # Not .dll: rundll32 and regsvr32 always take one. A DLL in a writable
    # place is caught by the path check.
    r"\.(?:ps1|bat|cmd|vbs|vbe|js|jse|hta|wsf|sct)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Task XML
# ---------------------------------------------------------------------------


def _decode_xml(data: bytes) -> str:
    """Task XML text, whatever its encoding (UTF-16 with or without BOM, UTF-8)."""
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if len(data) >= 4 and data[1] == 0 and data[3] == 0:
        return data.decode("utf-16-le", errors="replace")
    if len(data) >= 4 and data[0] == 0 and data[2] == 0:
        return data.decode("utf-16-be", errors="replace")
    return data.decode("utf-8", errors="replace")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(elem: ET.Element | None, name: str) -> ET.Element | None:
    if elem is None:
        return None
    for c in elem:
        if _local(c.tag) == name:
            return c
    return None


def _children(elem: ET.Element | None) -> list[ET.Element]:
    # Not ``elem or []``: an Element's truth value is its child count.
    return list(elem) if elem is not None else []


def _text(elem: ET.Element | None, *path: str) -> str | None:
    for name in path:
        elem = _child(elem, name)
    if elem is None or elem.text is None:
        return None
    value = elem.text.strip()
    return value or None


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() == "true"


def _trigger(elem: ET.Element) -> dict[str, object]:
    kind = _local(elem.tag)
    trig: dict[str, object] = {"type": kind}
    for key, name in (
        ("start", "StartBoundary"),
        ("end", "EndBoundary"),
        ("delay", "Delay"),
        ("random_delay", "RandomDelay"),
        ("user_id", "UserId"),
    ):
        if value := _text(elem, name):
            trig[key] = value
    if interval := _text(elem, "Repetition", "Interval"):
        trig["repeat_every"] = interval
        if duration := _text(elem, "Repetition", "Duration"):
            trig["repeat_for"] = duration
    for sched in elem:
        name = _local(sched.tag)
        if name.startswith("ScheduleBy"):
            details = [f"{_local(c.tag)}={(c.text or '').strip()}" for c in sched if c.text]
            trig["schedule"] = name + (f"({', '.join(details)})" if details else "")
    if subscription := _text(elem, "Subscription"):
        trig["subscription"] = subscription[:_TEXT_CAP]
    if not _bool(_text(elem, "Enabled"), True):
        trig["enabled"] = False
    return trig


def _action(elem: ET.Element) -> dict[str, object] | None:
    kind = _local(elem.tag)
    if kind == "Exec":
        return {
            "type": "exec",
            "command": _text(elem, "Command") or "",
            "arguments": _text(elem, "Arguments") or "",
            "working_directory": _text(elem, "WorkingDirectory") or "",
        }
    if kind == "ComHandler":
        return {
            "type": "com",
            "class_id": _text(elem, "ClassId") or "",
            "data": (_text(elem, "Data") or "")[:_TEXT_CAP],
        }
    if kind == "SendEmail":
        return {
            "type": "email",
            "to": _text(elem, "To") or "",
            "subject": _text(elem, "Subject") or "",
        }
    if kind == "ShowMessage":
        return {"type": "message", "title": _text(elem, "Title") or ""}
    return None


def parse_task_xml(data: bytes) -> dict[str, Any]:
    """Decode one task definition. Raises ``ET.ParseError`` when it is not task XML."""
    text = _XML_DECL_RE.sub("", _decode_xml(data), count=1).lstrip("\ufeff")
    root = ET.fromstring(text)
    if _local(root.tag) != "Task":
        raise ET.ParseError(f"root element is <{_local(root.tag)}>, not <Task>")
    reg = _child(root, "RegistrationInfo")
    task: dict[str, Any] = {"version": root.get("version")}
    for key, name in (
        ("uri", "URI"),
        ("author", "Author"),
        ("date", "Date"),
        ("description", "Description"),
        ("source", "Source"),
    ):
        if value := _text(reg, name):
            task[key] = value[:_TEXT_CAP]

    actions_elem = _child(root, "Actions")
    context = actions_elem.get("Context") if actions_elem is not None else None
    principals = [p for p in _children(_child(root, "Principals")) if _local(p.tag) == "Principal"]
    chosen = next((p for p in principals if p.get("id") == context), None)
    if chosen is None and principals:  # not ``or``: an Element's truth is its child count
        chosen = principals[0]
    if chosen is not None:
        principal = {
            key: value
            for key, value in (
                ("user_id", _text(chosen, "UserId")),
                ("group_id", _text(chosen, "GroupId")),
                ("logon_type", _text(chosen, "LogonType")),
                ("run_level", _text(chosen, "RunLevel")),
            )
            if value
        }
        if principal:
            task["principal"] = principal

    settings = _child(root, "Settings")
    task["enabled"] = _bool(_text(settings, "Enabled"), True)
    task["hidden"] = _bool(_text(settings, "Hidden"), False)
    task["triggers"] = [_trigger(t) for t in _children(_child(root, "Triggers"))]
    task["actions"] = [a for a in map(_action, _children(actions_elem)) if a is not None]
    return task


# ---------------------------------------------------------------------------
# TaskCache binary values
# ---------------------------------------------------------------------------


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def u16(self) -> int:
        (value,) = struct.unpack_from("<H", self.data, self.pos)
        self.pos += 2
        return int(value)

    def bstr(self) -> str:
        (size,) = struct.unpack_from("<I", self.data, self.pos)
        self.pos += 4
        if size > len(self.data) - self.pos or size % 2:
            raise ValueError(f"string of {size} bytes at offset {self.pos - 4} overruns the value")
        raw = self.data[self.pos : self.pos + size]
        self.pos += size
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")

    def raw(self, size: int) -> bytes:
        if size > len(self.data) - self.pos:
            raise ValueError(f"{size} bytes at offset {self.pos} overrun the value")
        raw = self.data[self.pos : self.pos + size]
        self.pos += size
        return raw

    @property
    def left(self) -> int:
        return len(self.data) - self.pos


def parse_actions_blob(blob: bytes) -> dict[str, Any]:
    """Decode a TaskCache ``Actions`` value.

    Returns ``{"version", "context", "actions": [...]}`` and, when the value
    could not be read to its end, ``"error"`` with the actions read so far.
    """
    result: dict[str, Any] = {"actions": []}
    reader = _Reader(blob)
    try:
        result["version"] = reader.u16()
        result["context"] = reader.bstr()
        while reader.left >= 2:
            magic = reader.u16()
            action_id = reader.bstr()
            action: dict[str, object]
            if magic == 0x6666:
                action = {
                    "type": "exec",
                    "command": reader.bstr(),
                    "arguments": reader.bstr(),
                    "working_directory": reader.bstr(),
                }
                if result["version"] >= 3 and reader.left >= 2:
                    reader.u16()  # flags
            elif magic == 0x7777:
                clsid = uuid.UUID(bytes_le=reader.raw(16))
                action = {
                    "type": "com",
                    "class_id": "{" + str(clsid).upper() + "}",
                    "data": reader.bstr()[:_TEXT_CAP],
                }
            elif magic in (0x8888, 0x9999):
                # Deprecated action types, not decoded: stop rather than misread,
                # and say that the rest of the value was not read.
                result["actions"].append({"type": "email" if magic == 0x8888 else "message"})
                if reader.left:
                    result["error"] = (
                        f"{reader.left} bytes after a {result['actions'][-1]['type']} action "
                        "not decoded"
                    )
                break
            else:
                raise ValueError(f"unknown action type 0x{magic:04x} at offset {reader.pos - 2}")
            if action_id:
                action["id"] = action_id
            result["actions"].append(action)
    except (struct.error, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _filetime(value: int) -> str | None:
    if not value:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    if not 1995 <= dt.year <= 2100:
        return None
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_dynamic_info(blob: bytes) -> dict[str, object]:
    """Decode a TaskCache ``DynamicInfo`` value (times are UTC)."""
    info: dict[str, object] = {}
    if len(blob) >= 20:
        _version, created, last_run = struct.unpack_from("<IQQ", blob, 0)
        if stamp := _filetime(created):
            info["registered_utc"] = stamp
        if stamp := _filetime(last_run):
            info["last_run_utc"] = stamp
    if len(blob) >= 28:
        state, last_result = struct.unpack_from("<II", blob, 20)
        info["state"] = state
        info["last_result"] = f"0x{last_result:08X}"
    if len(blob) >= 36:
        (success,) = struct.unpack_from("<Q", blob, 28)
        if stamp := _filetime(success):
            info["last_success_utc"] = stamp
    return info


# ---------------------------------------------------------------------------
# TaskCache
# ---------------------------------------------------------------------------


@dataclass
class TaskCache:
    """What the SOFTWARE hive says about scheduled tasks.

    ``tree`` is keyed by lower-cased task path, ``tasks`` by lower-cased GUID.
    """

    tree: dict[str, dict[str, Any]] = field(default_factory=dict)
    tasks: dict[str, dict[str, Any]] = field(default_factory=dict)
    dirty: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def read_ok(self) -> bool:
        """True when the TaskCache held something: its checks mean something."""
        return bool(self.tree or self.tasks)


_UNREADABLE = object()


def _values(key: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for value in key.values():
        try:
            out[value.name().lower()] = value.value()
        except Exception:  # noqa: BLE001 - one bad value must not hide the key
            out[value.name().lower()] = _UNREADABLE
    return out


def _hive_is_dirty(path: Path) -> bool:
    """True when the primary and secondary sequence numbers differ (unflushed log)."""
    try:
        with path.open("rb") as fh:
            header = fh.read(12)
    except OSError:
        return False
    if len(header) < 12 or header[:4] != b"regf":
        return False
    seq1, seq2 = struct.unpack_from("<II", header, 4)
    return bool(seq1 != seq2)


def _sd_state(value: Any) -> str:
    if value is _UNREADABLE:
        return "unreadable"
    return "present" if value else "absent"


def read_taskcache(hive_path: Path) -> TaskCache:
    """Read ``TaskCache`` from a SOFTWARE hive. Raises when the hive cannot be opened."""
    from Registry import Registry

    cache = TaskCache(dirty=_hive_is_dirty(hive_path))
    reg = Registry.Registry(str(hive_path))
    try:
        base = reg.open(TASKCACHE_KEY)
    except Registry.RegistryKeyNotFoundException:
        cache.errors.append(f"{TASKCACHE_KEY} not found in the hive")
        return cache

    categories: dict[str, list[str]] = {}
    for sub in base.subkeys():
        if sub.name().lower() in ("boot", "logon", "plain", "maintenance"):
            for item in sub.subkeys():
                categories.setdefault(item.name().lower(), []).append(sub.name())

    def walk(key: Any, prefix: str) -> None:
        for sub in key.subkeys():
            path = f"{prefix}\\{sub.name()}"
            try:
                values = _values(sub)
                if "id" in values:
                    index = values.get("index")
                    guid = values["id"]
                    cache.tree[path.lower()] = {
                        "path": path,
                        "guid": guid.strip() if isinstance(guid, str) else "",
                        "index": index if isinstance(index, int) else None,
                        "sd": _sd_state(values.get("sd")),
                    }
                walk(sub, path)
            except Exception as exc:  # noqa: BLE001 - reported, the rest is still read
                cache.errors.append(f"Tree{path}: {type(exc).__name__}: {exc}")

    try:
        walk(base.subkey("Tree"), "")
    except Registry.RegistryKeyNotFoundException:
        cache.errors.append("TaskCache\\Tree not found")

    try:
        tasks_key = base.subkey("Tasks")
    except Registry.RegistryKeyNotFoundException:
        cache.errors.append("TaskCache\\Tasks not found")
        return cache
    for sub in tasks_key.subkeys():
        guid = sub.name()
        try:
            values = _values(sub)
            entry: dict[str, Any] = {"guid": guid}
            for key_name in ("path", "author", "date", "description", "uri", "source"):
                value = values.get(key_name)
                if isinstance(value, str) and value.strip():
                    entry[key_name] = value.strip()[:_TEXT_CAP]
            if isinstance(values.get("dynamicinfo"), bytes):
                entry.update(parse_dynamic_info(values["dynamicinfo"]))
            if isinstance(values.get("actions"), bytes):
                decoded = parse_actions_blob(values["actions"])
                entry["actions"] = decoded["actions"]
                if decoded.get("error"):
                    entry["actions_error"] = decoded["error"]
            elif values.get("actions") is _UNREADABLE:
                entry["actions_error"] = "Actions value unreadable"
            if guid.lower() in categories:
                entry["category"] = categories[guid.lower()]
            cache.tasks[guid.lower()] = entry
        except Exception as exc:  # noqa: BLE001 - reported, the rest is still read
            cache.errors.append(f"Tasks\\{guid}: {type(exc).__name__}: {exc}")
    return cache


# ---------------------------------------------------------------------------
# Merge and review
# ---------------------------------------------------------------------------


def _exec_strings(actions: list[dict[str, object]]) -> list[str]:
    out = []
    for a in actions:
        if a.get("type") == "exec":
            out.append(f"{a.get('command', '')} {a.get('arguments', '')}".strip())
        elif a.get("type") == "com":
            out.append(f"com {a.get('class_id', '')}")
    return out


def _norm(command: str) -> str:
    return re.sub(r"\s+", " ", command.replace('"', "")).strip().lower()


def _action_reasons(actions: list[dict[str, object]]) -> list[str]:
    reasons: list[str] = []
    for a in actions:
        if a.get("type") != "exec":
            continue
        command = str(a.get("command", ""))
        full = f"{command} {a.get('arguments', '')} {a.get('working_directory', '')}"
        if _WRITABLE_PATH_RE.search(_TRUSTED_WRITABLE_RE.sub(" ", full)):
            reasons.append("runs from or points to a user-writable path")
        name = command.strip().strip('"').replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if not name.endswith(".exe") and f"{name}.exe" in _INTERPRETERS:
            name += ".exe"
        if name in _INTERPRETERS and _SUSPICIOUS_ARGS_RE.search(str(a.get("arguments", ""))):
            reasons.append(f"{name} with script, download or evasion arguments")
    return reasons


def _review(rec: dict[str, Any], cache_read: bool, xml_collected: bool) -> None:
    """Set ``reasons`` (worth a look) and ``notes`` (context) on a merged record."""
    reasons: list[str] = list(rec["cache_issues"])
    tree, cache, xml = rec["tree"], rec["cache"], rec["xml"]
    if tree is not None and tree["sd"] == "absent":
        reasons.append("no SD value in TaskCache\\Tree: hidden from schtasks (Tarrask technique)")
    has_file = xml is not None or rec.get("xml_error") or rec.get("xml_not_read")
    if cache_read and xml_collected:
        if not has_file and not rec.get("shadowed") and (tree is not None or cache is not None):
            reasons.append("registered in TaskCache but its XML file is missing (deleted?)")
        if has_file and tree is None and cache is None:
            reasons.append("XML file present but not registered in TaskCache")
    if xml and cache and cache.get("actions") is not None and not cache.get("actions_error"):
        in_xml = sorted(_norm(x) for x in _exec_strings(xml.get("actions", [])))
        in_reg = sorted(_norm(x) for x in _exec_strings(cache["actions"]))
        if in_xml != in_reg:
            reasons.append(_ACTIONS_DIFFER)
    reasons.extend(_action_reasons(rec["actions"]))
    if _ACTIONS_DIFFER in reasons and cache is not None:
        # Registry actions that differ are checked too: they are what runs.
        reasons.extend(_action_reasons(cache["actions"]))
    rec["reasons"] = list(dict.fromkeys(reasons))
    notes: list[str] = []
    if not str(rec["task"]).lower().startswith("\\microsoft\\"):
        notes.append(_OUTSIDE_MICROSOFT)
    if tree is not None and tree["sd"] == "unreadable":
        notes.append("SD value unreadable: whether the task is hidden is unknown")
    rec["notes"] = notes


def _severity(rec: dict[str, Any]) -> int:
    ranks = [i for i, key in enumerate(_SEVERITY) for reason in rec["reasons"] if key in reason]
    if ranks:
        return min(ranks)
    return len(_SEVERITY) if rec["reasons"] else len(_SEVERITY) + 1


def _render_action(a: dict[str, object]) -> str:
    if a.get("type") == "exec":
        text = f"exec {a.get('command', '')} {a.get('arguments', '')}".strip()
        if a.get("working_directory"):
            text += f" (in {a['working_directory']})"
        return text
    if a.get("type") == "com":
        return f"com {a.get('class_id', '')} {a.get('data', '')}".strip()
    return str(a.get("type"))


def _render_trigger(t: dict[str, object]) -> str:
    parts = [str(t["type"])]
    for key in (
        "start",
        "end",
        "schedule",
        "repeat_every",
        "repeat_for",
        "delay",
        "user_id",
        "subscription",
    ):
        if t.get(key):
            parts.append(f"{key}={t[key]}")
    if t.get("enabled") is False:
        parts.append("disabled")
    return " ".join(parts)


def _task_line(task: dict[str, Any]) -> str:
    cache = task.get("cache") or {}
    xml = task.get("xml") or {}
    head = f"registered_utc={cache.get('registered_utc') or 'unknown'}"
    flag = f" [REVIEW: {'; '.join(task['reasons'])}]" if task["reasons"] else ""
    if task["notes"]:
        flag += f" [NOTE: {'; '.join(task['notes'])}]"
    parts = [f"{head} task={task['task']}{flag}"]
    if task["actions"]:
        parts.append("actions: " + " ; ".join(_render_action(a) for a in task["actions"]))
    if _ACTIONS_DIFFER in task["reasons"] and cache.get("actions"):
        parts.append(
            "registry actions: " + " ; ".join(_render_action(a) for a in cache["actions"])
        )
    if xml.get("triggers"):
        parts.append("triggers: " + " ; ".join(_render_trigger(t) for t in xml["triggers"]))
    elif cache.get("category"):
        parts.append("trigger kind (TaskCache): " + ",".join(cache["category"]))
    principal = xml.get("principal") or {}
    run_as = principal.get("user_id") or principal.get("group_id")
    if run_as:
        parts.append(f"run_as={run_as}")
    if principal.get("run_level"):
        parts.append(f"run_level={principal['run_level']}")
    author = xml.get("author") or cache.get("author")
    if author:
        parts.append(f"author={author}")
    if xml.get("date") or cache.get("date"):
        parts.append(f"declared_date={xml.get('date') or cache.get('date')}")
    for key in ("last_run_utc", "last_success_utc", "last_result"):
        if cache.get(key):
            parts.append(f"{key}={cache[key]}")
    if xml and not xml.get("enabled", True):
        parts.append("disabled")
    if xml.get("hidden"):
        parts.append("hidden_setting=true")
    guid = cache.get("guid") or (task.get("tree") or {}).get("guid")
    if guid:
        parts.append(f"guid={guid}")
    if xml.get("description"):
        parts.append(f"description={xml['description'][:200]}")
    if task.get("xml_file"):
        parts.append(f"xml={task['xml_file']}")
    if task.get("xml_error"):
        parts.append(f"xml_unreadable={task['xml_error']}")
    if task.get("xml_not_read"):
        parts.append(f"xml_not_read={task['xml_not_read']}")
    if cache.get("actions_error"):
        parts.append(f"registry_actions_partly_decoded={cache['actions_error']}")
    return " | ".join(p.replace("\n", " ").replace("\r", " ") for p in parts)


def _task_path_from_file(rel: str) -> str | None:
    idx = rel.lower().find(_TASK_DIR)
    if idx < 0:
        return None
    return "\\" + rel[idx + len(_TASK_DIR) :].replace("/", "\\")


def merge_tasks(
    xml_files: list[tuple[str, bytes]],
    cache: TaskCache | None,
    not_read: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """One record per task, from the XML files and the TaskCache, with review reasons.

    *not_read* maps task files that exist but could not be read (too large,
    I/O or icat error) to the reason: their task is "not read", never
    "missing". TaskCache ``Tree`` entries are joined to ``Tasks\\{GUID}``
    through their ``Id``; a ``Tasks`` entry no ``Tree`` entry points to is
    reported on its own.
    """
    records: dict[str, dict[str, Any]] = {}

    def record(path: str, key: str | None = None) -> dict[str, Any]:
        return records.setdefault(
            (key or path).lower(),
            {"task": path, "xml": None, "cache": None, "tree": None, "cache_issues": []},
        )

    for rel, data in xml_files:
        path = _task_path_from_file(rel)
        if path is None:
            continue
        rec = record(path)
        rec["xml_file"] = rel
        try:
            rec["xml"] = parse_task_xml(data)
        except (ET.ParseError, ValueError) as exc:
            rec["xml_error"] = f"{type(exc).__name__}: {exc}"[:200]
    for rel, reason in (not_read or {}).items():
        path = _task_path_from_file(rel)
        if path is not None:
            rec = record(path)
            rec["xml_file"] = rel
            rec["xml_not_read"] = reason

    cache_read = cache is not None and cache.read_ok
    if cache is not None and cache_read:
        used: set[str] = set()
        for tree in cache.tree.values():
            rec = record(tree["path"])
            rec["tree"] = tree
            entry = cache.tasks.get(tree["guid"].lower())
            if entry is None:
                rec["cache_issues"].append(
                    f"TaskCache\\Tree points to {tree['guid'] or 'no GUID'}, which has no "
                    "TaskCache\\Tasks entry"
                )
                continue
            used.add(tree["guid"].lower())
            rec["cache"] = entry
            if entry.get("path") and str(entry["path"]).lower() != tree["path"].lower():
                rec["cache_issues"].append(
                    f"TaskCache\\Tasks Path ({entry['path']}) differs from its Tree path"
                )
        for guid, entry in cache.tasks.items():
            if guid in used:
                continue
            path = str(entry.get("path") or f"\\<TaskCache entry {entry['guid']} without Path>")
            existing = records.get(path.lower())
            if existing is not None and existing["cache"] is None:
                rec = existing
            else:
                rec = record(path, key=f"{path}#{guid}")
                # A second entry for a path that already has one: the XML
                # belongs to the other record, so "missing" would be wrong.
                rec["shadowed"] = existing is not None
            rec["cache"] = entry
            rec["cache_issues"].append(
                f"TaskCache\\Tasks\\{entry['guid']} is not referenced by TaskCache\\Tree"
            )

    xml_collected = bool(xml_files) or bool(not_read)
    out = []
    for rec in records.values():
        xml_actions = (rec["xml"] or {}).get("actions") or []
        cache_actions = (rec["cache"] or {}).get("actions") or []
        rec["actions"] = xml_actions or cache_actions
        _review(rec, cache_read, xml_collected)
        out.append(rec)
    # Tasks with a UTC registration time first, in time order: a window's
    # event time is taken from its first timestamp, and the XML dates of the
    # others are local times.
    out.sort(
        key=lambda r: (
            (r["cache"] or {}).get("registered_utc") is None,
            (r["cache"] or {}).get("registered_utc") or "",
            r["task"].lower(),
        )
    )
    return out


def _summary_entry(task: dict[str, Any]) -> dict[str, object]:
    cache = task.get("cache") or {}
    xml = task.get("xml") or {}
    entry: dict[str, object] = {
        "task": task["task"],
        "reasons": task["reasons"],
        "actions": [_render_action(a) for a in task["actions"]],
    }
    if task["notes"]:
        entry["notes"] = task["notes"]
    if xml.get("triggers"):
        entry["triggers"] = [_render_trigger(t) for t in xml["triggers"]]
    principal = xml.get("principal") or {}
    if principal:
        entry["principal"] = principal
    for key in ("registered_utc", "last_run_utc", "last_result", "guid"):
        if cache.get(key):
            entry[key] = cache[key]
    if xml.get("author") or cache.get("author"):
        entry["author"] = xml.get("author") or cache.get("author")
    if xml.get("date"):
        entry["declared_date"] = xml["date"]
    if task.get("xml_file"):
        entry["xml_file"] = task["xml_file"]
    return entry


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


def _root_of(rel: str) -> str:
    idx = rel.lower().find("windows/")
    return rel[:idx] if idx >= 0 else rel


def _pick_root(roots: set[str]) -> str | None:
    return min(roots, key=lambda r: (len(r), r)) if roots else None


def _stage(
    image_path: str, failures: list[IcatFailure]
) -> tuple[list[tuple[str, Path]], list[tuple[str, Path]], list[str]]:
    """Task files and SOFTWARE hives found, and the directories to clean up.

    Deleted entries are left out on disk images: a deleted task XML read as a
    live one would hide that the task was removed.
    """
    cleanup: list[str] = []
    files = _tsk_extract_files(
        image_path,
        ["System32/Tasks/", "System32/Tasks_Migrated/", "Windows/Tasks/"],
        failures=failures,
        include_deleted=False,
    )
    if files:
        cleanup.append(str(files[0][1].parent))
    hives = _tsk_extract_files(
        image_path,
        ["System32/config/SOFTWARE"],
        lambda rel: rel.endswith(_SOFTWARE_HIVE),
        failures,
        include_deleted=False,
    )
    if hives and str(hives[0][1].parent) not in cleanup:
        cleanup.append(str(hives[0][1].parent))
    return files, hives, cleanup


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def parse_scheduled_tasks(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse every scheduled task: its actions, triggers, account and run times.

    Call on Windows disk images and triage collections. Reads each task
    XML under ``Windows\\System32\\Tasks`` (command line, arguments,
    triggers, principal, author, declared date) and the Task Scheduler
    cache in the SOFTWARE hive (GUID, UTC registration and last-run
    times, last result, actions). Comparing the two finds tasks hidden
    from schtasks (no ``SD`` value), tasks whose XML was deleted, and
    actions changed in the registry only. Tasks worth a look are flagged
    ``[REVIEW: reasons]`` and listed first in ``to_review``, most serious
    first (then tasks that only sit outside the ``\\Microsoft\\`` folder,
    flagged ``[NOTE: ...]``). Every task is indexed as ``tasks.scheduled``.

    Args:
        image_path: Disk image, or triage collection directory.
        force: Re-run extraction even if the source already exists.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path, "force": force}
    if not force:
        existing = sources_already_indexed([SRC_TASKS], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "parse_scheduled_tasks",
                params,
                {"status": "skipped", "reason": "Already indexed", "existing_sources": existing},
                SRC_TASKS,
                0.0,
            )

    failures: list[IcatFailure] = []
    files, hives, cleanup = _stage(image_path, failures)
    warnings: list[str] = []
    not_read: dict[str, str] = {
        f.path: f"not extracted from the image: {f.reason}"
        for f in failures
        if _task_path_from_file(f.path)
    }
    try:
        task_files = [(rel, p) for rel, p in files if _task_path_from_file(rel)]
        jobs = [rel for rel, _ in files if rel.lower().endswith(".job")]
        migrated = [rel for rel, _ in files if _MIGRATED_DIR in rel.lower()]
        roots = {_root_of(rel) for rel, _ in task_files} | {_root_of(r) for r in not_read}
        root = _pick_root(roots)
        other_roots = sorted(r for r in roots if r != root)
        xml_files: list[tuple[str, bytes]] = []
        for rel, path in task_files:
            if _root_of(rel) != root:
                continue
            try:
                size = path.stat().st_size
                if size > _MAX_XML_BYTES:
                    not_read[rel] = f"{size} bytes, over the 1 MB limit"
                    continue
                xml_files.append((rel, path.read_bytes()))
            except OSError as exc:
                not_read[rel] = f"could not be read: {exc}"
        not_read = {rel: why for rel, why in not_read.items() if _root_of(rel) == root}

        cache: TaskCache | None = None
        hive_rel: str | None = None
        if hives:
            by_root = {_root_of(rel): (rel, p) for rel, p in hives}
            chosen_root = root if root in by_root else _pick_root(set(by_root))
            hive_rel, hive_path = by_root[chosen_root or ""]
            if root is not None and chosen_root != root:
                warnings.append(
                    f"No SOFTWARE hive next to the task files ({root or 'volume root'}): "
                    f"TaskCache read from {hive_rel}, which may be another system or a copy"
                )
            try:
                cache = read_taskcache(hive_path)
            except Exception as exc:  # noqa: BLE001 - the XML is still worth reading
                warnings.append(
                    f"SOFTWARE hive {hive_rel} could not be opened ({type(exc).__name__}: "
                    f"{exc}): registration and last-run times, hidden tasks and registry "
                    "actions were not checked"
                )
        else:
            warnings.append(
                "SOFTWARE hive not found: registration and last-run times, tasks hidden "
                "from schtasks (no SD) and registry-only actions were not checked"
            )
    finally:
        for d in cleanup:
            _cleanup_tsk_extract_dir(d)

    if cache is not None:
        warnings.extend(f"TaskCache: {e}" for e in cache.errors)
        if not cache.read_ok:
            warnings.append(
                "TaskCache is empty or missing: registration checks were not made, and no "
                "task is reported as unregistered"
            )
        if cache.dirty:
            warnings.append(
                f"{hive_rel} is dirty (unflushed .LOG1/.LOG2 transaction logs, not applied "
                "here): a task registered shortly before collection may be missing from "
                "TaskCache"
            )
    has_cache_tasks = cache is not None and cache.read_ok
    if not xml_files and not not_read:
        if not has_cache_tasks:
            return nothing_extracted_response(
                tc_id,
                "parse_scheduled_tasks",
                params,
                t0,
                "No scheduled task found: Windows\\System32\\Tasks and the SOFTWARE hive's "
                "TaskCache were not collected or are empty",
                failures,
            )
        warnings.append(
            "No task XML under Windows\\System32\\Tasks (not collected?): tasks come from "
            "the registry only, without triggers or principals"
        )

    tasks = merge_tasks(xml_files, cache, not_read)
    unreadable = [t["task"] for t in tasks if t.get("xml_error")]
    if unreadable:
        warnings.append(
            f"{len(unreadable)} task file(s) are not readable task XML: "
            + ", ".join(unreadable[:10])
            + (" ..." if len(unreadable) > 10 else "")
            + " (read them with read_evidence_file)"
        )
    if not_read:
        listed = "; ".join(f"{rel}: {why}" for rel, why in list(not_read.items())[:10])
        warnings.append(f"{len(not_read)} task file(s) found but not read: {listed}")

    summary = extract_and_index(
        "\n".join(_task_line(t) for t in tasks), SRC_TASKS, image_path, "scheduled_tasks"
    )
    review = sorted((t for t in tasks if t["reasons"] or t["notes"]), key=lambda t: _severity(t))
    summary.update(
        {
            "tasks": len(tasks),
            "from_xml": sum(1 for t in tasks if t.get("xml") is not None),
            "from_taskcache": sum(1 for t in tasks if t.get("cache") is not None),
            "flagged_review": sum(1 for t in tasks if t["reasons"]),
            "software_hive": hive_rel,
            "to_review": [_summary_entry(t) for t in review[:_MAX_REVIEW_LISTED]],
            "indexed_as": SRC_TASKS,
            "hint": (
                f"Every task is one line of '{SRC_TASKS}' "
                f"(search(query, source='{SRC_TASKS}')); lines of tasks worth a look "
                "contain [REVIEW. registered_utc, last_run_utc and last_success_utc come "
                "from TaskCache and are UTC; declared_date and trigger start times are "
                "copied from the XML as written (usually local time, and set by whoever "
                "created the task)."
            ),
        }
    )
    if len(review) > _MAX_REVIEW_LISTED:
        summary["to_review_not_listed"] = len(review) - _MAX_REVIEW_LISTED
    if jobs:
        summary["legacy_job_files"] = jobs[:20]
        warnings.append(
            f"{len(jobs)} legacy .job file(s) in Windows\\Tasks are listed, not parsed "
            "(read them with read_evidence_file)"
        )
    if migrated:
        summary["migrated_task_files"] = len(migrated)
        summary["migrated_task_files_note"] = (
            "Windows\\System32\\Tasks_Migrated holds pre-upgrade copies of task definitions; "
            "they are not merged with the live tasks (read them with read_evidence_file)."
        )
    if other_roots:
        summary["other_task_folders_not_read"] = other_roots
        summary["other_task_folders_note"] = (
            "Task folders found under other paths (copies staged by a collector or an "
            "attacker) were not parsed; the shortest path was taken as the live system."
        )
    if warnings:
        summary["tool_warning"] = "\n".join(warnings)
    add_extraction_failures(summary, failures)
    elapsed = (time.monotonic() - t0) * 1000
    # Returned in full (source=None): to_review is the finding, and the
    # indexed-source preview would cut it.
    return tool_response(tc_id, "parse_scheduled_tasks", params, summary, None, elapsed)
