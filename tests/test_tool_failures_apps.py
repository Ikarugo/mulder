"""Failed external runs must not read as "ran, found nothing".

Covers hindsight, ALEAPP/iLEAPP, MVT, analyze_pdf (pdfid / pdf-parser),
Zircolite, the YARA scans and extract_archive's 7z call. Each wrapper used to
drop the exit code (or the parts of the output that said something went wrong)
and answer success, so the agent concluded the evidence was clean.

The programs are replaced at ``mulder.server.helpers.subprocess.run``, the one
place ``run_tool`` starts them.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.helpers import tool_response as real_tool_response

_RUN = "mulder.server.helpers.subprocess.run"


def _proc(cmd: Any, rc: int = 0, stdout: str = "", stderr: str = "") -> Any:
    return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=stderr)


class _Index:
    """Stand-in for extract_and_index that records what would be indexed."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, raw: str, source: str, *args: object, **kw: object) -> dict[str, object]:
        self.calls.append((source, raw))
        return {"source_name": source, "windows_indexed": 1, "line_count": 1}


# ---------------------------------------------------------------------------
# Hindsight
# ---------------------------------------------------------------------------


def _hindsight(profile: Path, fake: Callable[..., Any]) -> tuple[dict[str, Any], _Index]:
    from mulder.server.tools.hindsight import run_hindsight

    index = _Index()
    with (
        patch("mulder.server.tools.hindsight._find_hindsight_cmd", return_value=["hindsight"]),
        patch(_RUN, side_effect=fake),
        patch("mulder.server.tools.hindsight.extract_and_index", side_effect=index),
    ):
        result = run_hindsight.__wrapped__(str(profile))  # type: ignore[attr-defined]
    return result, index


def _hindsight_writing(rc: int, stderr: str = "") -> Callable[..., Any]:
    def fake(cmd: list[str], **_: object) -> Any:
        out = Path(cmd[cmd.index("-o") + 1])
        Path(str(out) + ".jsonl").write_text('{"url": "http://evil.example"}\n')
        return _proc(cmd, rc, "", stderr)

    return fake


def test_hindsight_crash_is_an_error_and_nothing_is_indexed(tmp_path: Path) -> None:
    traceback = "Traceback (most recent call last):\nsqlite3.DatabaseError: file is not a database"
    result, index = _hindsight(tmp_path, lambda cmd, **_: _proc(cmd, 1, "", traceback))

    assert result["status"] == "error"
    assert "exited 1" in str(result["error_message"])
    assert "file is not a database" in str(result["error_message"])
    assert index.calls == []


def test_hindsight_nonzero_after_output_is_partial(tmp_path: Path) -> None:
    result, index = _hindsight(tmp_path, _hindsight_writing(1, "plugin crashed"))

    assert result["status"] == "partial"
    assert "plugin crashed" in str(result["tool_warning"])
    assert index.calls and "evil.example" in index.calls[0][1]


def test_hindsight_clean_run_stays_success(tmp_path: Path) -> None:
    result, index = _hindsight(tmp_path, _hindsight_writing(0))

    assert result["status"] == "success"
    assert "tool_warning" not in result
    assert len(index.calls) == 1


# ---------------------------------------------------------------------------
# ALEAPP / iLEAPP
# ---------------------------------------------------------------------------


def _leapp(
    tool_name: str, tmp_path: Path, fake: Callable[..., Any]
) -> tuple[dict[str, Any], _Index]:
    from mulder.server.tools import phone

    script = tmp_path / "leapp.py"
    script.write_text("")
    extraction = tmp_path / "extraction"
    extraction.mkdir()
    index = _Index()
    script_fn = "_aleapp_script" if tool_name == "run_aleapp" else "_ileapp_script"
    with (
        patch(f"mulder.server.tools.phone.{script_fn}", return_value=str(script)),
        patch("mulder.server.tools.phone._find_leapp_cmd", return_value=["python", "leapp.py"]),
        patch(_RUN, side_effect=fake),
        patch("mulder.server.tools.phone.extract_and_index", side_effect=index),
    ):
        result = getattr(phone, tool_name).__wrapped__(str(extraction))
    return result, index


def _leapp_writing_tsv(rc: int, stderr: str = "") -> Callable[..., Any]:
    def fake(cmd: list[str], **_: object) -> Any:
        tsv = Path(cmd[cmd.index("-o") + 1]) / "tsv"
        tsv.mkdir(parents=True)
        (tsv / "sms.tsv").write_text("Timestamp\tBody\n2026-01-01\thello\n")
        return _proc(cmd, rc, "", stderr)

    return fake


@pytest.mark.parametrize("tool_name", ["run_aleapp", "run_ileapp"])
def test_leapp_crash_is_an_error_not_no_artifacts(tool_name: str, tmp_path: Path) -> None:
    result, index = _leapp(
        tool_name,
        tmp_path,
        lambda cmd, **_: _proc(cmd, 1, "", "ModuleNotFoundError: No module named 'bencoding'"),
    )

    assert result["status"] == "error"
    assert "bencoding" in str(result["error_message"])
    assert index.calls == []


@pytest.mark.parametrize("tool_name", ["run_aleapp", "run_ileapp"])
def test_leapp_genuinely_empty_names_no_source(tool_name: str, tmp_path: Path) -> None:
    result, index = _leapp(tool_name, tmp_path, lambda cmd, **_: _proc(cmd, 0, "done", ""))

    assert result["status"] == "success"
    assert result["source"] is None, "the hint must not point at a source never created"
    assert result["results"]["status"] == "no_artifacts"
    assert index.calls == []


@pytest.mark.parametrize("tool_name", ["run_aleapp", "run_ileapp"])
def test_leapp_nonzero_after_output_is_partial(tool_name: str, tmp_path: Path) -> None:
    result, index = _leapp(tool_name, tmp_path, _leapp_writing_tsv(1, "module X crashed"))

    assert result["status"] == "partial"
    assert "module X crashed" in str(result["tool_warning"])
    assert index.calls and "hello" in index.calls[0][1]


# ---------------------------------------------------------------------------
# MVT
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_name", ["run_mvt_android", "run_mvt_ios"])
def test_mvt_missing_iocs_file_is_an_error(tool_name: str, tmp_path: Path) -> None:
    from mulder.server.tools import mvt

    backup = tmp_path / "backup"
    backup.mkdir()
    run = MagicMock()
    with (
        patch("mulder.server.tools.mvt.shutil.which", return_value="/usr/bin/mvt"),
        patch(_RUN, run),
    ):
        result = getattr(mvt, tool_name).__wrapped__(
            str(backup), iocs=str(tmp_path / "pegasus.stix2")
        )

    assert result["status"] == "error"
    assert result["error_type"] == "file_not_found"
    assert "pegasus.stix2" in str(result["error_message"])
    run.assert_not_called()


def test_mvt_existing_iocs_file_is_passed(tmp_path: Path) -> None:
    from mulder.server.tools.mvt import run_mvt_android

    backup = tmp_path / "backup"
    backup.mkdir()
    iocs = tmp_path / "pegasus.stix2"
    iocs.write_text("{}")
    seen: list[list[str]] = []

    def fake(cmd: list[str], **_: object) -> Any:
        seen.append(cmd)
        return _proc(cmd, 0, "No traces detected", "")

    with (
        patch("mulder.server.tools.mvt.shutil.which", return_value="/usr/bin/mvt"),
        patch(_RUN, side_effect=fake),
        patch("mulder.server.tools.mvt.extract_and_index", side_effect=_Index()),
    ):
        result = run_mvt_android.__wrapped__(str(backup), iocs=str(iocs))  # type: ignore[attr-defined]

    assert result["status"] == "success"
    assert seen[0][-2:] == ["--iocs", str(iocs)]


# ---------------------------------------------------------------------------
# analyze_pdf
# ---------------------------------------------------------------------------


def _pdf(
    tmp_path: Path, pdfid: Any, parser: Any, **kwargs: Any
) -> tuple[dict[str, Any], list[dict[str, Any]], _Index]:
    from mulder.server.tools.documents import analyze_pdf

    target = tmp_path / "doc.pdf"
    target.write_bytes(b"%PDF-1.4\n%%EOF\n")
    index = _Index()
    captured: list[dict[str, Any]] = []

    def fake(cmd: list[str], **_: object) -> Any:
        return pdfid(cmd) if "pdfid.py" in cmd[1] else parser(cmd)

    def capture(*args: Any, **kw: Any) -> dict[str, object]:
        captured.append(args[3])
        return real_tool_response(*args, **kw)

    with (
        patch("mulder.server.tools.documents._pdfid_script", return_value=Path("pdfid.py")),
        patch("mulder.server.tools.documents._pdf_parser_script", return_value=Path("pp.py")),
        patch(_RUN, side_effect=fake),
        patch("mulder.server.tools.documents.extract_and_index", side_effect=index),
        patch("mulder.server.tools.documents.tool_response", side_effect=capture),
    ):
        result = analyze_pdf.__wrapped__("case-1", str(target), **kwargs)  # type: ignore[attr-defined]
    return result, captured, index


def test_pdfid_crash_is_an_error_not_a_clean_pdf(tmp_path: Path) -> None:
    result, _captured, index = _pdf(
        tmp_path,
        lambda cmd: _proc(cmd, 1, "", "Traceback ...\nZeroDivisionError"),
        lambda cmd: _proc(cmd, 0, "", ""),
    )

    assert result["status"] == "error"
    assert "pdfid" in str(result["error_message"])
    assert "ZeroDivisionError" in str(result["error_message"])
    assert index.calls == []


def test_pdf_parser_failure_is_reported(tmp_path: Path) -> None:
    result, captured, index = _pdf(
        tmp_path,
        lambda cmd: _proc(cmd, 0, "PDFiD 0.2.8 doc.pdf\n /JS 0\n", ""),
        lambda cmd: _proc(cmd, 1, "", "pdf-parser: error parsing xref"),
    )

    assert result["status"] == "partial"
    assert "pdf-parser" in str(result["tool_warning"])
    errors = captured[0]["analyzer_errors"]
    assert {e["analyzer"] for e in errors} == {
        "pdf-parser (URLs)",
        "pdf-parser (embedded files)",
    }
    assert "error parsing xref" in errors[0]["error"]
    # URL / embedded extraction do not feed the verdict.
    assert captured[0]["risk_assessment"]["verdict_incomplete"] is False
    assert len(index.calls) == 1


def test_a_verdict_from_a_partial_pdfid_is_marked_incomplete(tmp_path: Path) -> None:
    result, captured, _index = _pdf(
        tmp_path,
        lambda cmd: _proc(cmd, 1, "PDFiD 0.2.8 doc.pdf\n obj 3\n", "MemoryError"),
        lambda cmd: _proc(cmd, 0, "", ""),
    )

    assert result["status"] == "partial"
    risk = captured[0]["risk_assessment"]
    assert risk["risk_level"] == "clean"  # the key stays...
    assert risk["verdict_incomplete"] is True  # ...but is not a clean bill of health
    assert "pdfid" in risk["incomplete_reason"]


def test_a_clean_pdf_stays_success(tmp_path: Path) -> None:
    result, captured, _index = _pdf(
        tmp_path,
        lambda cmd: _proc(cmd, 0, "PDFiD 0.2.8 doc.pdf\n /JS 0\n", ""),
        lambda cmd: _proc(cmd, 0, "", ""),
    )

    assert result["status"] == "success"
    assert "analyzer_errors" not in captured[0]
    assert captured[0]["risk_assessment"]["verdict_incomplete"] is False


# ---------------------------------------------------------------------------
# Zircolite
# ---------------------------------------------------------------------------


@pytest.fixture
def zircolite_env(tmp_path: Path) -> dict[str, Path]:
    script = tmp_path / "zircolite.py"
    script.write_text("")
    events = tmp_path / "audit.log"
    events.write_text("type=EXECVE msg=audit(1700000000.000:1): argc=1\n")
    ruleset = tmp_path / "rules"
    ruleset.mkdir()
    return {"script": script, "events": events, "ruleset": ruleset}


def _zircolite(
    env: dict[str, Path],
    fake: Callable[..., Any],
    *,
    existing: list[str] | None = None,
    kv: str | None = None,
    **kwargs: Any,
) -> tuple[dict[str, Any], _Index, MagicMock]:
    from mulder.server.tools.zircolite import run_zircolite

    index = _Index()
    ctx = MagicMock()
    ctx.db.get_kv.return_value = kv
    run = MagicMock(side_effect=fake)
    with (
        patch(
            "mulder.server.tools.zircolite.sources_already_indexed", return_value=existing or []
        ),
        patch("mulder.server.tools.zircolite.has_ctx", return_value=True),
        patch("mulder.server.tools.zircolite.get_ctx", return_value=ctx),
        patch("mulder.server.tools.zircolite.importlib.util.find_spec", return_value=MagicMock()),
        patch("mulder.server.tools.zircolite._zircolite_script", return_value=env["script"]),
        patch(_RUN, run),
        patch("mulder.server.tools.zircolite.extract_and_index", side_effect=index),
    ):
        result = run_zircolite.__wrapped__(  # type: ignore[attr-defined]
            str(env["events"]), ruleset_path=str(env["ruleset"]), **kwargs
        )
    return result, index, run


def _zircolite_writing(content: str, rc: int = 0) -> Callable[..., Any]:
    def fake(cmd: list[str], **_: object) -> Any:
        Path(cmd[cmd.index("--outfile") + 1]).write_text(content)
        return _proc(cmd, rc, "", "")

    return fake


def test_zircolite_unreadable_results_are_an_error(zircolite_env: dict[str, Path]) -> None:
    result, index, _run = _zircolite(zircolite_env, _zircolite_writing('[{"rule_level": '))

    assert result["status"] == "error"
    assert "could not be parsed" in str(result["error_message"])
    assert index.calls == []


def test_zircolite_skip_is_keyed_on_log_format(zircolite_env: dict[str, Path]) -> None:
    """A default (auditd) run must not block the sysmon_linux run."""
    rows = json.dumps([{"rule_level": "high", "rule_title": "T"}])
    result, index, run = _zircolite(
        zircolite_env,
        _zircolite_writing(rows),
        existing=["zircolite.detections"],
        kv='["auditd"]',
        log_format="sysmon_linux",
    )

    assert run.called, "the sysmon_linux run was skipped because auditd had run"
    assert result["status"] == "success"
    assert index.calls


def test_zircolite_same_format_is_skipped_with_force_hint(zircolite_env: dict[str, Path]) -> None:
    result, _index, run = _zircolite(
        zircolite_env,
        _zircolite_writing("[]"),
        existing=["zircolite.detections"],
        kv='["auditd"]',
        log_format="auditd",
    )

    assert not run.called
    assert "force=True" in str(result["hint"]) + str(result["preview"])


def test_zircolite_does_not_label_detections_as_events(zircolite_env: dict[str, Path]) -> None:
    rows = json.dumps([{"rule_level": "high", "rule_title": "T"}] * 3)
    _result, index, _run = _zircolite(
        zircolite_env, _zircolite_writing(rows), sigma_level_filter=None
    )

    text = index.calls[0][1]
    assert "Events processed" not in text
    assert "Rule matches before level filter: 3" in text


# ---------------------------------------------------------------------------
# YARA
# ---------------------------------------------------------------------------


@pytest.fixture
def yara_env(tmp_path: Path) -> dict[str, Any]:
    from mulder.server.tools import yara

    yara._valid_rules_cache.clear()
    rule = tmp_path / "one.yar"
    rule.write_text("rule R { condition: true }")
    target = tmp_path / "files"
    target.mkdir()
    return {"rule": rule, "target": target, "tmp": tmp_path}


def _yara_files(env: dict[str, Any], rules: str, fake: Callable[..., Any]) -> tuple[Any, _Index]:
    from mulder.server.tools.yara import yara_scan_files

    index = _Index()
    with (
        patch("mulder.server.tools.yara.get_ctx", return_value=MagicMock()),
        patch("mulder.server.tools.yara._update_community_rules"),
        patch("mulder.server.tools.yara.shutil.which", return_value="/usr/bin/yara"),
        patch(_RUN, side_effect=fake),
        patch("mulder.server.tools.yara.extract_and_index", side_effect=index),
    ):
        result = yara_scan_files.__wrapped__(str(env["target"]), rules=rules)  # type: ignore[attr-defined]
    return result, index


def test_yara_rules_that_fail_to_compile_are_reported(yara_env: dict[str, Any]) -> None:
    rules_dir = yara_env["tmp"] / "rules"
    rules_dir.mkdir()
    (rules_dir / "good.yar").write_text("rule G { condition: true }")
    (rules_dir / "bad.yar").write_text("rule B { condition: nope }")

    def fake(cmd: list[str], **_: object) -> Any:
        if cmd[-1] == "/dev/null":  # a compile check
            text = Path(cmd[-2]).read_text()
            if "bad.yar" in text or "nope" in text:
                return _proc(cmd, 1, "", 'error: rule "B" in bad.yar(1): undefined identifier')
            return _proc(cmd, 0)
        return _proc(cmd, 0, "G /evidence/x.bin\n", "")

    result, index = _yara_files(yara_env, str(rules_dir), fake)

    assert result["status"] == "partial"
    assert result["rules_failed_count"] == 1
    failed = result["rules_failed_to_compile"][0]
    assert failed["file"] == "bad.yar"
    assert "undefined identifier" in failed["error"]
    assert "failed to compile" in result["tool_warning"]
    assert result["result_count"] == 1
    assert index.calls


def test_yara_no_rule_compiling_is_an_error_naming_them(yara_env: dict[str, Any]) -> None:
    rules_dir = yara_env["tmp"] / "rules"
    rules_dir.mkdir()
    (rules_dir / "bad1.yar").write_text("x")
    (rules_dir / "bad2.yar").write_text("y")

    result, index = _yara_files(
        yara_env,
        str(rules_dir),
        lambda cmd, **_: _proc(cmd, 1, "", "error: syntax error, unexpected identifier"),
    )

    assert result["status"] == "error"
    assert "bad1.yar" in result["error_message"]
    assert "syntax error" in result["error_message"]
    assert index.calls == []


def test_yara_per_file_errors_beside_hits_are_reported(yara_env: dict[str, Any]) -> None:
    result, index = _yara_files(
        yara_env,
        str(yara_env["rule"]),
        lambda cmd, **_: _proc(
            cmd,
            0,
            "R /evidence/x.bin\n",
            "warning: rule R is slow\nerror scanning /evidence/locked.bin: could not open file",
        ),
    )

    assert result["status"] == "partial"
    assert result["files_failed"] == 1
    assert result["scan_errors"] == [
        {"file": "/evidence/locked.bin", "error": "could not open file"}
    ]
    assert result["result_count"] == 1


def test_yara_failed_scan_is_an_error(yara_env: dict[str, Any]) -> None:
    result, index = _yara_files(
        yara_env,
        str(yara_env["rule"]),
        lambda cmd, **_: _proc(cmd, 1, "", "error: could not open file /nope"),
    )

    assert result["status"] == "error"
    assert "could not open file" in result["error_message"]
    assert index.calls == []


def test_yara_clean_scan_stays_success(yara_env: dict[str, Any]) -> None:
    result, _index = _yara_files(yara_env, str(yara_env["rule"]), lambda cmd, **_: _proc(cmd, 0))

    assert result["status"] == "success"
    assert result["result_count"] == 0
    assert "tool_warning" not in result


_VOL_BANNER = "Volatility 3 Framework 2.7.0\n"


def _yara_vol(env: dict[str, Any], stdout: str, rc: int, stderr: str = "") -> tuple[Any, _Index]:
    from mulder.server.tools.yara import yara_scan_with_volatility

    index = _Index()
    with (
        patch("mulder.server.tools.yara.get_ctx", return_value=MagicMock()),
        patch("mulder.extractors.volatility._find_vol_binary", return_value=["vol"]),
        patch("mulder.server.tools.yara._find_memory_image", return_value="/evidence/mem.raw"),
        patch("mulder.server.tools.yara._update_community_rules"),
        patch(_RUN, side_effect=lambda cmd, **_: _proc(cmd, rc, stdout, stderr)),
        patch("mulder.server.tools.yara.extract_and_index", side_effect=index),
    ):
        result = yara_scan_with_volatility.__wrapped__(rules=str(env["rule"]))  # type: ignore[attr-defined]
    return result, index


def test_vol_failure_with_only_the_banner_is_an_error(yara_env: dict[str, Any]) -> None:
    result, index = _yara_vol(
        yara_env, _VOL_BANNER, 1, "Unsatisfied requirement plugins.VadYaraScan.kernel"
    )

    assert result["status"] == "error"
    assert "Unsatisfied requirement" in result["error_message"]
    assert result["result_count"] == 0
    assert index.calls == []


def test_vol_banner_and_header_are_not_rule_hits(yara_env: dict[str, Any]) -> None:
    stdout = _VOL_BANNER + "\nOffset\tPID\tRule\tComponent\tValue\n\n"
    result, _index = _yara_vol(yara_env, stdout, 0)

    assert result["status"] == "success"
    assert result["result_count"] == 0


def test_vol_rows_are_parsed(yara_env: dict[str, Any]) -> None:
    stdout = (
        _VOL_BANNER
        + "\nOffset\tPID\tRule\tComponent\tValue\n\n"
        + "0x1d0000\t4242\tCobaltStrike_Beacon\t$s1\t4d 5a 90\n"
    )
    result, index = _yara_vol(yara_env, stdout, 0)

    assert result["status"] == "success"
    assert result["result_count"] == 1
    assert result["hit_metadata"]["family_names"] == ["CobaltStrike"]
    assert "Volatility 3 Framework" not in index.calls[0][1]


# ---------------------------------------------------------------------------
# extract_archive (7z)
# ---------------------------------------------------------------------------


def _extract_7z(tmp_path: Path, rc: int, stdout: str) -> tuple[dict[str, Any], MagicMock]:
    from mulder.server.tools.case import extract_archive

    archive = tmp_path / "evidence.7z"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c")
    cases = tmp_path / "cases"
    cases.mkdir()
    cfg = MagicMock()
    cfg.db_dir = cases
    run = MagicMock(side_effect=lambda cmd, **_: _proc(cmd, rc, stdout, ""))
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
        patch("mulder.server.tools.case.shutil.which", return_value="/usr/bin/7z"),
        patch(_RUN, run),
    ):
        result = extract_archive.__wrapped__(str(archive))  # type: ignore[attr-defined]
    return result, run


def test_encrypted_archive_is_named_as_such(tmp_path: Path) -> None:
    result, run = _extract_7z(
        tmp_path, 2, "ERROR: evidence.7z\nCan not open encrypted archive. Wrong password?\n"
    )

    assert result["status"] == "error"
    assert result["error_type"] == "encrypted_archive"
    assert "encrypted" in result["error_message"]
    assert "password" in result["suggestion"]
    # 7z must never be left waiting on a password prompt.
    assert run.call_args.kwargs["stdin"] == subprocess.DEVNULL


def test_7z_failure_carries_7z_output(tmp_path: Path) -> None:
    result, _run = _extract_7z(tmp_path, 2, "ERROR: evidence.7z\nHeaders Error\n")

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert "7z exited 2" in result["error_message"]
    assert "Headers Error" in result["error_message"]
    assert "CalledProcessError" not in result["error_message"]
