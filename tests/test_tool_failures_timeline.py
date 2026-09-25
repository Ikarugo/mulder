"""Failed Hayabusa / Plaso / icat runs must not read as "ran, found nothing".

Each wrapper here used to trust a zero exit code or an empty output file:
Hayabusa exits 0 when it refuses to run, log2timeline leaves a partial
storage file behind when it dies, psort was invoked in a way that always
failed (and its error went to stdout, which was not shown), and an ``icat``
that could not read a file handed back ``b""`` which was then counted as a
clean sample. These tests drive the wrappers through ``run_tool`` with a
faked ``subprocess.run`` and check three shapes: a failed run is an error
and nothing is indexed; a non-zero exit after real output is indexed as
``partial`` with a ``tool_warning``; a clean run that found nothing stays a
success, without claiming anything was indexed.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools import hayabusa
from mulder.server.tools import plaso as plaso_query
from mulder.server.tools.extract import masquerade
from mulder.server.tools.extract import plaso as plaso_extract

Proc = subprocess.CompletedProcess[str]
_RUN = "mulder.server.helpers.subprocess.run"


def _proc(rc: int, stdout: str = "", stderr: str = "", argv: list[str] | None = None) -> Proc:
    return subprocess.CompletedProcess(argv or ["tool"], rc, stdout=stdout, stderr=stderr)


class _Memory:
    """A case context whose kv store backs the helpers' failure memory."""

    def __init__(self) -> None:
        self.kv: dict[str, str] = {}
        self.ctx = MagicMock()
        self.ctx.db.get_kv.side_effect = self.kv.get
        self.ctx.db.set_kv.side_effect = self.kv.__setitem__


@pytest.fixture
def memory() -> Iterator[_Memory]:
    mem = _Memory()
    with (
        patch("mulder.server.helpers.has_ctx", return_value=True),
        patch("mulder.server.helpers.get_ctx", return_value=mem.ctx),
    ):
        yield mem


# ---------------------------------------------------------------------------
# run_hayabusa
# ---------------------------------------------------------------------------

_HB_HEADER = "Timestamp,RuleTitle,Level,Computer,MitreAttack\n"
_HB_ROW = "2026-01-01 00:00:00,Suspicious PowerShell,high,WS01,T1059.001\n"


def _hb_report(files: int = 2, hits: int = 0, total: int = 1234, color: bool = False) -> str:
    green, reset = ("\x1b[38;2;0;255;0m", "\x1b[0m") if color else ("", "")
    return (
        f"{green}Total event log files: {reset}{files:,}\n"
        f"{green}Total file size: {reset}1.2 MiB\n\nScanning finished.\n\n"
        f"{green}Results Summary:{reset}\n\n"
        f"Events with hits / Total events: {hits:,} / {total:,} "
        f"(Data reduction: {total - hits:,} events (100.00%))\n"
    )


HbRunner = Callable[[list[str], Path], Proc]


class _Hayabusa:
    def __init__(self, evtx_dir: Path) -> None:
        self.evtx_dir = evtx_dir
        self.indexed: list[str] = []
        self.argv: list[list[str]] = []
        self.skip_checks: list[str | None] = []

    def call(
        self,
        run: HbRunner,
        *,
        indexed_for: Callable[[str | None], list[str]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        def _run(cmd: list[str], **_: object) -> Proc:
            self.argv.append(list(cmd))
            return run(cmd, Path(cmd[cmd.index("-o") + 1]))

        def _index(**kw: object) -> dict[str, object]:
            self.indexed.append(str(kw["raw_output"]))
            return {"windows_indexed": 1, "line_count": 2, "status": "indexed"}

        def _already(_prefixes: list[str], evidence_path: str | None = None) -> list[str]:
            self.skip_checks.append(evidence_path)
            return indexed_for(evidence_path) if indexed_for else []

        kwargs.setdefault("evtx_dir", str(self.evtx_dir))
        with (
            patch.object(hayabusa, "_hayabusa_binary", return_value="/opt/hayabusa/hayabusa"),
            patch.object(hayabusa, "sources_already_indexed", side_effect=_already),
            patch.object(hayabusa, "extract_and_index", side_effect=_index),
            patch(_RUN, side_effect=_run),
        ):
            result: dict[str, Any] = hayabusa.run_hayabusa.__wrapped__(**kwargs)  # type: ignore[attr-defined]
        return result


@pytest.fixture
def hb(tmp_path: Path) -> _Hayabusa:
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    (evtx / "Security.evtx").write_bytes(b"ElfFile\x00")
    return _Hayabusa(evtx)


def _writes(csv: str, rc: int = 0, stdout: str = "", stderr: str = "") -> HbRunner:
    def _run(cmd: list[str], out: Path) -> Proc:
        out.write_text(csv)
        return _proc(rc, stdout, stderr, cmd)

    return _run


class TestHayabusa:
    def test_exit_0_without_a_scan_report_is_an_error(self, hb: _Hayabusa) -> None:
        """Hayabusa's refusal to overwrite its output exits 0 and scans nothing."""
        refusal = "[ERROR]  The file /tmp/x.csv already exists. Please add -C, --clobber.\n"
        result = hb.call(_writes("", stderr=refusal))

        assert result["status"] == "error"
        assert result["error_type"] == "tool_failed"
        assert "already exists" in result["error_message"]
        assert "total_alerts" not in str(result)
        assert hb.indexed == []

    def test_zero_event_log_files_is_an_error(self, hb: _Hayabusa) -> None:
        stdout = "Total event log files: 0\n"
        stderr = "[ERROR] No .evtx files were found.\n"
        result = hb.call(_writes("", stdout=stdout, stderr=stderr))

        assert result["status"] == "error"
        assert "0 event log files" in result["error_message"]
        assert "No .evtx files were found" in result["error_message"]

    def test_scanned_and_nothing_matched_is_a_success(self, hb: _Hayabusa) -> None:
        result = hb.call(_writes("", stdout=_hb_report(files=2, total=1234, color=True)))

        assert result["status"] == "success"
        assert '"total_alerts": 0' in result["preview"]
        assert '"events_scanned": 1234' in result["preview"]
        assert '"event_log_files_scanned": 2' in result["preview"]
        assert "Nothing was indexed" in result["hint"], "an empty scan must not claim an index"
        assert hb.indexed == []

    def test_scanned_zero_events_is_partial(self, hb: _Hayabusa) -> None:
        result = hb.call(_writes("", stdout=_hb_report(files=3, total=0)))

        assert result["status"] == "partial"
        assert "read 0 events" in result["tool_warning"]

    def test_non_zero_exit_after_alerts_keeps_them_with_a_warning(self, hb: _Hayabusa) -> None:
        stderr = "[ERROR] Failed to parse event file: /evtx/Broken.evtx\n"
        result = hb.call(_writes(_HB_HEADER + _HB_ROW, rc=1, stdout=_hb_report(), stderr=stderr))

        assert result["status"] == "partial"
        assert "Broken.evtx" in result["tool_warning"]
        assert "exited 1" in result["tool_warning"]
        assert hb.indexed == [_HB_HEADER + _HB_ROW]
        assert '"total_alerts": 1' in result["preview"]

    def test_non_zero_exit_without_alerts_is_an_error(self, hb: _Hayabusa) -> None:
        result = hb.call(_writes("", rc=2, stderr="thread 'main' panicked\n"))

        assert result["status"] == "error"
        assert "panicked" in result["error_message"]
        assert hb.indexed == []

    def test_timeout_is_an_error(self, hb: _Hayabusa) -> None:
        def _slow(cmd: list[str], _out: Path) -> Proc:
            raise subprocess.TimeoutExpired(cmd, 300)

        result = hb.call(_slow)
        assert result["status"] == "error"
        assert result["error_type"] == "timeout"

    def test_error_log_is_surfaced(
        self, hb: _Hayabusa, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hayabusa writes per-file errors to ./logs/errorlog-*.log and only names it."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "logs").mkdir()
        (tmp_path / "logs" / "errorlog-1.log").write_text(
            "user input: hayabusa csv-timeline ...\n[ERROR] Failed to open System.evtx\n"
        )
        stdout = _hb_report() + (
            "\nErrors were generated. Please check ./logs/errorlog-1.log for details.\n"
        )
        result = hb.call(_writes(_HB_HEADER + _HB_ROW, stdout=stdout))

        assert result["status"] == "partial"
        assert "Failed to open System.evtx" in result["tool_warning"]

    def test_skip_compares_the_resolved_directory(self, hb: _Hayabusa) -> None:
        """hayabusa.alerts is registered under the resolved EVTX dir: compare that."""
        from mulder.server.tools.extract import evtx

        target = str(hb.evtx_dir)

        with patch.dict(evtx._evtx_extract_dirs, {"/cases/disk.E01": target}, clear=True):
            result = hb.call(
                _writes(""),
                evtx_dir="",
                image_path="/cases/disk.E01",
                indexed_for=lambda path: ["hayabusa.alerts"] if path == target else [],
            )

        assert hb.argv == [], "already indexed for this directory: Hayabusa must not run"
        assert target in hb.skip_checks
        assert None not in hb.skip_checks
        assert "force=True" in result["preview"]

    def test_no_directory_known_never_skips_across_evidence(
        self, hb: _Hayabusa, tmp_path: Path
    ) -> None:
        """With nothing to compare, the old unscoped check skipped on other evidence."""
        from mulder.server.tools.extract import evtx

        with (
            patch.dict(evtx._evtx_extract_dirs, {}, clear=True),
            patch.object(hayabusa, "get_ctx", side_effect=RuntimeError("no case")),
        ):
            result = hb.call(
                _writes(""),
                evtx_dir="",
                image_path="",
                indexed_for=lambda _path: ["hayabusa.alerts"],
            )

        assert None not in hb.skip_checks
        assert result["status"] == "error"  # no EVTX dir: the run itself cannot start
        assert "No EVTX directory" in result["error_message"]

    def test_failure_is_remembered_per_directory_and_severity(
        self, hb: _Hayabusa, memory: _Memory
    ) -> None:
        first = hb.call(_writes("", rc=1, stderr="rules folder missing\n"))
        assert first["status"] == "error"
        assert len(hb.argv) == 1

        again = hb.call(_writes("", rc=1, stderr="rules folder missing\n"))
        assert again["status"] == "error"
        assert "Not run again" in again["error_message"]
        assert len(hb.argv) == 1, "the same failing scan must not run twice"

        other = hb.call(_writes("", stdout=_hb_report()), min_severity="high")
        assert other["status"] == "success", "another severity is another run"

        forced = hb.call(_writes("", stdout=_hb_report()), force=True)
        assert forced["status"] == "success"
        assert len(hb.argv) == 3


# ---------------------------------------------------------------------------
# run_plaso
# ---------------------------------------------------------------------------

_L2T_HEADER = (
    "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,"
    "filename,inode,notes,format,extra"
)
_L2T_ROW_EVTX = (
    "01/15/2025,08:00:00,UTC,M...,EVT,WinEVTX,Content Modification Time,-,WS01,"
    "4624,Logon,2,Security.evtx,-,-,winevtx,-"
)
_L2T_ROW_PF = (
    "01/15/2025,08:01:00,UTC,.A..,LOG,WinPrefetch,Last Time Executed,-,WS01,"
    "EVIL.EXE,Prefetch,2,EVIL.EXE-1234.pf,-,-,prefetch,-"
)


class _Plaso:
    """subprocess.run stand-in for log2timeline / psort / pinfo."""

    def __init__(
        self,
        *,
        l2t: Proc | None = None,
        storage: bytes = b"plaso",
        psort: Proc | None = None,
        csv: str | None = f"{_L2T_HEADER}\n{_L2T_ROW_EVTX}\n",
    ) -> None:
        self.l2t = l2t or _proc(0, stdout="Processing completed.\n")
        self.storage = storage
        self.psort = psort or _proc(0, stdout="Processing completed.\n")
        self.csv = csv
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_: object) -> Proc:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool == "log2timeline":
            if self.storage:
                Path(argv[argv.index("--storage_file") + 1]).write_bytes(self.storage)
            return self.l2t
        if tool == "psort":
            if "-w" not in argv:
                return _proc(1, stdout="ERROR: Output format: l2tcsv requires an output file\n")
            out = Path(argv[argv.index("-w") + 1])
            if out.exists():
                return _proc(1, stdout=f"ERROR: Output file already exists: {out}\n")
            if self.csv is not None:
                out.write_text(self.csv)
            return self.psort
        return _proc(0, stdout="Storage file: timeline.plaso\n")


class _RunPlaso:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.indexed: list[tuple[str, str]] = []

    def call(self, fake: _Plaso, *, found: set[str] | None = None, **kwargs: Any) -> Any:
        tools = found if found is not None else {"log2timeline", "psort", "pinfo"}

        def _index(raw: str, source: str, *_: object) -> dict[str, object]:
            self.indexed.append((source, raw))
            return {"source_name": source, "windows_indexed": 1, "line_count": 2}

        kwargs.setdefault("evidence_path", "/evidence/disk.E01")
        with (
            patch.object(
                plaso_extract,
                "_find_plaso_cmd",
                side_effect=lambda t: [f"/usr/bin/{t}"] if t in tools else None,
            ),
            patch.object(plaso_extract, "get_cfg", return_value=MagicMock(db_dir=self.tmp_path)),
            patch.object(plaso_extract, "get_ctx", return_value=MagicMock(case_id="case")),
            patch.object(plaso_extract, "extract_and_index", side_effect=_index),
            patch(_RUN, side_effect=fake),
        ):
            return plaso_extract.run_plaso.__wrapped__(**kwargs)  # type: ignore[attr-defined]


@pytest.fixture
def rp(tmp_path: Path, memory: _Memory) -> _RunPlaso:
    # ``memory`` isolates failure memory from any case a previous test left open.
    return _RunPlaso(tmp_path)


class TestRunPlaso:
    def test_timeline_is_indexed(self, rp: _RunPlaso) -> None:
        result = rp.call(_Plaso())
        assert result["status"] == "success"
        assert [s for s, _ in rp.indexed] == ["plaso.timeline", "plaso.stats"]
        assert "Full output indexed as 'plaso.timeline'" in result["hint"]

    def test_l2t_non_zero_with_storage_is_partial(self, rp: _RunPlaso) -> None:
        l2t = _proc(1, stdout="Worker failed: unable to open NTUSER.DAT\n")
        result = rp.call(_Plaso(l2t=l2t))

        assert result["status"] == "partial"
        assert "log2timeline exited 1" in result["tool_warning"]
        assert "NTUSER.DAT" in result["tool_warning"]
        assert ("plaso.timeline", f"{_L2T_HEADER}\n{_L2T_ROW_EVTX}") in rp.indexed

    def test_l2t_failed_and_no_events_is_an_error(self, rp: _RunPlaso) -> None:
        l2t = _proc(1, stdout="No supported file system found in source.\n")
        result = rp.call(_Plaso(l2t=l2t, csv=_L2T_HEADER + "\n"))

        assert result["status"] == "error"
        assert "No supported file system" in result["error_message"]
        assert rp.indexed == []

    def test_no_storage_file_is_an_error_showing_stdout(self, rp: _RunPlaso) -> None:
        """plaso prints its own errors on stdout; they must reach the message."""
        l2t = _proc(1, stdout="Checking dependencies [OK]\nUnable to open source: bad E01\n")
        fake = _Plaso(l2t=l2t, storage=b"")
        result = rp.call(fake)

        assert result["status"] == "error"
        assert "Unable to open source: bad E01" in result["error_message"]
        assert len(fake.calls) == 1
        assert rp.indexed == []

    def test_empty_timeline_does_not_claim_an_index(self, rp: _RunPlaso) -> None:
        result = rp.call(_Plaso(csv=_L2T_HEADER + "\n"))

        assert result["status"] == "success"
        assert "Nothing was indexed as 'plaso.timeline'" in result["hint"]
        assert '"events": 0' in result["preview"]
        assert "plaso.timeline" not in [s for s, _ in rp.indexed]

    def test_missing_psort_is_an_error_before_l2t_runs(self, rp: _RunPlaso) -> None:
        """The old code fell back to a bare "psort.py" that raised FileNotFoundError."""
        fake = _Plaso()
        result = rp.call(fake, found={"log2timeline", "pinfo"})

        assert result["status"] == "error"
        assert result["error_type"] == "binary_missing"
        assert fake.calls == []

    def test_psort_failure_is_an_error_naming_its_stdout(self, rp: _RunPlaso) -> None:
        psort = _proc(1, stdout="ERROR: Unable to compile filter expression\n")
        result = rp.call(_Plaso(psort=psort, csv=None), time_range="2015-08-01")

        assert result["status"] == "error"
        assert "Unable to compile filter expression" in result["error_message"]
        assert rp.indexed == []

    def test_time_range_uses_a_current_plaso_filter(self, rp: _RunPlaso) -> None:
        fake = _Plaso()
        rp.call(fake, time_range="2015-08-01 10:00:00")
        psort_argv = next(c for c in fake.calls if Path(c[0]).name == "psort")
        assert psort_argv[-1] == "timestamp > DATETIME('2015-08-01T10:00:00')"

    def test_l2t_failure_is_remembered(self, rp: _RunPlaso, memory: _Memory) -> None:
        l2t = _proc(1, stdout="No supported file system found in source.\n")
        fake = _Plaso(l2t=l2t, storage=b"")
        assert rp.call(fake)["status"] == "error"
        again = rp.call(fake)
        assert "Not run again" in again["error_message"]
        assert len(fake.calls) == 1

        other_parsers = rp.call(fake, parsers="winevtx")
        assert "Not run again" not in other_parsers["error_message"]
        rp.call(fake, force=True)
        assert len(fake.calls) == 3


# ---------------------------------------------------------------------------
# filter_timeline / export_timeline_slice
# ---------------------------------------------------------------------------


class _Query:
    def __init__(self, tmp_path: Path) -> None:
        self.plaso_file = tmp_path / "case.plaso"
        self.plaso_file.write_bytes(b"plaso")
        self.indexed: list[tuple[str, str]] = []

    def call(self, tool: Any, fake: Callable[..., Proc], *args: Any, psort: bool = True) -> Any:
        ctx = MagicMock()
        ctx.db.get_sources.return_value = [
            MagicMock(source_name="plaso.stats", source_path=str(self.plaso_file))
        ]

        def _index(raw: str, source: str, *_: object) -> dict[str, object]:
            self.indexed.append((source, raw))
            return {"windows_indexed": 1}

        with (
            patch.object(plaso_query, "get_ctx", return_value=ctx),
            patch.object(
                plaso_query,
                "_find_plaso_cmd",
                return_value=["/usr/bin/psort"] if psort else None,
            ),
            patch.object(plaso_query, "extract_and_index", side_effect=_index),
            patch(_RUN, side_effect=fake),
        ):
            return tool.__wrapped__(*args)


@pytest.fixture
def q(tmp_path: Path) -> _Query:
    return _Query(tmp_path)


class TestPsortQueries:
    def test_filter_timeline_writes_l2tcsv_to_a_file(self, q: _Query) -> None:
        """Without -w psort refuses l2tcsv ("requires an output file") and exits 1."""
        fake = _Plaso(csv=f"{_L2T_HEADER}\n{_L2T_ROW_EVTX}\n{_L2T_ROW_PF}\n")
        result = q.call(
            plaso_query.filter_timeline, fake, "2025-01-15 07:00:00", "2025-01-15T09:00:00"
        )

        assert result["status"] == "success", result
        assert result["result_count"] == 2
        argv = fake.calls[0]
        assert argv[argv.index("-o") + 1] == "l2tcsv"
        assert "-w" in argv
        assert argv[-2] == str(q.plaso_file)
        assert argv[-1] == (
            "timestamp >= DATETIME('2025-01-15T07:00:00') AND "
            "timestamp <= DATETIME('2025-01-15T09:00:00')"
        )
        assert q.indexed and q.indexed[0][0] == "plaso.filtered"

    def test_parser_filter_uses_the_format_column(self, q: _Query) -> None:
        fake = _Plaso(csv=f"{_L2T_HEADER}\n{_L2T_ROW_EVTX}\n{_L2T_ROW_PF}\n")
        result = q.call(
            plaso_query.filter_timeline, fake, "2025-01-15", "2025-01-16", None, "prefetch"
        )

        assert result["result_count"] == 1
        assert "parser" not in fake.calls[0][-1]
        assert q.indexed[0][1] == f"{_L2T_HEADER}\n{_L2T_ROW_PF}"

    def test_psort_failure_shows_its_stdout(self, q: _Query) -> None:
        psort = _proc(1, stdout="ERROR: Unable to open storage file\n", stderr="[INFO] start\n")
        result = q.call(plaso_query.filter_timeline, _Plaso(psort=psort, csv=None), "a", "b")

        assert result["status"] == "error"
        assert result["error_type"] == "tool_failed"
        assert "Unable to open storage file" in result["error_message"]
        assert q.indexed == []

    def test_no_events_does_not_claim_an_index(self, q: _Query) -> None:
        result = q.call(
            plaso_query.filter_timeline, _Plaso(csv=_L2T_HEADER + "\n"), "2025-01-15", "2025-01-16"
        )

        assert result["status"] == "success"
        assert result["result_count"] == 0
        assert "nothing was indexed" in result["hint"]
        assert q.indexed == []

    def test_non_zero_with_rows_is_partial(self, q: _Query) -> None:
        psort = _proc(1, stdout="ERROR: event data missing for event 42\n")
        fake = _Plaso(psort=psort, csv=f"{_L2T_HEADER}\n{_L2T_ROW_EVTX}\n")
        result = q.call(plaso_query.filter_timeline, fake, "2025-01-15", "2025-01-16")

        assert result["status"] == "partial"
        assert "event data missing" in result["tool_warning"]
        assert result["result_count"] == 1

    def test_missing_psort_is_an_error(self, q: _Query) -> None:
        result = q.call(plaso_query.filter_timeline, _Plaso(), "a", "b", psort=False)
        assert result["status"] == "error"
        assert result["error_type"] == "binary_missing"

    def test_slice_is_minutes_and_written_to_a_file(self, q: _Query) -> None:
        fake = _Plaso(csv=f"{_L2T_HEADER}\n{_L2T_ROW_EVTX}\n")
        result = q.call(plaso_query.export_timeline_slice, fake, "2025-01-15 08:00:00")

        assert result["status"] == "success", result
        argv = fake.calls[0]
        assert "-w" in argv
        assert argv[argv.index("--slice") + 1] == "2025-01-15T08:00:00"
        assert argv[argv.index("--slice_size") + 1] == "5", "--slice_size is in minutes"
        assert argv[-1] == str(q.plaso_file)
        assert q.indexed[0][0] == "plaso.slice"

    def test_slice_timeout_is_an_error(self, q: _Query) -> None:
        def _slow(argv: list[str], **_: object) -> Proc:
            raise subprocess.TimeoutExpired(argv, 300)

        result = q.call(plaso_query.export_timeline_slice, _slow, "2025-01-15T08:00:00")
        assert result["status"] == "error"
        assert result["error_type"] == "timeout"


# ---------------------------------------------------------------------------
# detect_masquerading
# ---------------------------------------------------------------------------


def _fls_line(inode: str, path: str) -> str:
    ts = "2015-01-01 00:00:00 (UTC)"
    return f"r/r {inode}:\t{path}\t{ts}\t{ts}\t{ts}\t{ts}\t100\t0\t0\n"


_FLS = (
    _fls_line("5", "Users/bob/movie.7z")
    + _fls_line("6", "Users/bob/readme.txt")
    + _fls_line("7", "Users/bob/gone.docx")
)
_HEADS: dict[str, bytes] = {
    "5": b"PK\x03\x04" + b"\x00" * 26 + b"[Content_Types].xml xl/workbook.xml",
    "6": b"plain text\n",
}


def _masq(fls: Proc, heads: Callable[[str], bytes]) -> tuple[dict[str, Any], MagicMock]:
    def _head(_image: str, _offset: int, inode: str, _n: int) -> bytes:
        return heads(inode)

    with (
        patch(_RUN, return_value=fls),
        patch.object(masquerade, "_read_head", side_effect=_head),
        patch.object(masquerade, "require_binary", return_value="/usr/bin/x"),
        patch.object(masquerade, "sources_already_indexed", return_value=[]),
        patch.object(masquerade, "extract_and_index", return_value={"line_count": 1}) as index,
    ):
        result = masquerade.detect_masquerading.__wrapped__(  # type: ignore[attr-defined]
            "/ev/disk.E01", partition_offset=128
        )
    return result, index


def _unreadable_7(inode: str) -> bytes:
    if inode == "7":
        raise masquerade._HeadReadError("icat exited 1: Error reading image file (sector 99)")
    return _HEADS[inode]


class TestMasquerade:
    def test_unreadable_file_is_reported_not_counted_clean(self) -> None:
        result, index = _masq(_proc(0, _FLS), _unreadable_7)

        assert result["status"] == "partial"
        assert "could not read 1 allocated file(s) of the 3" in result["tool_warning"]
        assert "gone.docx" in result["tool_warning"]
        preview = result["preview"]
        assert '"files_sampled": 2' in preview, "an unreadable file is not a checked sample"
        assert '"files_unreadable": 1' in preview
        assert "Error reading image file (sector 99)" in preview
        assert index.called, "the mismatches found on readable files are still indexed"

    def test_every_read_failing_is_an_error(self) -> None:
        def _none(inode: str) -> bytes:
            raise masquerade._HeadReadError("icat exited 1: Invalid file system type")

        result, index = _masq(_proc(0, _FLS), _none)

        assert result["status"] == "error"
        assert "could not read any of the 3 files" in result["error_message"]
        index.assert_not_called()

    def test_all_readable_stays_a_success(self) -> None:
        heads = {**_HEADS, "7": b"PK\x03\x04" + b"\x00" * 26 + b"[Content_Types].xml word/"}
        result, _index = _masq(_proc(0, _FLS), heads.__getitem__)

        assert result["status"] == "success"
        assert '"files_unreadable": 0' in result["preview"]
        assert "tool_warning" not in result

    def test_fls_stopping_part_way_is_partial(self) -> None:
        fls = _proc(1, _FLS, stderr="Error reading directory contents (inode 900)")
        result, _index = _masq(fls, _unreadable_7)

        assert result["status"] == "partial"
        assert "Error reading directory contents" in result["tool_warning"]

    def test_read_head_returns_the_reason(self) -> None:
        fail = ["sh", "-c", "echo 'icat: Error reading image file' >&2; exit 1", "sh"]
        with (
            patch.object(masquerade, "_tsk_cmd", return_value=fail),
            pytest.raises(masquerade._HeadReadError, match="Error reading image file"),
        ):
            masquerade._read_head("/ev/disk.E01", 0, "7", 64)

        ok = ["sh", "-c", "printf 'MZ\\220\\000'", "sh"]
        with patch.object(masquerade, "_tsk_cmd", return_value=ok):
            assert masquerade._read_head("/ev/disk.E01", 0, "7", 64).startswith(b"MZ")
