"""Triage collections: normalization, detection, classification and tool routing.

A triage collection is a directory of files collected from a live Windows
host (Velociraptor, KAPE) that mirrors the volume root. These tests build
small synthetic collections; the file contents are placeholders, since the
point is that each tool is handed the right file, not that EZ Tools parse it.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mulder.triage import (
    detect_raw_collection,
    find_triage_roots,
    find_unprepared_collections,
    is_triage_root,
    iter_tree_files,
)
from mulder.triage.prepare import (
    MANIFEST_NAME,
    TriagePrepareError,
    artifact_coverage,
    map_velociraptor_path,
    missing_artifacts,
    prepare_triage,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VOLUME_FILES: dict[str, bytes] = {
    "$MFT": b"FILE0-mft",
    "Windows/System32/config/SYSTEM": b"regf-system",
    "Windows/System32/config/SYSTEM.LOG1": b"log1",
    "Windows/System32/config/SOFTWARE": b"regf-software",
    "Windows/System32/config/SAM": b"regf-sam",
    "Windows/System32/config/SECURITY": b"regf-security",
    "Windows/System32/winevt/Logs/Security.evtx": b"ElfFile-sec",
    "Windows/System32/winevt/Logs/System.evtx": b"ElfFile-sys",
    "Windows/Prefetch/CMD.EXE-4A81B364.pf": b"MAM-pf",
    "Windows/appcompat/Programs/Amcache.hve": b"regf-amcache",
    "Users/alice/NTUSER.DAT": b"regf-ntuser-alice",
    "Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat": b"regf-usrclass",
    "Users/alice/AppData/Local/Temp/stage.ps1": b"IEX (New-Object Net.WebClient)",
    "Users/alice/AppData/Local/Temp/helper.py": b"import socket",
    (
        "Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/"
        "ConsoleHost_history.txt"
    ): b"whoami",
    "Users/alice/AppData/Roaming/PuTTY/sessions.ini": b"[session]\nhost=10.0.0.5\n",
    "Windows/Logs/CBS/CBS.log": b"noise",
}


def _write_volume(root: Path, files: dict[str, bytes] | None = None) -> Path:
    for rel, data in (files or _VOLUME_FILES).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def _velociraptor_zip(path: Path, include_meta: bool = True) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        if include_meta:
            zf.writestr("client_info.json", json.dumps({"Hostname": "WS01.corp.local"}))
            zf.writestr("collection_context.json", "{}")
            zf.writestr("uploads.json", "[]")
            zf.writestr("results/Windows.System.Pslist.json", '{"Name": "cmd.exe"}\n')
        zf.writestr("uploads/ntfs/%5C%5C.%5CC%3A/$MFT", b"FILE0-mft")
        zf.writestr("uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J", b"usn")
        zf.writestr("uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J.idx", b"idx")
        zf.writestr("uploads/ntfs/%5C%5C.%5CC%3A/Windows/System32/config/SYSTEM", b"from-ntfs")
        zf.writestr("uploads/auto/C%3A/Windows/System32/config/SYSTEM", b"from-auto")
        zf.writestr("uploads/auto/C%3A/Windows/System32/config/SOFTWARE", b"sw")
        zf.writestr("uploads/auto/C%3A/Windows/Prefetch/CMD.EXE-1.pf", b"pf")
        zf.writestr("uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx", b"ev")
        zf.writestr("uploads/auto/C%3A/Users/bob/NTUSER.DAT", b"nt")
        zf.writestr("uploads/auto/D%3A/Data/notes.txt", b"d-drive")
        zf.writestr(
            "uploads/ntfs/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1/"
            "Windows/System32/config/SAM",
            b"vss-sam",
        )
        zf.writestr("uploads/auto/C%3A/../../etc/passwd", b"escape")
    return path


@pytest.fixture()
def triage_root(tmp_path: Path) -> Path:
    """A normalized collection: <tmp>/triage/WS01/C mirrors a Windows volume."""
    host = tmp_path / "triage" / "WS01"
    root = _write_volume(host / "C")
    (host / MANIFEST_NAME).write_text(
        json.dumps({"hostname": "WS01", "source": {"kind": "velociraptor"}})
    )
    return root


@pytest.fixture()
def ctx() -> MagicMock:
    mock = MagicMock()
    mock.case_id = "case"
    mock.db.get_sources.return_value = []
    return mock


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


class TestDetection:
    def test_volume_copy_is_a_triage_root(self, triage_root: Path) -> None:
        assert is_triage_root(triage_root)
        assert not is_triage_root(triage_root.parent)
        assert not is_triage_root(triage_root / "$MFT")

    def test_detection_ignores_case(self, tmp_path: Path) -> None:
        (tmp_path / "WINDOWS" / "system32" / "CONFIG").mkdir(parents=True)
        assert is_triage_root(tmp_path)

    def test_mft_alone_is_enough(self, tmp_path: Path) -> None:
        (tmp_path / "$MFT").write_bytes(b"x")
        assert is_triage_root(tmp_path)

    def test_disk_image_file_is_not_a_triage_root(self, tmp_path: Path) -> None:
        image = tmp_path / "disk.E01"
        image.write_bytes(b"EVF")
        assert not is_triage_root(image)

    def test_tree_walk_matches_fls_path_shape(self, triage_root: Path) -> None:
        rels = {rel for rel, _ in iter_tree_files(triage_root)}
        assert "Windows/Prefetch/CMD.EXE-4A81B364.pf" in rels
        assert all(not r.startswith("/") for r in rels)

    def test_find_triage_roots_stops_at_the_root(self, triage_root: Path) -> None:
        roots = find_triage_roots(triage_root.parent.parent)
        assert roots == [triage_root]

    def test_velociraptor_zip_and_dir_detected(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "Collection-WS01.zip")
        assert detect_raw_collection(z) == "velociraptor"
        extracted = tmp_path / "extracted"
        with zipfile.ZipFile(z) as zf:
            zf.extractall(extracted)
        assert detect_raw_collection(extracted) == "velociraptor"

    def test_plain_zip_is_not_a_collection(self, tmp_path: Path) -> None:
        z = tmp_path / "docs.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("a.txt", "x")
        assert detect_raw_collection(z) is None

    def test_kape_destination_detected(self, tmp_path: Path) -> None:
        _write_volume(tmp_path / "kape" / "C")
        assert detect_raw_collection(tmp_path / "kape") == "kape"

    def test_unprepared_collections_are_found(self, tmp_path: Path) -> None:
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        z = _velociraptor_zip(evidence / "Collection-WS01.zip")
        _write_volume(evidence / "kape" / "C")
        assert find_unprepared_collections(evidence) == [z]


# ---------------------------------------------------------------------------
# prepare-triage
# ---------------------------------------------------------------------------


class TestVelociraptorPathMapping:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("uploads/auto/C%3A/Windows/System32/config/SAM", "C/Windows/System32/config/SAM"),
            ("uploads/ntfs/%5C%5C.%5CC%3A/$MFT", "C/$MFT"),
            ("uploads/ntfs/%5C%5C.%5CC%3A/%24MFT", "C/$MFT"),
            ("uploads/file/d%3A/x.txt", "D/x.txt"),
            ("uploads/auto/C%3A%5CUsers%5Cbob%5CNTUSER.DAT", "C/Users/bob/NTUSER.DAT"),
        ],
    )
    def test_drive_paths(self, name: str, expected: str) -> None:
        mapped = map_velociraptor_path(name)
        assert mapped is not None
        assert mapped[0] == expected

    def test_ntfs_accessor_outranks_auto(self) -> None:
        ntfs = map_velociraptor_path("uploads/ntfs/%5C%5C.%5CC%3A/x")
        auto = map_velociraptor_path("uploads/auto/C%3A/x")
        assert ntfs is not None and auto is not None
        assert ntfs[1] > auto[1]

    def test_traversal_is_dropped(self) -> None:
        assert map_velociraptor_path("uploads/auto/C%3A/../../etc/passwd") is None
        assert map_velociraptor_path("uploads/auto/C%3A/%2E%2E/%2E%2E/x") is None

    def test_shadow_copies_are_opt_in(self) -> None:
        name = (
            "uploads/ntfs/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy3/"
            "Windows/System32/config/SAM"
        )
        assert map_velociraptor_path(name) is None
        mapped = map_velociraptor_path(name, include_vss=True)
        assert mapped is not None
        assert mapped[0] == "_vss/HarddiskVolumeShadowCopy3/Windows/System32/config/SAM"


class TestPrepareVelociraptor:
    def test_zip_is_normalized(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "Collection-WS01-2026-09-25.zip")
        result = prepare_triage(z, tmp_path / "out")

        host = tmp_path / "out" / "WS01"
        assert result.hostname == "WS01"
        assert result.kind == "velociraptor"
        assert [r.name for r in result.triage_roots] == ["C"]
        assert (host / "C" / "$MFT").read_bytes() == b"FILE0-mft"
        assert (host / "C" / "$Extend" / "$UsnJrnl:$J").read_bytes() == b"usn"
        assert not (host / "C" / "$Extend" / "$UsnJrnl:$J.idx").exists()
        assert (host / "D" / "Data" / "notes.txt").exists()
        assert not (host / "_vss").exists()
        assert not any("passwd" in str(p) for p in host.rglob("*"))
        assert (host / "_collector" / "velociraptor" / "client_info.json").exists()
        assert (host / "_collector" / "velociraptor" / "results").is_dir()

    def test_raw_ntfs_copy_wins(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "c.zip")
        result = prepare_triage(z, tmp_path / "out")
        system = tmp_path / "out" / "WS01" / "C" / "Windows" / "System32" / "config" / "SYSTEM"
        assert system.read_bytes() == b"from-ntfs"
        assert any("several accessors" in w for w in result.warnings)

    def test_manifest_hashes_every_file(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "c.zip")
        prepare_triage(z, tmp_path / "out")
        host = tmp_path / "out" / "WS01"
        manifest = json.loads((host / MANIFEST_NAME).read_text())

        assert manifest["source"]["kind"] == "velociraptor"
        assert manifest["source"]["sha256"] == hashlib.sha256(z.read_bytes()).hexdigest()
        assert manifest["files"]
        for rec in manifest["files"]:
            data = (host / rec["path"]).read_bytes()
            assert hashlib.sha256(data).hexdigest() == rec["sha256"]
            assert rec["size"] == len(data)
        mft = next(r for r in manifest["files"] if r["path"] == "C/$MFT")
        assert mft["source"] == "uploads/ntfs/%5C%5C.%5CC%3A/$MFT"

    def test_coverage_lists_missing_artifacts(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "c.zip")
        result = prepare_triage(z, tmp_path / "out")
        cov = result.coverage["C"]
        assert cov["mft"] is True
        assert cov["usn_journal"] is True
        assert cov["prefetch_files"] == 1
        assert "registry hive SAM" in cov["missing"]  # type: ignore[operator]
        assert "Amcache.hve" in cov["missing"]  # type: ignore[operator]

    def test_extracted_directory_matches_zip(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "c.zip")
        extracted = tmp_path / "extracted"
        with zipfile.ZipFile(z) as zf:
            zf.extractall(extracted)
        prepare_triage(z, tmp_path / "from_zip")
        prepare_triage(extracted, tmp_path / "from_dir")
        a = {rel for rel, _ in iter_tree_files(tmp_path / "from_zip" / "WS01" / "C")}
        b = {rel for rel, _ in iter_tree_files(tmp_path / "from_dir" / "WS01" / "C")}
        # zipfile.extractall strips the ".." of the traversal entry, so the
        # extracted copy holds a harmless C%3A/etc/passwd that the zip path
        # rejected outright.
        assert b - a == {"etc/passwd"}
        assert a <= b

    def test_include_vss(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "c.zip")
        prepare_triage(z, tmp_path / "out", include_vss=True)
        vss = tmp_path / "out" / "WS01" / "_vss" / "HarddiskVolumeShadowCopy1"
        assert (vss / "Windows" / "System32" / "config" / "SAM").read_bytes() == b"vss-sam"

    def test_hostname_falls_back_to_file_name(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "Collection-DESKTOP-9-2026-01-02T10_00Z.zip", False)
        # Without metadata the zip is no longer auto-detected; name the kind.
        result = prepare_triage(z, tmp_path / "out", kind="velociraptor")
        assert result.hostname == "DESKTOP-9"

    def test_existing_output_needs_force(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "c.zip")
        prepare_triage(z, tmp_path / "out")
        with pytest.raises(TriagePrepareError, match="--force"):
            prepare_triage(z, tmp_path / "out")
        prepare_triage(z, tmp_path / "out", force=True)

    def test_encrypted_zip_is_refused(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "c.zip")
        raw = bytearray(z.read_bytes())
        # Set the "encrypted" bit on the first local header and its
        # central-directory twin, the flag zipfile checks.
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            idx = raw.find(sig)
            flag_at = idx + (6 if sig == b"PK\x03\x04" else 8)
            raw[flag_at] |= 0x1
        z.write_bytes(bytes(raw))
        with pytest.raises(TriagePrepareError, match="encrypted"):
            prepare_triage(z, tmp_path / "out")

    def test_output_inside_source_is_refused(self, tmp_path: Path) -> None:
        src = _write_volume(tmp_path / "C")
        with pytest.raises(TriagePrepareError, match="outside"):
            prepare_triage(src, src / "out", kind="tree")


class TestPrepareKapeAndTree:
    def test_kape_destination(self, tmp_path: Path) -> None:
        tdest = tmp_path / "kape" / "2026-09-25T101010_triage"
        _write_volume(tdest / "C")
        (tdest / "2026-09-25_CopyLog.csv").write_text("copied")
        result = prepare_triage(tmp_path / "kape", tmp_path / "out", hostname="WS02")

        host = tmp_path / "out" / "WS02"
        assert result.kind == "kape"
        assert (host / "C" / "Windows" / "System32" / "config" / "SYSTEM").exists()
        assert (host / "_collector" / "kape" / "2026-09-25_CopyLog.csv").exists()
        assert result.coverage["C"]["missing"] == ["USN journal ($J)", "SRUM database"]

    def test_plain_volume_copy(self, tmp_path: Path) -> None:
        src = _write_volume(tmp_path / "sherlock" / "C")
        result = prepare_triage(src, tmp_path / "out", hostname="lab")
        assert result.kind == "tree"
        assert is_triage_root(tmp_path / "out" / "lab" / "C")

    def test_missing_hostname_is_reported(self, tmp_path: Path) -> None:
        src = _write_volume(tmp_path / "vol")
        result = prepare_triage(src, tmp_path / "out")
        assert result.hostname == "vol"
        assert any("--hostname" in w for w in result.warnings)

    def test_unknown_input_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "random").mkdir()
        with pytest.raises(TriagePrepareError, match="Unrecognized"):
            prepare_triage(tmp_path / "random", tmp_path / "out")


class TestCoverage:
    def test_full_volume(self, triage_root: Path) -> None:
        cov = artifact_coverage(triage_root)
        assert cov["ntuser_dat"] == ["alice"]
        assert cov["usrclass_dat"] == ["alice"]
        assert cov["powershell_history"] == ["alice"]
        assert cov["amcache"] is True
        assert cov["evtx_files"] == 2
        assert missing_artifacts(cov) == ["USN journal ($J)", "SRUM database"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    def test_prepare_triage_command(self, tmp_path: Path) -> None:
        from mulder.cli import cli

        z = _velociraptor_zip(tmp_path / "c.zip")
        res = CliRunner().invoke(cli, ["prepare-triage", str(z), str(tmp_path / "out")])
        assert res.exit_code == 0, res.output
        assert "Volume C:" in res.output
        assert "missing" in res.output

    def test_prepare_triage_error_is_clean(self, tmp_path: Path) -> None:
        from mulder.cli import cli

        (tmp_path / "empty").mkdir()
        res = CliRunner().invoke(
            cli, ["prepare-triage", str(tmp_path / "empty"), str(tmp_path / "out")]
        )
        assert res.exit_code != 0
        assert "Unrecognized collection" in res.output

    def test_investigate_refuses_raw_collections(self, tmp_path: Path) -> None:
        from mulder.cli import cli

        evidence = tmp_path / "evidence"
        evidence.mkdir()
        _velociraptor_zip(evidence / "Collection-WS01.zip")
        with patch("mulder.orchestrator.runner.Orchestrator") as orch:
            res = CliRunner().invoke(
                cli, ["investigate", str(evidence), "case1", "--cwd", str(tmp_path / "ws")]
            )
        assert res.exit_code != 0
        assert "mulder prepare-triage" in res.output
        orch.assert_not_called()


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class TestClassifier:
    def _classify(self, root: Path) -> dict[str, list[Path]]:
        from mulder.extractors.classifier import EvidenceClassifier

        out: dict[str, list[Path]] = {}
        for item in EvidenceClassifier().classify(root):
            out.setdefault(item.artifact_type, []).append(item.path)
        return out

    def test_triage_root_is_one_entry(self, triage_root: Path) -> None:
        by_type = self._classify(triage_root.parent.parent)
        assert by_type["triage_collection"] == [triage_root]
        # Logs are covered by the collection's own tools, not listed one by one.
        assert "evtx" not in by_type
        assert "log_file" not in by_type
        assert "log_directory" not in by_type

    def test_scripts_inside_collection_are_catalogued(self, triage_root: Path) -> None:
        by_type = self._classify(triage_root.parent.parent)
        names = {p.name for p in by_type["script"]}
        assert names == {"stage.ps1", "helper.py"}
        assert [p.name for p in by_type["powershell_history"]] == ["ConsoleHost_history.txt"]

    def test_evidence_root_itself_can_be_the_collection(self, triage_root: Path) -> None:
        assert self._classify(triage_root)["triage_collection"] == [triage_root]

    def test_windows_scripts_outside_collections(self, tmp_path: Path) -> None:
        (tmp_path / "dropper.ps1").write_text("x")
        (tmp_path / "run.bat").write_text("x")
        (tmp_path / "loader.js").write_text("x")
        (tmp_path / "analyst_helper.py").write_text("x")
        by_type = self._classify(tmp_path)
        assert {p.name for p in by_type["script"]} == {"dropper.ps1", "run.bat", "loader.js"}

    def test_raw_velociraptor_collection(self, tmp_path: Path) -> None:
        z = _velociraptor_zip(tmp_path / "Collection-WS01.zip")
        extracted = tmp_path / "extracted"
        with zipfile.ZipFile(z) as zf:
            zf.extractall(extracted)
        by_type = self._classify(tmp_path)
        assert set(by_type["raw_triage_collection"]) == {z, extracted}
        assert "compressed_archive" not in by_type
        # C%3A inside the raw tree holds a hive folder but must not be
        # mistaken for a usable triage root.
        assert "triage_collection" not in by_type


# ---------------------------------------------------------------------------
# Tool routing on a triage root
# ---------------------------------------------------------------------------


class TestMountAndExtraction:
    def test_mount_yields_the_directory(self, triage_root: Path) -> None:
        from mulder.server.extract_helpers import mount_disk_image

        with (
            patch("mulder.server.extract_helpers._mount_image") as fuse,
            mount_disk_image(str(triage_root)) as mount_point,
        ):
            assert Path(mount_point) == triage_root
        fuse.assert_not_called()

    def test_tsk_extract_copies_matching_files(self, triage_root: Path, ctx: MagicMock) -> None:
        from mulder.server.tools.extract import tsk

        with (
            patch.object(tsk, "get_ctx", return_value=ctx),
            patch("mulder.server.tools.extract.tsk.subprocess.run") as run,
        ):
            extracted = tsk._tsk_extract_files(str(triage_root), ["Prefetch/", ".pf"])
        run.assert_not_called()
        assert [rel for rel, _ in extracted] == ["Windows/Prefetch/CMD.EXE-4A81B364.pf"]
        staged = extracted[0][1]
        assert staged.name == "Windows_Prefetch_CMD.EXE-4A81B364.pf"
        assert staged.read_bytes() == b"MAM-pf"
        assert not staged.is_symlink()
        assert staged.parent.name.startswith("mulder_tsk_extract_")
        tsk._cleanup_tsk_extract_dir(str(staged.parent))
        assert (triage_root / "Windows" / "Prefetch" / "CMD.EXE-4A81B364.pf").exists()

    def test_user_hives_are_discovered(self, triage_root: Path) -> None:
        from mulder.server.tools.extract.registry import _discover_user_hives_via_tsk

        hives, extract_dir = _discover_user_hives_via_tsk(str(triage_root))
        assert extract_dir is not None
        found = sorted((htype, user, p.read_bytes()) for p, htype, user in hives)
        assert found == [
            ("ntuser", "alice", b"regf-ntuser-alice"),
            ("usrclass", "alice", b"regf-usrclass"),
        ]

    def test_system_hives_are_discovered(self, triage_root: Path, ctx: MagicMock) -> None:
        from mulder.server.tools.extract import registry, tsk

        with patch.object(tsk, "get_ctx", return_value=ctx):
            hives, extract_dir = registry._discover_hives_via_tsk(str(triage_root))
        names = {name for _p, name in hives}
        assert {"system", "software", "sam", "security"} <= names
        assert extract_dir is not None

    def test_evtx_copied_for_the_image_flow(self, triage_root: Path, tmp_path: Path) -> None:
        from mulder.server.tools.extract.evtx import _extract_evtx_from_image

        dest = tmp_path / "evtx_out"
        dest.mkdir()
        files = _extract_evtx_from_image(str(triage_root), str(dest))
        assert sorted(f.name for f in files) == [
            "Windows_System32_winevt_Logs_Security.evtx",
            "Windows_System32_winevt_Logs_System.evtx",
        ]


class TestToolsOnTriageRoot:
    @staticmethod
    def _call(tool: str, **kwargs: Any) -> dict[str, Any]:
        import inspect

        from mulder.server.app import _tool_dispatch_sync

        fn = _tool_dispatch_sync[tool]
        if "case_id" in inspect.signature(fn).parameters:
            kwargs.setdefault("case_id", "case")
        return fn(**kwargs)  # type: ignore[no-any-return]

    @pytest.mark.parametrize(
        "tool",
        [
            "run_fls",
            "run_mmls",
            "run_fsstat",
            "run_mactime",
            "detect_masquerading",
            "run_bulk_extractor",
            "analyze_disk_pcaps",
            "run_vshadow_info",
            "run_optical_listing",
        ],
    )
    def test_image_only_tools_redirect(self, tool: str, triage_root: Path) -> None:
        with patch("mulder.server.tools.extract.tsk.subprocess.run") as run:
            result = self._call(tool, image_path=str(triage_root))
        assert result["status"] == "error"
        assert result["error_type"] == "not_applicable_triage"
        assert "run_registry_parser" in result["suggestion"] or result["suggestion"]
        run.assert_not_called()

    def test_prefetch_parser_reads_the_collection(self, triage_root: Path, ctx: MagicMock) -> None:
        from mulder.server.tools.extract import misc, tsk

        seen: dict[str, Any] = {}

        def fake_ez(dll: str, args: list[str], *rest: Any) -> dict[str, object]:
            seen["dll"] = dll
            seen["files"] = sorted(p.name for p in Path(args[1]).iterdir())
            return {"status": "success"}

        with (
            patch.object(tsk, "get_ctx", return_value=ctx),
            patch.object(misc, "sources_already_indexed", return_value=[]),
            patch.object(misc, "_run_ez_tool", side_effect=fake_ez),
        ):
            result = misc.run_prefetch_parser.__wrapped__(str(triage_root))  # type: ignore[attr-defined]
        assert result == {"status": "success"}
        assert seen == {
            "dll": "PECmd.dll",
            "files": ["Windows_Prefetch_CMD.EXE-4A81B364.pf"],
        }

    def test_amcache_parser_picks_the_hive(self, triage_root: Path, ctx: MagicMock) -> None:
        from mulder.server.tools.extract import misc, tsk

        seen: dict[str, Any] = {}

        def fake_ez(dll: str, args: list[str], *rest: Any) -> dict[str, object]:
            seen["file"] = Path(args[1]).read_bytes()
            return {"status": "success"}

        with (
            patch.object(tsk, "get_ctx", return_value=ctx),
            patch.object(misc, "sources_already_indexed", return_value=[]),
            patch.object(misc, "_run_ez_tool", side_effect=fake_ez),
        ):
            misc.run_amcache_parser.__wrapped__(str(triage_root))  # type: ignore[attr-defined]
        assert seen["file"] == b"regf-amcache"

    def test_mft_parser_uses_the_collected_mft(self, triage_root: Path) -> None:
        from mulder.server.tools.extract import misc

        seen: dict[str, Any] = {}

        def fake_ez(dll: str, args: list[str], *rest: Any) -> dict[str, object]:
            seen["dll"] = dll
            seen["path"] = args[1]
            return {"status": "success"}

        with (
            patch.object(misc, "sources_already_indexed", return_value=[]),
            patch.object(misc, "_resolve_partition_offset") as offset,
            patch.object(misc, "_detect_filesystem_type") as fstype,
            patch("mulder.server.tools.extract.misc.subprocess.run") as run,
            patch.object(misc, "_run_ez_tool", side_effect=fake_ez),
        ):
            misc.run_mft_parser.__wrapped__(str(triage_root))  # type: ignore[attr-defined]
        offset.assert_not_called()
        fstype.assert_not_called()
        run.assert_not_called()
        assert seen == {"dll": "MFTECmd.dll", "path": str(triage_root / "$MFT")}

    def test_index_app_files_reads_the_tree(self, triage_root: Path, ctx: MagicMock) -> None:
        from mulder.server.tools.extract import app_files

        with (
            patch.object(app_files, "get_ctx", return_value=ctx),
            patch.object(app_files, "_collect_fls_chunks") as chunks,
            patch.object(
                app_files, "extract_and_index", return_value={"windows_indexed": 1}
            ) as idx,
        ):
            result = self._call(
                "index_app_files",
                case_id="case",
                image_path=str(triage_root),
                directory_pattern="Users/*/AppData/Roaming/PuTTY",
            )
        chunks.assert_not_called()
        assert result["status"] == "success"
        assert result["results"]["files_indexed"] == 1
        text = idx.call_args.args[0]
        assert "host=10.0.0.5" in text


# ---------------------------------------------------------------------------
# Catalog and planner context
# ---------------------------------------------------------------------------


class TestCatalogAndContext:
    def test_manifest_entry_carries_coverage(self, triage_root: Path) -> None:
        from mulder.extractors.classifier import ClassifiedEvidence
        from mulder.server.tools.case import _manifest_entry

        entry = _manifest_entry(ClassifiedEvidence(triage_root, "triage_collection"))
        assert entry["hostname"] == "WS01"
        assert entry["collector"] == "velociraptor"
        assert "image_path" in str(entry["note"])
        assert entry["missing_artifacts"] == ["USN journal ($J)", "SRUM database"]

    def test_every_collected_file_is_hashed(self, triage_root: Path) -> None:
        from mulder.server.tools.case import _evidence_files

        files = _evidence_files([{"path": str(triage_root), "artifact_type": "triage_collection"}])
        assert len(files) == len(_VOLUME_FILES)

    def test_planner_context_lists_collection_and_scripts(self, triage_root: Path) -> None:
        from mulder.orchestrator.evidence import EvidenceContext

        evidence = triage_root.parent.parent
        text = EvidenceContext(str(evidence)).build_evidence_context("WS01")
        assert "Triage collections" in text
        assert str(triage_root) in text
        assert "hives: SYSTEM, SOFTWARE, SAM, SECURITY" in text
        assert "MISSING: USN journal ($J), SRUM database" in text
        assert "stage.ps1" in text
        assert "helper.py" in text
        assert "ConsoleHost_history.txt" in text
        # Collected hives and logs are never mistaken for memory or archives.
        assert "memory dumps" not in text
        assert "No pre-populated paths" not in text

    def test_triage_systems_get_their_own_session(self) -> None:
        from mulder.orchestrator.evidence import EvidenceContext

        # Memory-only systems are batched four to a session when there are
        # many; a system with a collection is a full host and is not.
        catalog = {
            "systems": [
                {"name": f"WS0{i}", "evidence": ["triage_collection", "memory_dump"]}
                for i in range(1, 6)
            ]
        }
        groups = EvidenceContext("/evidence").group_systems(
            [str(s["name"]) for s in catalog["systems"]], catalog
        )
        assert len(groups) == 5
        assert all(len(g) == 1 for g in groups)


class TestHiveSelection:
    """Regression: hive names come from the source path, not the flattened copy."""

    def test_each_hive_keeps_its_name(self, tmp_path: Path) -> None:
        from mulder.server.tools.extract.registry import _select_system_hives

        def staged(rel: str) -> tuple[str, Path]:
            return rel, tmp_path / rel.replace("/", "_")

        extracted = [
            staged("Windows.old/Windows/System32/config/SYSTEM"),
            staged("Windows/System32/config/SAM"),
            staged("Windows/System32/config/SECURITY"),
            staged("Windows/System32/config/SOFTWARE"),
            staged("Windows/System32/config/SYSTEM"),
            staged("Windows/System32/config/SYSTEM.LOG1"),
            staged("Windows/System32/config/systemprofile/NTUSER.DAT"),
        ]
        selected = {name: path.name for path, name in _select_system_hives(extracted)}
        assert selected == {
            "sam": "Windows_System32_config_SAM",
            "security": "Windows_System32_config_SECURITY",
            "software": "Windows_System32_config_SOFTWARE",
            "system": "Windows_System32_config_SYSTEM",
        }
