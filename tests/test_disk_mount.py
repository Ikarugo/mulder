"""``_mount_image`` must not fall back to ``guestmount``.

libguestfs boots a supermin appliance, which needs a kernel image in the
filesystem.  The container ships none, so the fallback could never succeed
there: it only added a doomed subprocess and a misleading warning after every
``ewfmount`` failure (see ``examples/ndlc/mulder.log``).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.extractors import disk


def _which(name: str) -> str | None:
    return None if name == "mmls" else f"/usr/bin/{name}"


@pytest.mark.parametrize(("name", "first"), [("image.E01", "ewfmount"), ("image.dd", "mount")])
def test_mount_failure_never_invokes_guestmount(tmp_path: Path, name: str, first: str) -> None:
    calls: list[str] = []

    def run(cmd: list[str], **_: object) -> None:
        calls.append(cmd[0])
        raise subprocess.CalledProcessError(1, cmd, stderr=b"No sub system to mount EWF format.\n")

    with (
        patch("mulder.extractors.disk.shutil.which", _which),
        patch("mulder.extractors.disk.subprocess.run", run),
    ):
        assert disk._mount_image(tmp_path / name, tmp_path / "mnt") is False

    assert calls == [first]


def test_e01_mounts_via_ewfmount_then_loop_mount(tmp_path: Path) -> None:
    calls: list[str] = []

    def run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(cmd[0])
        if cmd[0] == "ewfmount":
            (Path(cmd[2]) / "ewf1").touch()
        return subprocess.CompletedProcess(cmd, 0)

    with (
        patch("mulder.extractors.disk.shutil.which", _which),
        patch("mulder.extractors.disk.subprocess.run", run),
    ):
        assert disk._mount_image(tmp_path / "image.E01", tmp_path / "mnt") is True

    assert calls == ["ewfmount", "mount"]
