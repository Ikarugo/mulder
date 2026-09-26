"""What kind of sample is this? Decides which reverse-engineering route to take.

Magic bytes first, extension second: a PE renamed ``.txt`` is still a PE.
"""

from __future__ import annotations

import struct
from pathlib import Path

from mulder.server.helpers import detect_text_encoding

__all__ = ["SAMPLE_KINDS", "describe_kind", "detect_sample_kind"]

SAMPLE_KINDS = (
    "pe",
    "pe_dotnet",
    "elf",
    "macho",
    "script",
    "document",
    "archive",
    "unknown",
)

_SCRIPT_EXTS = {
    ".ps1",
    ".psm1",
    ".psd1",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".bat",
    ".cmd",
    ".hta",
    ".wsf",
    ".sh",
    ".py",
}
_DOCUMENT_MAGIC = (b"%PDF", b"\xd0\xcf\x11\xe0", b"{\\rtf")
_ARCHIVE_MAGIC = (b"PK\x03\x04", b"Rar!", b"7z\xbc\xaf", b"\x1f\x8b")
_MACHO_MAGIC = (
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)
_CLR_DIRECTORY = 14


def _pe_is_dotnet(head: bytes) -> bool:
    """True when the PE's CLR runtime header directory is set (.NET)."""
    try:
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if head[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            return False
        opt = e_lfanew + 24
        magic = struct.unpack_from("<H", head, opt)[0]
        dirs = opt + (96 if magic == 0x10B else 112 if magic == 0x20B else -1)
        if dirs < opt:
            return False
        rva, size = struct.unpack_from("<II", head, dirs + _CLR_DIRECTORY * 8)
        return bool(rva != 0 and size != 0)
    except struct.error:
        return False


def detect_sample_kind(path: Path) -> str:
    """One of :data:`SAMPLE_KINDS`."""
    with path.open("rb") as fh:
        head = fh.read(4096)
    if head[:2] == b"MZ":
        return "pe_dotnet" if _pe_is_dotnet(head) else "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in _MACHO_MAGIC:
        return "macho"
    if head.startswith(_DOCUMENT_MAGIC):
        return "document"
    if head.startswith(_ARCHIVE_MAGIC):
        return "archive"
    if path.suffix.lower() in _SCRIPT_EXTS:
        return "script"
    if head and detect_text_encoding(head) != "binary":
        return "script"
    return "unknown"


_DESCRIPTIONS = {
    "pe": "Windows PE executable (native code): Ghidra route.",
    "pe_dotnet": (
        ".NET assembly: Ghidra decompiles .NET poorly. Triage it, but do not rely on "
        "Ghidra's output for its logic; a .NET decompiler (ILSpy) is needed for the code."
    ),
    "elf": "ELF executable (native code): Ghidra route.",
    "macho": "Mach-O executable (native code): Ghidra route.",
    "script": "Script or text: read and decode it statically, layer by layer.",
    "document": "Document (PDF/OLE/RTF): not a direct target for these tools; triage only.",
    "archive": "Archive: extract its members and analyse them one at a time.",
    "unknown": "Unknown format: triage only.",
}


def describe_kind(kind: str) -> str:
    return _DESCRIPTIONS.get(kind, _DESCRIPTIONS["unknown"])
