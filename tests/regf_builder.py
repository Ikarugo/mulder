"""Build small registry hives (regf) for tests.

Writes one hbin holding nk, lf, vk and data cells, which is enough for
python-registry to open keys and read values. Value data over 4 bytes is
stored in its own cell; big-data (``db``) records are not supported, so
keep values under 16 KB.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

REG_SZ = 1
REG_BINARY = 3
REG_DWORD = 4

_HBIN_START = 0x1000


@dataclass
class Key:
    values: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    keys: dict[str, Key] = field(default_factory=dict)

    def key(self, path: str) -> Key:
        """The subkey at a backslash-separated *path*, created as needed."""
        node = self
        for part in path.split("\\"):
            node = node.keys.setdefault(part, Key())
        return node

    def sz(self, name: str, text: str) -> Key:
        self.values[name] = (REG_SZ, (text + "\x00").encode("utf-16-le"))
        return self

    def dword(self, name: str, value: int) -> Key:
        self.values[name] = (REG_DWORD, struct.pack("<I", value))
        return self

    def binary(self, name: str, data: bytes) -> Key:
        self.values[name] = (REG_BINARY, data)
        return self


class _Cells:
    def __init__(self) -> None:
        self.buf = bytearray()

    def alloc(self, data: bytes) -> int:
        """Store a cell and return its offset relative to the first hbin."""
        size = (len(data) + 4 + 7) & ~7
        offset = 0x20 + len(self.buf)
        self.buf += struct.pack("<i", -size) + data + b"\x00" * (size - 4 - len(data))
        return offset

    def patch(self, offset: int, at: int, data: bytes) -> None:
        start = offset - 0x20 + 4 + at
        self.buf[start : start + len(data)] = data


def _nk(name: str, flags: int, parent: int) -> bytes:
    raw = name.encode("ascii")
    head = bytearray(0x4C)
    head[0:2] = b"nk"
    struct.pack_into("<H", head, 0x2, flags)
    struct.pack_into("<I", head, 0x10, parent)
    for off in (0x1C, 0x20, 0x28, 0x2C, 0x30):
        struct.pack_into("<I", head, off, 0xFFFFFFFF)
    struct.pack_into("<H", head, 0x48, len(raw))
    return bytes(head) + raw


def _vk(cells: _Cells, name: str, vtype: int, data: bytes) -> int:
    raw = name.encode("ascii")
    if len(data) <= 4:
        length = len(data) | 0x80000000
        data_field = data.ljust(4, b"\x00")
    else:
        length = len(data)
        data_field = struct.pack("<I", cells.alloc(data))
    head = b"vk" + struct.pack("<HI", len(raw), length) + data_field
    head += struct.pack("<IHH", vtype, 1 if raw else 0, 0)
    return cells.alloc(head + raw)


def _write_key(cells: _Cells, name: str, key: Key, parent: int, root: bool) -> int:
    offset = cells.alloc(_nk(name, 0x2C if root else 0x20, parent))
    children = sorted(key.keys.items(), key=lambda kv: kv[0].upper())
    child_offsets = [_write_key(cells, n, k, offset, False) for n, k in children]
    if children:
        lf = b"lf" + struct.pack("<H", len(children))
        for (n, _), off in zip(children, child_offsets, strict=True):
            lf += struct.pack("<I", off) + n.encode("ascii")[:4].ljust(4, b"\x00")
        cells.patch(offset, 0x14, struct.pack("<I", len(children)))
        cells.patch(offset, 0x1C, struct.pack("<I", cells.alloc(lf)))
    if key.values:
        vks = [_vk(cells, n, t, d) for n, (t, d) in key.values.items()]
        cells.patch(offset, 0x24, struct.pack("<I", len(vks)))
        value_list = cells.alloc(struct.pack(f"<{len(vks)}I", *vks))
        cells.patch(offset, 0x28, struct.pack("<I", value_list))
    return offset


def build_hive(path: Path, root: Key, *, dirty: bool = False) -> Path:
    """Write *root* as a hive at *path* (sequence numbers differ when *dirty*)."""
    cells = _Cells()
    root_offset = _write_key(cells, "ROOT", root, 0xFFFFFFFF, True)
    hbin_size = (0x20 + len(cells.buf) + 0xFFF) & ~0xFFF
    body = bytearray(hbin_size)
    body[0:4] = b"hbin"
    struct.pack_into("<II", body, 4, 0, hbin_size)
    body[0x20 : 0x20 + len(cells.buf)] = cells.buf
    free = hbin_size - 0x20 - len(cells.buf)
    if free:
        struct.pack_into("<i", body, 0x20 + len(cells.buf), free)

    header = bytearray(_HBIN_START)
    header[0:4] = b"regf"
    struct.pack_into("<II", header, 4, 2, 1 if dirty else 2)
    struct.pack_into("<IIIII", header, 0x14, 1, 5, 0, 1, root_offset)
    struct.pack_into("<II", header, 0x28, hbin_size, 1)
    checksum = 0
    for (word,) in struct.iter_unpack("<I", bytes(header[:0x1FC])):
        checksum ^= word
    struct.pack_into("<I", header, 0x1FC, checksum)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(header) + bytes(body))
    return path
