"""Build synthetic NTFS $MFT records for tests (1 KiB records, fixups applied)."""

from __future__ import annotations

import struct

RECORD = 1024
FT_2024_11_06 = 133753318940000000  # 2024-11-06T01:58:14Z as FILETIME


def _attr(attr_type: int, content: bytes, name: str = "") -> bytes:
    name_b = name.encode("utf-16-le")
    header_len = 0x18
    name_off = header_len
    content_off = (name_off + len(name_b) + 7) // 8 * 8
    total = (content_off + len(content) + 7) // 8 * 8
    buf = bytearray(total)
    struct.pack_into("<IIBBH", buf, 0, attr_type, total, 0, len(name), name_off)
    struct.pack_into("<IH", buf, 0x10, len(content), content_off)
    buf[name_off : name_off + len(name_b)] = name_b
    buf[content_off : content_off + len(content)] = content
    return bytes(buf)


def _nonresident_data(real_size: int) -> bytes:
    buf = bytearray(0x48)
    struct.pack_into("<IIBBH", buf, 0, 0x80, 0x48, 1, 0, 0x40)
    struct.pack_into("<Q", buf, 0x30, real_size)
    return bytes(buf)


def file_name_attr(name: str, parent: int) -> bytes:
    body = bytearray(0x42)
    struct.pack_into("<Q", body, 0, parent | (1 << 48))
    struct.pack_into("<QQ", body, 8, FT_2024_11_06, FT_2024_11_06)
    body[0x40] = len(name)
    body[0x41] = 1
    return _attr(0x30, bytes(body) + name.encode("utf-16-le"))


def build_record(
    name: str,
    parent: int = 5,
    data: bytes | None = b"",
    in_use: bool = True,
    ads: dict[str, bytes] | None = None,
    nonresident_size: int | None = None,
) -> bytes:
    """One 1 KiB FILE record with $SI, $FN and $DATA; fixups applied as on disk."""
    si = bytearray(0x48)
    struct.pack_into("<QQQQ", si, 0, FT_2024_11_06, FT_2024_11_06, FT_2024_11_06, FT_2024_11_06)
    attrs = _attr(0x10, bytes(si)) + file_name_attr(name, parent)
    if nonresident_size is not None:
        attrs += _nonresident_data(nonresident_size)
    elif data is not None:
        attrs += _attr(0x80, data)
    for stream, content in (ads or {}).items():
        attrs += _attr(0x80, content, stream)
    attrs += struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 4

    rec = bytearray(RECORD)
    rec[0:4] = b"FILE"
    usa_offset, usa_count = 0x30, 3
    first_attr = 0x38
    struct.pack_into("<HH", rec, 4, usa_offset, usa_count)
    struct.pack_into(
        "<HHHHII", rec, 0x10, 1, 1, first_attr, 1 if in_use else 0, first_attr + len(attrs), RECORD
    )
    rec[first_attr : first_attr + len(attrs)] = attrs
    usn = b"\x07\x00"
    rec[usa_offset : usa_offset + 2] = usn
    for i in (1, 2):
        end = i * 512 - 2
        rec[usa_offset + 2 * i : usa_offset + 2 * i + 2] = rec[end : end + 2]
        rec[end : end + 2] = usn
    return bytes(rec)


def build_mft(records: dict[int, bytes], count: int | None = None) -> bytes:
    """An $MFT with *records* at their entry numbers and empty FILE records elsewhere."""
    total = count or (max(records) + 1)
    out = bytearray()
    for i in range(total):
        out += records.get(i) or build_record(f"filler{i}", data=b"x")
    return bytes(out)
