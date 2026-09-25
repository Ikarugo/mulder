"""Read one $MFT record: names, timestamps and resident data of small files.

NTFS stores the content of a small file (up to about 700 bytes in a
1 KiB record) inside its $MFT record rather than in clusters. When the
file is deleted the record is only marked free, so a dropper script,
batch file or config that was deleted is often still readable from a
collected $MFT, with no disk image. MFTECmd does this with ``--de``;
this tool does it in Python so it works on any collection.
"""

from __future__ import annotations

import hashlib
import mmap
import re
import struct
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    TOOL_TIMEOUT,
    detect_text_encoding,
    error_response,
    make_tool_call_id,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import _resolve_partition_offset, icat_file
from mulder.triage import child_ci, is_triage_root

__all__ = ["extract_mft_record", "parse_mft_record"]

_ATTR_STANDARD_INFORMATION = 0x10
_ATTR_FILE_NAME = 0x30
_ATTR_DATA = 0x80
_ATTR_END = 0xFFFFFFFF
_TEXT_CAP = 64 * 1024
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_NAMESPACES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}


class MftFormatError(ValueError):
    """The bytes are not a usable $MFT record."""


def _filetime(value: int) -> str | None:
    if not value:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _apply_fixups(record: bytearray) -> None:
    """Restore the last two bytes of each 512-byte sector from the update sequence array."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count < 2 or usa_offset + 2 * usa_count > len(record):
        raise MftFormatError("bad update sequence array")
    usn = record[usa_offset : usa_offset + 2]
    for i in range(1, usa_count):
        end = i * 512 - 2
        if end + 2 > len(record):
            break
        if record[end : end + 2] != usn:
            raise MftFormatError(f"torn record: sector {i} fails the update sequence check")
        record[end : end + 2] = record[usa_offset + 2 * i : usa_offset + 2 * i + 2]


def parse_mft_record(raw: bytes, entry: int) -> dict[str, Any]:
    """Decode one $MFT record: flags, $STANDARD_INFORMATION, $FILE_NAME and $DATA streams."""
    if raw[:4] != b"FILE":
        raise MftFormatError(f"entry {entry}: no FILE signature ({raw[:4]!r})")
    rec = bytearray(raw)
    _apply_fixups(rec)
    sequence, _links, first_attr, flags, used = struct.unpack_from("<HHHHI", rec, 0x10)
    base_ref = struct.unpack_from("<Q", rec, 0x20)[0] & 0xFFFFFFFFFFFF
    out: dict[str, Any] = {
        "entry": entry,
        "sequence": sequence,
        "in_use": bool(flags & 0x01),
        "is_directory": bool(flags & 0x02),
        "base_record": base_ref or None,
        "names": [],
        "streams": [],
    }
    pos = first_attr
    limit = min(used, len(rec))
    while pos + 16 <= limit:
        attr_type, attr_len = struct.unpack_from("<II", rec, pos)
        if attr_type == _ATTR_END or attr_len == 0 or pos + attr_len > limit:
            break
        non_resident = rec[pos + 8]
        name_len = rec[pos + 9]
        name_off = struct.unpack_from("<H", rec, pos + 10)[0]
        attr_name = (
            bytes(rec[pos + name_off : pos + name_off + 2 * name_len]).decode(
                "utf-16-le", errors="replace"
            )
            if name_len
            else ""
        )
        if non_resident:
            content = b""
            real_size = struct.unpack_from("<Q", rec, pos + 0x30)[0]
        else:
            c_len, c_off = struct.unpack_from("<IH", rec, pos + 0x10)
            content = bytes(rec[pos + c_off : pos + c_off + c_len])
            real_size = c_len

        if attr_type == _ATTR_STANDARD_INFORMATION and len(content) >= 32:
            created, modified, changed, accessed = struct.unpack_from("<QQQQ", content, 0)
            out["si_times"] = {
                "created": _filetime(created),
                "modified": _filetime(modified),
                "mft_changed": _filetime(changed),
                "accessed": _filetime(accessed),
            }
        elif attr_type == _ATTR_FILE_NAME and len(content) >= 0x42:
            parent = struct.unpack_from("<Q", content, 0)[0] & 0xFFFFFFFFFFFF
            fn_created, fn_modified = struct.unpack_from("<QQ", content, 8)
            n_len, namespace = content[0x40], content[0x41]
            name = content[0x42 : 0x42 + 2 * n_len].decode("utf-16-le", errors="replace")
            out["names"].append(
                {
                    "name": name,
                    "parent_entry": parent,
                    "namespace": _NAMESPACES.get(namespace, str(namespace)),
                    "fn_created": _filetime(fn_created),
                    "fn_modified": _filetime(fn_modified),
                }
            )
        elif attr_type == _ATTR_DATA:
            out["streams"].append(
                {
                    "stream": attr_name or "(unnamed)",
                    "resident": not non_resident,
                    "size": real_size,
                    "content": content if not non_resident else None,
                }
            )
        pos += attr_len
    return out


def _record_size(mft: Any) -> int:
    if mft[:4] != b"FILE":
        raise MftFormatError("the file does not start with an $MFT record")
    size = struct.unpack_from("<I", mft, 0x1C)[0]
    if size not in (1024, 2048, 4096):
        raise MftFormatError(f"unexpected record size {size}")
    return int(size)


def _name_pattern(name: str) -> re.Pattern[bytes]:
    """Case-insensitive pattern for *name* as stored in a $FILE_NAME (UTF-16LE)."""
    parts = []
    for ch in name:
        variants = {ch.lower(), ch.upper()}
        alternatives = b"|".join(re.escape(v.encode("utf-16-le")) for v in sorted(variants))
        parts.append(b"(?:" + alternatives + b")")
    return re.compile(b"".join(parts))


def _find_by_name(mft: Any, record_size: int, name: str, limit: int) -> list[int]:
    wanted = name.lower()
    entries: list[int] = []
    for m in _name_pattern(name).finditer(mft):
        entry = m.start() // record_size
        if entries and entries[-1] == entry:
            continue
        try:
            rec = parse_mft_record(
                bytes(mft[entry * record_size : (entry + 1) * record_size]), entry
            )
        except MftFormatError:
            continue
        if any(n["name"].lower() == wanted for n in rec["names"]):
            entries.append(entry)
            if len(entries) >= limit:
                break
    return entries


def _locate_mft(image_path: str, tmpdir: str) -> tuple[Path | None, str | None]:
    """The $MFT to read, or ``(None, why it could not be read)``."""
    if is_triage_root(image_path):
        found = child_ci(Path(image_path), "$MFT")
        return (found, None) if found is not None and found.is_file() else (None, None)
    dest = Path(tmpdir) / "$MFT"
    ok, reason = icat_file(
        image_path, _resolve_partition_offset(image_path), "0", dest, timeout=TOOL_TIMEOUT * 4
    )
    return (dest, None) if ok else (None, reason)


def _describe(rec: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """JSON-safe summary of a parsed record, and the text to index for it."""
    lines = [
        f"MFT entry {rec['entry']} seq {rec['sequence']} "
        f"{'in use' if rec['in_use'] else 'NOT IN USE (deleted)'}"
        f"{' directory' if rec['is_directory'] else ''}"
    ]
    for n in rec["names"]:
        lines.append(
            f"name={n['name']} parent_entry={n['parent_entry']} ({n['namespace']}) "
            f"fn_created={n['fn_created']}"
        )
    if rec.get("si_times"):
        lines.append("si_times " + " ".join(f"{k}={v}" for k, v in rec["si_times"].items()))
    streams: list[dict[str, Any]] = []
    for st in rec["streams"]:
        info: dict[str, Any] = {k: st[k] for k in ("stream", "resident", "size")}
        if st["resident"]:
            blob: bytes = st["content"] or b""
            info["sha256"] = hashlib.sha256(blob).hexdigest()
            encoding = detect_text_encoding(blob[:4096])
            info["encoding"] = encoding
            if encoding == "binary":
                info["hex"] = blob[:512].hex(" ")
                lines.append(f"stream {st['stream']} resident {len(blob)} bytes (binary)")
            else:
                text = blob.decode(encoding, errors="replace")
                info["text"] = text[:_TEXT_CAP]
                if len(text) > _TEXT_CAP:
                    info["text_truncated"] = True
                lines.append(f"stream {st['stream']} resident {len(blob)} bytes:\n{text}")
        else:
            info["note"] = (
                "Non-resident: the content lives in clusters outside the $MFT and cannot be "
                "read from the $MFT alone (a disk image is needed)."
            )
            lines.append(f"stream {st['stream']} non-resident {st['size']} bytes")
        streams.append(info)
    summary = {k: v for k, v in rec.items() if k != "streams"}
    summary["streams"] = streams
    if not rec["in_use"]:
        summary["note"] = (
            "Deleted record: its content is what NTFS left behind and may be stale "
            "or partly reused by a later file."
        )
    return summary, "\n".join(lines)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def extract_mft_record(
    image_path: str,
    entry: int = -1,
    file_name: str = "",
    max_matches: int = 5,
) -> dict[str, object]:
    """Read $MFT records by entry number or file name, including resident file content.

    Call when a small file (script, .bat, config, dropper) was deleted or
    is missing from a collection: NTFS keeps files under about 700 bytes
    inside their $MFT record, so their full content is often still here.
    Find the entry number with search(query='<name>', source='ez.mft') or
    pass ``file_name`` (case-insensitive exact name). Returns names,
    parent entries, $STANDARD_INFORMATION times and every $DATA stream
    (content decoded as text when it is text, hex otherwise; Zone.Identifier
    and other alternate streams included). Resident content is indexed as
    ``mftrecord.<entry>``; decode obfuscated scripts with decode_payload.

    Args:
        image_path: Disk image, or triage collection directory.
        entry: $MFT entry number (e.g. 315567). Use -1 with file_name.
        file_name: File name to look up when the entry number is unknown.
        max_matches: Maximum records returned for a file_name lookup.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "image_path": image_path,
        "entry": entry,
        "file_name": file_name,
        "max_matches": max_matches,
    }
    if entry < 0 and not file_name:
        return error_response(
            tc_id, "extract_mft_record", params, "Pass an entry number or a file_name"
        )

    with tempfile.TemporaryDirectory(prefix="mulder_mft_record_") as tmpdir:
        mft_path, reason = _locate_mft(image_path, tmpdir)
        if mft_path is None:
            if reason is not None:
                return error_response(
                    tc_id,
                    "extract_mft_record",
                    params,
                    f"The $MFT could not be read out of the image: {reason}",
                    (time.monotonic() - t0) * 1000,
                    error_type="extraction_failed",
                )
            return error_response(
                tc_id,
                "extract_mft_record",
                params,
                "No $MFT found (not collected, or not an NTFS volume)",
                (time.monotonic() - t0) * 1000,
                error_type="artifact_missing",
            )
        try:
            with (
                mft_path.open("rb") as fh,
                mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm,
            ):
                record_size = _record_size(mm)
                total = len(mm) // record_size
                if entry >= 0:
                    if entry >= total:
                        return error_response(
                            tc_id,
                            "extract_mft_record",
                            params,
                            f"Entry {entry} is beyond the end of the $MFT ({total} records)",
                        )
                    entries = [entry]
                else:
                    entries = _find_by_name(mm, record_size, file_name, max(1, max_matches))
                records = [
                    parse_mft_record(bytes(mm[e * record_size : (e + 1) * record_size]), e)
                    for e in entries
                ]
        except (MftFormatError, ValueError, OSError) as exc:
            return error_response(
                tc_id,
                "extract_mft_record",
                params,
                f"Cannot read the $MFT record: {exc}",
                (time.monotonic() - t0) * 1000,
            )

    if not records:
        return error_response(
            tc_id,
            "extract_mft_record",
            params,
            f"No $MFT record named {file_name!r} (the name may have been overwritten; "
            "search ez.mft and ez.usnjrnl for the entry number)",
            (time.monotonic() - t0) * 1000,
            error_type="not_found",
        )

    described = [_describe(r) for r in records]
    for rec, (summary, text) in zip(records, described, strict=True):
        if any(st["resident"] and st["content"] for st in rec["streams"]):
            extract_and_index(text, f"mftrecord.{rec['entry']}", image_path, "mft-record")
            summary["indexed_source"] = f"mftrecord.{rec['entry']}"
    # Records are small and the point is to read them: return them in full
    # rather than as the truncated preview tool_response gives indexed sources.
    return tool_response(
        tc_id,
        "extract_mft_record",
        params,
        {"records": [d for d, _ in described], "record_count": len(described)},
        None,
        (time.monotonic() - t0) * 1000,
    )
