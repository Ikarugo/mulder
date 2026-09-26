"""Static reading and layer-by-layer decoding of scripts (PS1, JS, VBS, BAT, HTA).

Nothing here runs a script: no PowerShell, Windows Script Host, Node or
browser engine is ever started, not even in a sandbox. Scripts are read as
text, obfuscated blobs are located with regular expressions, and each blob
is decoded by pure-Python transforms (base64, hex, character codes, XOR,
DEFLATE/gzip). Every decoded layer is written to disk as a derived artefact
with its lineage, so a finding can cite the exact layer it relies on.

A decoded layer is attacker-controlled content like the script itself.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mulder.reverse.backend import BackendError
from mulder.server.helpers import detect_text_encoding

__all__ = [
    "Indicator",
    "LAYERS_MANIFEST",
    "MAX_SCRIPT_BYTES",
    "decode_indicator",
    "find_indicators",
    "indicator_text",
    "read_script_text",
    "record_layer",
    "script_language",
]

#: Scripts bigger than this are refused rather than half-read.
MAX_SCRIPT_BYTES = 20 * 1024 * 1024
#: A decoded layer (after decompression) is capped: a small blob can inflate
#: to gigabytes.
MAX_LAYER_BYTES = 20 * 1024 * 1024
MAX_INDICATORS = 500
LAYERS_MANIFEST = "layers.json"
_PREVIEW = 80

_LANG_BY_EXT = {
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".js": "javascript",
    ".jse": "javascript (encoded)",
    ".vbs": "vbscript",
    ".vbe": "vbscript (encoded)",
    ".bat": "batch",
    ".cmd": "batch",
    ".hta": "hta",
    ".wsf": "windows script file",
    ".py": "python",
    ".sh": "shell",
}

# Blob patterns, most specific first. Overlapping matches keep the first.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        # -e, -en, -enc ... -EncodedCommand, and -ec: every prefix PowerShell accepts.
        "powershell_encoded_command",
        re.compile(r"(?i)(?<![\w-])-(?:ec|e(?:n(?:c\w*)?)?)\s+['\"]?([A-Za-z0-9+/]{20,}={0,2})"),
    ),
    ("char_codes", re.compile(r"((?:\d{2,3}\s*[,;]\s*){9,}\d{2,3})")),
    ("hex", re.compile(r"(?<![0-9A-Za-z])((?:[0-9A-Fa-f]{2}){24,})(?![0-9A-Za-z])")),
    ("base64", re.compile(r"([A-Za-z0-9+/]{40,}={0,2})")),
]


def _plausible(kind: str, blob: str) -> bool:
    """Drop long identifiers that the base64 pattern would otherwise catch."""
    if kind != "base64":
        return True
    has_digit_or_sym = any(c.isdigit() or c in "+/=" for c in blob)
    return has_digit_or_sym and any(c.isupper() for c in blob) and any(c.islower() for c in blob)


_ENCODINGS = ("auto", "base64", "utf16le_base64", "hex", "char_codes", "none")


@dataclass
class Indicator:
    """One encoded-looking blob in a script."""

    id: int
    kind: str
    line: int
    column: int
    length: int
    preview: str


def script_language(path: Path, text: str) -> str:
    """Best guess at the scripting language, from the extension then content."""
    lang = _LANG_BY_EXT.get(path.suffix.lower())
    if lang:
        return lang
    head = text[:4096].lower()
    if "<script" in head or "<hta:application" in head:
        return "hta"
    if "$env:" in head or "invoke-" in head or "[system." in head:
        return "powershell"
    if "wscript." in head or "createobject(" in head:
        return "vbscript"
    if "@echo off" in head or "%comspec%" in head:
        return "batch"
    if "function(" in head or "var " in head or "activexobject" in head:
        return "javascript"
    return "unknown"


def read_script_text(path: Path) -> tuple[str, str]:
    """Return ``(text, encoding)`` for a script file, whatever its encoding."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BackendError(f"File not found: {path}", "file_not_found") from exc
    if size > MAX_SCRIPT_BYTES:
        raise BackendError(
            f"{path.name} is {size} bytes; scripts over {MAX_SCRIPT_BYTES} bytes are not read. "
            "It is probably not a script: try triage_binary or reverse_analyze.",
            "invalid_parameter",
        )
    raw = path.read_bytes()
    encoding = detect_text_encoding(raw[:65536])
    if encoding == "binary":
        raise BackendError(
            f"{path.name} looks binary, not a script. Use triage_binary or reverse_analyze.",
            "invalid_parameter",
        )
    codec = {"utf-8": "utf-8-sig"}.get(encoding, encoding)
    text = raw.decode(codec, errors="replace")
    if encoding.startswith("utf-16"):
        text = text.lstrip("﻿")
    return text, encoding


def find_indicators(text: str) -> list[Indicator]:
    """Encoded-looking blobs in *text*, in file order, numbered from 1."""
    taken: list[tuple[int, int]] = []
    found: list[tuple[int, int, str]] = []
    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.span(1)
            if not _plausible(kind, m.group(1)):
                continue
            if any(s < end and start < e for s, e in taken):
                continue
            taken.append((start, end))
            found.append((start, end, kind))
    found.sort()
    line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]
    out: list[Indicator] = []
    import bisect

    for n, (start, end, kind) in enumerate(found[:MAX_INDICATORS], start=1):
        line_idx = bisect.bisect_right(line_starts, start) - 1
        blob = text[start:end]
        out.append(
            Indicator(
                id=n,
                kind=kind,
                line=line_idx + 1,
                column=start - line_starts[line_idx] + 1,
                length=end - start,
                preview=blob[:_PREVIEW] + ("..." if len(blob) > _PREVIEW else ""),
            )
        )
    return out


def indicator_text(text: str, ind: Indicator) -> str:
    """The blob an indicator points at."""
    line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]
    start = line_starts[ind.line - 1] + ind.column - 1
    return text[start : start + ind.length]


def _bounded_inflate(raw: bytes) -> tuple[str, bytes] | None:
    """zlib, raw DEFLATE or gzip, capped at MAX_LAYER_BYTES; None if none fits."""
    if len(raw) < 8:
        return None
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw[:256])
    if printable > 0.9 * min(len(raw), 256):
        return None
    for method, wbits in (("gzip", 31), ("zlib", 15), ("deflate", -15)):
        d = zlib.decompressobj(wbits)
        try:
            plain = d.decompress(raw, MAX_LAYER_BYTES)
        except zlib.error:
            continue
        if plain and (d.eof or d.unconsumed_tail):
            if d.unconsumed_tail:
                raise BackendError(
                    f"The {method} stream inflates past {MAX_LAYER_BYTES} bytes; not decoded.",
                    "invalid_parameter",
                )
            return method, plain
    return None


def _b64(blob: str) -> bytes:
    clean = re.sub(r"\s+", "", blob)
    clean += "=" * (-len(clean) % 4)
    try:
        return base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BackendError(f"Not valid base64: {exc}", "invalid_parameter") from exc


def _looks_utf16le(raw: bytes) -> bool:
    return len(raw) >= 8 and detect_text_encoding(raw[:4096]) == "utf-16-le"


def decode_indicator(
    blob: str, kind: str, encoding: str = "auto", xor_key: str = ""
) -> tuple[bytes, list[str]]:
    """Decode one blob statically; return the bytes and the steps applied."""
    if encoding not in _ENCODINGS:
        raise BackendError(
            f"encoding must be one of {', '.join(_ENCODINGS)}, got {encoding!r}",
            "invalid_parameter",
        )
    if encoding == "auto":
        encoding = {
            "powershell_encoded_command": "utf16le_base64",
            "char_codes": "char_codes",
            "hex": "hex",
        }.get(kind, "base64")
    steps: list[str] = []
    if encoding in ("base64", "utf16le_base64"):
        raw = _b64(blob)
        steps.append("base64")
    elif encoding == "hex":
        try:
            raw = bytes.fromhex(re.sub(r"\s+", "", blob))
        except ValueError as exc:
            raise BackendError(f"Not valid hex: {exc}", "invalid_parameter") from exc
        steps.append("hex")
    elif encoding == "char_codes":
        values = [int(v) for v in re.findall(r"\d+", blob)]
        if any(v > 0x10FFFF for v in values):
            raise BackendError("Character code out of range", "invalid_parameter")
        raw = "".join(chr(v) for v in values).encode("utf-8")
        steps.append("char_codes")
    else:
        raw = blob.encode("utf-8")
    if xor_key:
        try:
            key = bytes.fromhex(xor_key.removeprefix("0x"))
        except ValueError as exc:
            raise BackendError(
                "xor_key must be hex, e.g. 5a or 0x5a13", "invalid_parameter"
            ) from exc
        if not key or len(key) > 256:
            raise BackendError("xor_key must be 1 to 256 bytes", "invalid_parameter")
        raw = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        steps.append(f"xor 0x{key.hex()}")
    inflated = _bounded_inflate(raw)
    if inflated is not None:
        method, raw = inflated
        steps.append(method)
    if encoding == "utf16le_base64" or _looks_utf16le(raw):
        raw = raw.decode("utf-16-le", errors="replace").encode("utf-8")
        steps.append("utf-16le")
    if len(raw) > MAX_LAYER_BYTES:
        raise BackendError(f"Decoded layer exceeds {MAX_LAYER_BYTES} bytes", "invalid_parameter")
    return raw, steps


def _manifest(layer_dir: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads((layer_dir / LAYERS_MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def record_layer(
    layer_dir: Path,
    parent: Path,
    parent_sha256: str,
    indicator: Indicator,
    steps: list[str],
    content: bytes,
) -> dict[str, Any]:
    """Write a decoded layer beside its siblings and append it to layers.json.

    The same decoding of the same blob always yields the same file, so
    decoding twice does not create a second layer.
    """
    layer_dir.mkdir(parents=True, exist_ok=True)
    sha = hashlib.sha256(content).hexdigest()
    entries = _manifest(layer_dir)
    for e in entries:
        if e.get("sha256") == sha and e.get("indicator", {}).get("id") == indicator.id:
            return {**e, "already_recorded": True}
    is_text = detect_text_encoding(content[:65536]) != "binary"
    suffix = ".txt" if is_text else ".bin"
    layer_id = f"L{len(entries) + 1}"
    path = layer_dir / f"{layer_id}_{sha[:12]}{suffix}"
    path.write_bytes(content)
    entry: dict[str, Any] = {
        "layer_id": layer_id,
        "path": str(path),
        "sha256": sha,
        "size": len(content),
        "kind": "text" if is_text else "binary",
        "parent": str(parent),
        "parent_sha256": parent_sha256,
        "indicator": asdict(indicator),
        "steps": steps,
        "decoded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if content[:2] == b"MZ":
        entry["looks_like"] = "PE executable"
    entries.append(entry)
    (layer_dir / LAYERS_MANIFEST).write_text(json.dumps(entries, indent=2), encoding="utf-8")
    return entry
