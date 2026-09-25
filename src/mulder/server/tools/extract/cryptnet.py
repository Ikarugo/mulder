"""CryptnetUrlCache: files Windows fetched through CryptAPI, certutil downloads included.

``certutil -urlcache -split -f <url>`` is a common living-off-the-land
download. CryptAPI caches what it fetches under
``<profile>\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache``: ``Content\\<id>``
holds the bytes and ``MetaData\\<id>`` the URL, the download time, the
server's Last-Modified time, the ETag and the size. Most entries are
certificate revocation lists and OCSP responses; anything else deserves a
look.

MetaData layout (little endian), as documented by
AbdulRhmanAlfaifi/CryptnetURLCacheParser::

    0x0C  uint32   URL size in bytes (UTF-16LE, NUL included)
    0x10  FILETIME last download time
    0x58  FILETIME Last-Modified header
    0x64  uint32   ETag size in bytes (UTF-16LE, NUL included)
    0x70  uint32   file size
    0x74  URL, then ETag
"""

from __future__ import annotations

import hashlib
import re
import struct
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import (
    IcatFailure,
    _cleanup_tsk_extract_dir,
    _tsk_extract_files,
    extraction_failure_fields,
    nothing_extracted_response,
)
from mulder.triage import is_triage_root, iter_tree_files

__all__ = ["parse_cryptnet_metadata", "parse_cryptnet_url_cache"]

SRC_CRYPTNET = "cryptnet.urlcache"

_HEADER = struct.Struct("<12xIQ64xQ4xI8xI")
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_PROFILE_RE = re.compile(r"(?:^|/)(?:users|documents and settings)/([^/]+)/")
_SERVICE_PROFILE_RE = re.compile(r"(?:serviceprofiles/([^/]+)|config/(systemprofile))/")

#: Hosts that serve certificate revocation data: their entries are routine.
_PKI_HOST_RE = re.compile(
    r"^(?:crl\d*|ocsp\d*|cacerts|certs?|pki|ctldl)\.|"
    r"(?:^|\.)(?:windowsupdate\.com|digicert\.com|verisign\.com|symcb\.com|symcd\.com|"
    r"globalsign\.(?:com|net)|sectigo\.com|usertrust\.com|comodoca\.com|letsencrypt\.org|"
    r"lencr\.org|amazontrust\.com|godaddy\.com|entrust\.net|identrust\.com|pki\.goog|"
    r"trust\.microsoft\.com)$",
    re.IGNORECASE,
)
_PKI_PATH_RE = re.compile(r"\.(?:crl|crt|cer|p7c|stl)$|/ocsp|/crl", re.IGNORECASE)


def _filetime(value: int) -> str | None:
    """ISO 8601 UTC for a FILETIME, or None when zero or implausible."""
    if not value:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    if not 1995 <= dt.year <= 2100:
        return None
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_cryptnet_metadata(data: bytes) -> dict[str, object] | None:
    """Decode one MetaData file; None if it is too short to hold a header and URL."""
    if len(data) < _HEADER.size:
        return None
    url_size, downloaded, last_modified, etag_size, file_size = _HEADER.unpack_from(data)
    url_end = _HEADER.size + url_size
    if url_size == 0 or url_end > len(data):
        return None
    url = data[_HEADER.size : url_end].decode("utf-16-le", errors="replace").rstrip("\x00")
    etag = (
        data[url_end : url_end + etag_size]
        .decode("utf-16-le", errors="replace")
        .rstrip("\x00")
        .strip('"')
    )
    return {
        "url": url,
        "last_download_time": _filetime(downloaded),
        "last_modified_header": _filetime(last_modified),
        "etag": etag,
        "file_size": file_size,
    }


def _is_routine_pki(url: str) -> bool:
    host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE).split("/", 1)[0].split(":")[0]
    return bool(_PKI_HOST_RE.search(host)) or bool(_PKI_PATH_RE.search(url.split("?")[0]))


def _profile_of(rel_lower: str) -> str:
    m = _PROFILE_RE.search(rel_lower)
    if m:
        return m.group(1)
    m = _SERVICE_PROFILE_RE.search(rel_lower)
    if m:
        return m.group(1) or m.group(2) or "system"
    return "unknown"


def _cache_files(
    image_path: str, failures: list[IcatFailure] | None = None
) -> tuple[list[tuple[str, Path]], str | None]:
    """``(relative path, readable file)`` for every CryptnetUrlCache file, plus a dir to clean."""
    if is_triage_root(image_path):
        files = [
            (rel, path)
            for rel, path in iter_tree_files(image_path)
            if "/cryptneturlcache/" in "/" + rel.lower()
        ]
        return files, None
    extracted = _tsk_extract_files(image_path, ["CryptnetUrlCache/"], failures=failures)
    cleanup = str(extracted[0][1].parent) if extracted else None
    return extracted, cleanup


def _entries(
    files: list[tuple[str, Path]], unreadable: frozenset[str] = frozenset()
) -> Iterator[dict[str, object]]:
    by_rel = {rel.lower().replace("\\", "/"): path for rel, path in files}
    for rel_lower, path in sorted(by_rel.items()):
        if "/metadata/" not in rel_lower:
            continue
        try:
            meta = parse_cryptnet_metadata(path.read_bytes())
        except OSError:
            continue
        if meta is None:
            continue
        content_rel = rel_lower.replace("/metadata/", "/content/")
        content = by_rel.get(content_rel)
        entry: dict[str, object] = {
            **meta,
            "profile": _profile_of(rel_lower),
            "metadata_file": rel_lower,
            "content_present": content is not None,
        }
        if content is None and content_rel in unreadable:
            # Present in the image but unreadable: not the same as deleted.
            entry["content_unreadable"] = True
        if content is not None:
            try:
                blob = content.read_bytes()
            except OSError:
                blob = b""
            entry["content_size"] = len(blob)
            entry["content_sha256"] = hashlib.sha256(blob).hexdigest()
            entry["content_magic"] = blob[:4].hex()
            entry["content_type"] = (
                "zip"
                if blob.startswith(b"PK\x03\x04")
                else "pe"
                if blob.startswith(b"MZ")
                else "other"
            )
        entry["routine_pki"] = _is_routine_pki(str(meta["url"]))
        yield entry


def _entry_line(e: dict[str, object]) -> str:
    flag = "" if e["routine_pki"] else "[NON-PKI DOWNLOAD] "
    parts = [
        f"{e.get('last_download_time') or 'unknown-time'} {flag}url={e['url']}",
        f"size={e.get('file_size')}",
        f"profile={e['profile']}",
    ]
    if e.get("content_sha256"):
        parts.append(f"content_sha256={e['content_sha256']} type={e.get('content_type')}")
    if e.get("etag"):
        parts.append(f"etag={e['etag']}")
    if e.get("last_modified_header"):
        parts.append(f"last_modified={e['last_modified_header']}")
    parts.append(f"metadata={e['metadata_file']}")
    return " | ".join(parts)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def parse_cryptnet_url_cache(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse the CryptnetUrlCache of every profile: files fetched through CryptAPI.

    Call on Windows disk images and triage collections whenever
    certutil, a LOLBin download, or a missing second-stage tool is
    suspected. ``certutil -urlcache -split -f <url>`` leaves the URL,
    download time, size and the downloaded bytes here even when the tool
    or its output was deleted. Entries not served by a certificate
    authority are flagged ``[NON-PKI DOWNLOAD]`` and returned in
    ``non_pki_downloads``; everything is indexed as ``cryptnet.urlcache``.

    Args:
        image_path: Disk image, or triage collection directory.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path, "force": force}
    if not force:
        existing = sources_already_indexed([SRC_CRYPTNET], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "parse_cryptnet_url_cache",
                params,
                {"status": "skipped", "reason": "Already indexed", "existing_sources": existing},
                SRC_CRYPTNET,
                0.0,
            )

    failures: list[IcatFailure] = []
    files, cleanup = _cache_files(image_path, failures)
    unreadable = frozenset(f.path.lower().replace("\\", "/") for f in failures)
    try:
        entries = list(_entries(files, unreadable))
    finally:
        if cleanup:
            _cleanup_tsk_extract_dir(cleanup)

    if not entries:
        return nothing_extracted_response(
            tc_id,
            "parse_cryptnet_url_cache",
            params,
            t0,
            "No CryptnetUrlCache MetaData files found (not collected, or cache empty)",
            failures,
        )

    entries.sort(key=lambda e: str(e.get("last_download_time") or ""))
    summary = extract_and_index(
        "\n".join(_entry_line(e) for e in entries), SRC_CRYPTNET, image_path, "cryptnet"
    )
    non_pki = [e for e in entries if not e["routine_pki"]]
    summary["entries"] = len(entries)
    summary["non_pki_downloads"] = [
        {
            k: e.get(k)
            for k in (
                "last_download_time",
                "url",
                "file_size",
                "profile",
                "content_sha256",
                "content_type",
            )
        }
        for e in non_pki[:25]
    ]
    if len(non_pki) > 25:
        summary["non_pki_not_listed"] = len(non_pki) - 25
    summary["indexed_as"] = SRC_CRYPTNET
    summary["hint"] = (
        f"All {len(entries)} entries are indexed as '{SRC_CRYPTNET}'; the first 25 non-PKI "
        "downloads are listed here (search the source for the others)."
    )
    if failures:
        summary.update(extraction_failure_fields(failures))
        summary["tool_warning"] = summary["extraction_note"]
    # Returned in full (source=None): the non-PKI list is the finding, and the
    # indexed-source preview would cut it.
    return tool_response(
        tc_id,
        "parse_cryptnet_url_cache",
        params,
        summary,
        None,
        (time.monotonic() - t0) * 1000,
    )
