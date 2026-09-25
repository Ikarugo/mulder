"""YARA threat-hunting MCP tools.

All three tools are query-time only; they shell out to the ``yara`` CLI
or Volatility 3's ``vadyarascan`` plugin on demand.  YARA is read-only by
design: it scans files and memory but never modifies evidence.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from mulder.assets.paths import asset_path, register_cache_clear
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    ToolRun,
    adaptive_timeout,
    hash_output,
    make_tool_call_id,
    run_tool,
)
from mulder.server.tool_access import Role, tool_access

logger = logging.getLogger(__name__)

_SIGNATURE_BASE_DIRNAME = "signature-base"

_rules_updated = False
_rules_lock = threading.Lock()


def _signature_base_dir() -> Path | None:
    """The Neo23x0/signature-base clone, or None if it is not installed."""
    return asset_path(_SIGNATURE_BASE_DIRNAME)


def _reset_rules_updated() -> None:
    """Re-arm the one-shot rule update after the asset root moves.

    A ``mulder setup`` run that *creates* signature-base must be allowed to
    pull, even if a previous lookup in the same process already gave up.
    """
    global _rules_updated  # noqa: PLW0603
    with _rules_lock:
        _rules_updated = False


register_cache_clear(_reset_rules_updated)

_SRC_FILE_SCAN = "yara.file_scan"
_SRC_MEMORY_SCAN = "yara.memory_scan"
_SRC_VOL_SCAN = "yara.volatility_scan"

_ERR_NO_RULES = (
    "No YARA rules available (built-in rules missing and none provided). "
    "Run 'mulder setup --minimal' to install the signature-base rule set."
)

_YARA_MATCH_RE = re.compile(r"^(\S+)\s+(.+)$")
_YARA_STRING_RE = re.compile(r"^(0x[0-9a-fA-F]+):(\S+):\s*(.*)$")


def _update_community_rules() -> None:
    """Pull latest YARA rules from signature-base (best-effort, once per session)."""
    global _rules_updated  # noqa: PLW0603
    with _rules_lock:
        if _rules_updated:
            return
        _rules_updated = True
    # Resolve once: four separate lookups could disagree if a concurrent
    # ``mulder setup`` publishes the clone mid-function.
    base = _signature_base_dir()
    if base is None or not (base / ".git").is_dir():
        return
    if not (os.access(base, os.W_OK) and os.access(base / ".git", os.W_OK)):
        # A pull has to write objects, refs and the worktree, and git also
        # refuses to touch a clone owned by another user. The container image
        # ships a root-owned, SHA-pinned clone under /opt and runs the server
        # as `mulder`, so there the pinned rules are the rules by design.
        logger.info(
            "YARA rules: %s is not writable by this user; using the installed checkout as-is",
            base,
        )
        return
    try:
        proc = subprocess.run(
            ["git", "-C", str(base), "pull", "--ff-only", "-q"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Could not update %s (no network?), using cached rules", base.name)
        return
    if proc.returncode == 0:
        logger.info("Updated YARA rules: %s", base.name)
    else:
        # Notably git's "detected dubious ownership" refusal, which is what a
        # root-owned clone plus a non-root server produces -- previously this
        # logged success and the rules silently never updated again.
        logger.warning(
            "Could not update %s (git exit %d): %s",
            base,
            proc.returncode,
            (proc.stderr or "").strip()[:200],
        )


def _collect_signature_base() -> list[str]:
    """Return .yar paths from Neo23x0/signature-base."""
    base = _signature_base_dir()
    if base is None or not base.is_dir():
        return []
    yara_dir = base / "yara"
    if yara_dir.is_dir():
        return sorted(str(p) for p in yara_dir.rglob("*.yar"))
    return sorted(str(p) for p in base.rglob("*.yar"))


_VALID_RULESETS = ("builtin", "standard", "full")


def _collect_rules_for_ruleset(ruleset: str) -> list[str]:
    """Collect rule file paths for the requested ruleset level.

    All levels now resolve to Neo23x0/signature-base (~4,000 rules).
    The ``ruleset`` parameter is preserved for API compatibility.
    """
    return _collect_signature_base()


_valid_rules_cache: dict[int, tuple[list[str], list[dict[str, str]]]] = {}
_valid_rules_lock = threading.Lock()

#: How many rule files that failed to compile are named in a response.
_MAX_REPORTED_RULE_FAILURES = 20
#: How many per-file scan errors are listed in a response.
_MAX_REPORTED_SCAN_ERRORS = 10


def _first_error_line(run: ToolRun) -> str:
    """The first line yara printed about why a rule file did not compile."""
    if run.timed_out or run.launch_error is not None:
        return run.describe()
    for line in (run.stderr + "\n" + run.stdout).splitlines():
        if line.strip() and not line.lstrip().lower().startswith("warning"):
            return line.strip()[:300]
    return f"yara exited {run.returncode}"


#: External variables that LOKI/THOR-style rules (signature-base) reference.
#: yara refuses to compile a rule file that uses an undefined external, so
#: without these every such file was dropped from every scan. They are set
#: to empty strings: rules that key on the file name then simply do not match
#: on that condition.
_YARA_EXTERNALS: tuple[str, ...] = tuple(
    arg
    for name in ("filename", "filepath", "extension", "filetype", "owner")
    for arg in ("-d", f"{name}=")
)


def _compile_error(paths: list[str], timeout: int, externals: bool = True) -> str | None:
    """None if *paths* compile together, else yara's first error line.

    *externals* defines :data:`_YARA_EXTERNALS`, as the yara CLI scans do;
    Volatility's yara-python scans do not, so their rules are checked without.
    """
    ext = _YARA_EXTERNALS if externals else ()
    if len(paths) == 1:
        run = run_tool(["yara", *ext, paths[0], "/dev/null"], timeout=timeout)
        return None if run.ok else _first_error_line(run)
    fd, idx_path = tempfile.mkstemp(suffix=".yar", prefix="mulder_yara_combined_")
    try:
        with os.fdopen(fd, "w") as fh:
            for rp in paths:
                fh.write(f'include "{rp}"\n')
        run = run_tool(["yara", *ext, idx_path, "/dev/null"], timeout=timeout)
        return None if run.ok else _first_error_line(run)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(idx_path)


def _validate_rules(
    rule_paths: list[str], externals: bool = True
) -> tuple[list[str], list[dict[str, str]]]:
    """Split rule files into those that compile together and those that do not.

    Caches results so repeated scans don't re-validate.  Attempts batch
    validation via a single index file first; falls back to individual
    compilation if the batch fails.  After individual validation, runs a
    final combined pass to catch cross-file conflicts (e.g. duplicate
    rule identifiers across different files).

    Returns:
        (valid paths, failures) where each failure is ``{"file", "error"}``
        with yara's first error line. Failures used to be logged only: a
        scan with half the rules silently excluded read as a full scan.
    """
    cache_key = hash((externals, *sorted(rule_paths)))
    with _valid_rules_lock:
        if cache_key in _valid_rules_cache:
            return _valid_rules_cache[cache_key]

    if not shutil.which("yara"):
        return rule_paths, []

    if _compile_error(rule_paths, 120, externals) is None:
        logger.info(
            "YARA rule validation: %d/%d files valid (batch)", len(rule_paths), len(rule_paths)
        )
        with _valid_rules_lock:
            _valid_rules_cache[cache_key] = (rule_paths, [])
        return rule_paths, []

    valid: list[str] = []
    failures: list[dict[str, str]] = []
    for rp in rule_paths:
        error = _compile_error([rp], 10, externals)
        if error is None:
            valid.append(rp)
        else:
            failures.append({"file": rp, "error": error})

    logger.info(
        "YARA rule validation: %d/%d files valid (individual)", len(valid), len(rule_paths)
    )

    valid = _resolve_cross_file_conflicts(valid, failures, externals)

    with _valid_rules_lock:
        _valid_rules_cache[cache_key] = (valid, failures)
    return valid, failures


def _validate_rule_files(rule_paths: list[str]) -> list[str]:
    """Return only rule files that compile without errors when combined."""
    return _validate_rules(rule_paths)[0]


def _resolve_cross_file_conflicts(
    valid_paths: list[str], failures: list[dict[str, str]] | None = None, externals: bool = True
) -> list[str]:
    """Remove files that cause cross-file compilation errors.

    Individual rule files may each compile fine on their own but conflict
    when combined (e.g. duplicate rule identifiers like ``WindowsPE``
    defined in multiple files).  This function does a combined validation
    pass and, on failure, uses incremental compilation to identify and
    exclude the conflicting files.

    Args:
        valid_paths: Rule file paths that each compile individually.
        failures: When given, each excluded file is recorded here with the
            compiler's error.

    Returns:
        Subset of *valid_paths* that compile together without conflicts.
    """
    if len(valid_paths) <= 1:
        return valid_paths

    if _compile_error(valid_paths, 120, externals) is None:
        return valid_paths

    logger.info(
        "Cross-file conflict detected among %d individually valid rule files; "
        "running incremental compilation to identify conflicting files",
        len(valid_paths),
    )

    kept: list[str] = []
    for rp in valid_paths:
        error = _compile_error([*kept, rp], 120, externals) if kept else None
        if error is None:
            kept.append(rp)
        else:
            logger.debug("Excluding conflicting rule file: %s", rp)
            if failures is not None:
                failures.append({"file": rp, "error": f"conflicts with other rule files: {error}"})

    logger.info(
        "Cross-file conflict resolution: %d/%d files retained",
        len(kept),
        len(valid_paths),
    )
    return kept


def _try_combined_compile(paths: list[str]) -> bool:
    """Test whether a set of rule files compile together without errors.

    Args:
        paths: Rule file paths to combine into one include file.

    Returns:
        True if YARA compiles the combined file successfully.
    """
    return _compile_error(paths, 120) is None


def _build_index_file(
    rule_paths: list[str], failures: list[dict[str, str]] | None = None, externals: bool = True
) -> tuple[str, bool]:
    """Create a temp .yar file with ``include`` directives for valid paths.

    Pre-validates rule files to skip ones with compilation errors; those are
    added to *failures* when given.
    """
    if not rule_paths:
        return "", False

    valid_paths, failed = _validate_rules(rule_paths, externals)
    if failures is not None:
        failures.extend(failed)
    if not valid_paths:
        return "", False
    if len(valid_paths) == 1:
        return valid_paths[0], False

    fd, idx_path = tempfile.mkstemp(suffix=".yar", prefix="mulder_yara_idx_")
    with os.fdopen(fd, "w") as fh:
        for rp in valid_paths:
            fh.write(f'include "{rp}"\n')
    return idx_path, True


def _build_rules_args(
    rules: str | None,
    ruleset: str = "builtin",
    failures: list[dict[str, str]] | None = None,
    externals: bool = True,
) -> tuple[list[str], bool]:
    """Build the CLI args list for yara rules and return cleanup flag.

    Rule files that do not compile are left out and, when *failures* is
    given, recorded there.
    """
    _update_community_rules()

    if rules is not None:
        stripped = rules.strip()
        if stripped.endswith((".yar", ".yara")) and os.path.isfile(stripped):
            return [stripped], False
        if os.path.isdir(stripped):
            dir_rules = sorted(str(p) for p in Path(stripped).rglob("*.yar"))
            if not dir_rules:
                return [], False
            idx, cleanup = _build_index_file(dir_rules, failures, externals)
            return ([idx], cleanup) if idx else ([], False)
        if re.search(r"^\s*include\s+", stripped, re.MULTILINE | re.IGNORECASE):
            return [], False
        fd, tmp_path = tempfile.mkstemp(suffix=".yar", prefix="mulder_yara_")
        with os.fdopen(fd, "w") as fh:
            fh.write(stripped)
        return [tmp_path], True

    all_rules = _collect_rules_for_ruleset(ruleset)
    if not all_rules:
        return [], False
    idx, cleanup = _build_index_file(all_rules, failures, externals)
    return ([idx], cleanup) if idx else ([], False)


_MEMORY_DUMP_EXTS = frozenset({".raw", ".mem", ".vmem", ".dmp", ".lime", ".001"})


def _find_memory_image() -> str:
    """Look up the memory dump path from DB sources or the extracted directory.

    Checks Volatility sources first (fastest path). If none are indexed
    yet (e.g. volatility is still running), searches the case's
    ``extracted/`` directory for common memory dump file extensions.
    """
    from mulder.server.app import get_cfg

    ctx = get_ctx()
    sources = ctx.db.get_sources()
    for s in sources:
        if s.source_name.startswith("volatility."):
            if not Path(s.source_path).exists():
                raise RuntimeError(
                    f"Memory dump file not found: {s.source_path}. "
                    "Has the evidence been moved or unmounted?"
                )
            return s.source_path

    cfg = get_cfg()

    # Search the evidence root (memory dumps may be alongside disk images)
    meta = ctx.db.get_case_metadata()
    evidence_root = Path(meta.evidence_root) if meta.evidence_root else None
    if evidence_root and evidence_root.is_dir():
        for mem_file in evidence_root.rglob("*"):
            if (
                mem_file.is_file()
                and mem_file.suffix.lower() in _MEMORY_DUMP_EXTS
                and ("memory" in mem_file.name.lower() or "mem" in mem_file.parent.name.lower())
            ):
                logger.info("Found memory dump in evidence root: %s", mem_file)
                return str(mem_file)

    # Fallback: search extracted directory
    extracted_dir = cfg.db_dir / "extracted"
    if extracted_dir.is_dir():
        for mem_file in extracted_dir.rglob("*"):
            if mem_file.is_file() and mem_file.suffix.lower() in _MEMORY_DUMP_EXTS:
                logger.info(
                    "No Volatility sources indexed yet; found memory dump via filesystem scan: %s",
                    mem_file,
                )
                return str(mem_file)

    raise RuntimeError(
        "No memory sources found in this case. Run run_volatility_batch first, "
        "or ensure a memory dump exists in the evidence directory."
    )


def _parse_yara_output(stdout: str) -> list[dict[str, object]]:
    """Parse ``yara -s`` output into structured match dicts."""
    results: list[dict[str, object]] = []
    current: dict[str, object] | None = None

    for line in stdout.splitlines():
        line = line.rstrip()
        if not line:
            continue

        string_m = _YARA_STRING_RE.match(line)
        if string_m and current is not None:
            matched_strings = current["matched_strings"]
            assert isinstance(matched_strings, list)
            matched_strings.append(
                {
                    "offset": string_m.group(1),
                    "identifier": string_m.group(2),
                    "data": string_m.group(3),
                }
            )
            continue

        match_m = _YARA_MATCH_RE.match(line)
        if match_m:
            current = {
                "rule": match_m.group(1),
                "file": match_m.group(2),
                "matched_strings": [],
            }
            results.append(current)

    return results


_VOL_BANNER_PREFIX = "Volatility 3 Framework"


def _parse_vadyarascan_output(stdout: str) -> tuple[list[dict[str, object]], bool]:
    """Parse ``windows.vadyarascan`` text output into match dicts.

    Volatility prints its banner and a column header on stdout before any
    row. Read with the ``yara`` CLI parser, those two lines were counted as
    rule hits ("Volatility" matching "3 Framework ..."), and a failed run
    was taken for a successful one because stdout was not empty.

    Returns:
        (matches, header_seen). ``header_seen`` is False when the plugin
        never printed its table, i.e. it did not run.
    """
    results: list[dict[str, object]] = []
    columns: list[str] | None = None
    for line in stdout.splitlines():
        if not line.strip() or line.startswith(_VOL_BANNER_PREFIX):
            continue
        cells = [c.strip() for c in line.split("\t")]
        if columns is None:
            if "Rule" in cells:
                columns = cells
            continue
        row = dict(zip(columns, cells, strict=False))
        rule = row.get("Rule", "")
        if not rule:
            continue
        pid = row.get("PID", "")
        results.append(
            {
                "rule": rule,
                "file": f"pid {pid}" if pid else "",
                "pid": pid,
                "matched_strings": [
                    {
                        "offset": row.get("Offset", ""),
                        "identifier": row.get("Component", ""),
                        "data": row.get("Value", ""),
                    }
                ],
            }
        )
    return results, columns is not None


def _strip_vol_banner(stdout: str) -> str:
    """Volatility's stdout without its banner line, for indexing."""
    return "\n".join(
        line for line in stdout.splitlines() if not line.startswith(_VOL_BANNER_PREFIX)
    ).strip()


def _scan_errors(stderr: str) -> list[dict[str, str]]:
    """Per-file errors yara printed on stderr (``error scanning <file>: <why>``).

    Compile warnings (``warning: ...``) are not scan errors and are skipped.
    """
    errors: list[dict[str, str]] = []
    for raw in stderr.splitlines():
        line = raw.strip()
        if not line.lower().startswith("error"):
            continue
        match = re.match(r"error scanning (.+?): (.+)$", line, re.IGNORECASE)
        if match:
            errors.append({"file": match.group(1), "error": match.group(2)})
        else:
            errors.append({"file": "", "error": line[:300]})
    return errors


def _no_rules_message(failures: list[dict[str, str]]) -> str:
    """The error for a scan with no usable rule, naming why rules were dropped."""
    if not failures:
        return _ERR_NO_RULES
    listed = "; ".join(
        f"{Path(f['file']).name}: {f['error']}" for f in failures[:_MAX_REPORTED_RULE_FAILURES]
    )
    return (
        f"No YARA rule compiled: {len(failures)} rule file(s) failed to compile, so nothing "
        f"was scanned. {listed}"
    )


def _cleanup(path: str) -> None:
    """Remove a temporary file, ignoring errors."""
    with contextlib.suppress(OSError):
        os.unlink(path)


def _yara_error(
    ctx: Any,
    tc_id: str,
    tool_name: str,
    params: dict[str, object],
    source: str,
    error_msg: str,
    t0: float,
    error_type: str = "tool_failed",
) -> dict[str, object]:
    """Build a standardized YARA error response with audit logging."""
    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=tool_name,
        params=params,
        output_hash=hash_output({"error": error_msg}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "error",
        "error_type": error_type,
        "error_message": error_msg,
        "results": [],
        "source": source,
        "result_count": 0,
    }


_NOISE_FAMILY_THRESHOLD = 4


def _compute_hit_metadata(matches: list[dict[str, object]]) -> dict[str, object]:
    """Compute diversity metadata for a set of YARA matches.

    Extracts the rule family prefix (first underscore-delimited segment)
    from each match and returns summary statistics.  When 4+ distinct
    families are detected, includes a noise warning advising the analyst
    to corroborate with behavioral evidence.
    """
    family_names: set[str] = set()
    for match in matches:
        rule_name = str(match.get("rule", ""))
        prefix = rule_name.split("_")[0] if "_" in rule_name else rule_name
        if prefix:
            family_names.add(prefix)

    metadata: dict[str, object] = {
        "total_hits": len(matches),
        "unique_families": len(family_names),
        "family_names": sorted(family_names)[:20],
    }

    if len(family_names) >= _NOISE_FAMILY_THRESHOLD:
        metadata["noise_warning"] = (
            f"Detected {len(family_names)} distinct rule families in a single scan. "
            "This pattern often indicates public ruleset over-matching rather than "
            "actual multi-actor presence. Corroborate with behavioral evidence before "
            "attributing to specific threat actors."
        )

    return metadata


def _run_yara_scan(
    *,
    cmd: list[str],
    timeout: int,
    source_name: str,
    tool_name: str,
    rules_args: list[str],
    cleanup: bool,
    ctx: Any,
    tc_id: str,
    t0: float,
    audit_params: dict[str, object],
    target_path: str,
    rule_failures: list[dict[str, str]] | None = None,
    volatility: bool = False,
) -> dict[str, object]:
    """Execute a YARA scan command with standardized error handling.

    Handles timeouts, launch failures, non-zero exit codes, result parsing,
    indexing, and audit logging. Returns the final tool response dict.

    Args:
        cmd: Full command list to execute.
        timeout: Subprocess timeout in seconds.
        source_name: Source label for indexing (e.g. "yara.files").
        tool_name: MCP tool name for audit logging.
        rules_args: List of rules file paths (first is cleaned up if needed).
        cleanup: Whether to remove the rules file after execution.
        ctx: Application context for audit logging.
        tc_id: Tool call identifier.
        t0: Start time for elapsed calculation.
        audit_params: Parameters dict for audit logging.
        target_path: Evidence file path for indexing.
        rule_failures: Rule files left out because they did not compile.
        volatility: *cmd* is Volatility's vadyarascan, not the yara CLI.

    Returns:
        Standardized tool response dict (success, partial or error).
    """
    run = run_tool(cmd, timeout=timeout)

    if cleanup:
        _cleanup(rules_args[0])

    if volatility:
        results, header_seen = _parse_vadyarascan_output(run.stdout)
        # The banner alone is not output: without the table the plugin did
        # not run, whatever the exit code says.
        failed = not header_seen
        index_text = _strip_vol_banner(run.stdout) if header_seen else ""
    else:
        results = _parse_yara_output(run.stdout)
        failed = run.failed
        index_text = run.stdout if run.stdout.strip() else ""

    if failed:
        message = run.describe()
        if volatility and run.ok:
            message = f"{message}. vadyarascan printed no result table, so the scan did not run."
        return _yara_error(
            ctx,
            tc_id,
            tool_name,
            audit_params,
            source_name,
            message,
            t0,
            error_type=run.error_type,
        )

    index_summary: dict[str, object] = {}
    if index_text:
        index_summary = extract_and_index(index_text, source_name, target_path, "yara")

    hit_metadata = _compute_hit_metadata(results)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=tool_name,
        params=audit_params,
        output_hash=hash_output({"result_count": len(results)}),
        duration_ms=elapsed,
    )
    response: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "source": source_name,
        "source_name": source_name,
        "result_count": len(results),
        "windows_indexed": index_summary.get("windows_indexed", 0),
        "hit_metadata": hit_metadata,
        "hint": (
            f"Use search(query, source='{source_name}') or "
            f"get_raw_output('{source_name}') to retrieve match details."
        ),
        "caveat": (
            "Rule names do not confirm malware. Inspect the matched "
            "strings/bytes to determine if they are malware-specific or "
            "generic content found in legitimate software."
        ),
    }

    warnings: list[str] = []
    if rule_failures:
        response["rules_failed_to_compile"] = [
            {"file": Path(f["file"]).name, "error": f["error"]}
            for f in rule_failures[:_MAX_REPORTED_RULE_FAILURES]
        ]
        response["rules_failed_count"] = len(rule_failures)
        warnings.append(
            f"{len(rule_failures)} rule file(s) failed to compile and were not used: "
            "no match from them is possible (see rules_failed_to_compile)."
        )
    scan_errors = [] if volatility else _scan_errors(run.stderr)
    if scan_errors:
        response["files_failed"] = len(scan_errors)
        response["scan_errors"] = scan_errors[:_MAX_REPORTED_SCAN_ERRORS]
        warnings.append(
            f"yara could not scan {len(scan_errors)} file(s) (see scan_errors): they were "
            "not checked."
        )
    if not run.ok:
        warnings.append(
            f"{run.describe()}\nThe matches printed before that were indexed; the scan may "
            "be incomplete."
        )
    if warnings:
        response["status"] = "partial"
        response["tool_warning"] = "\n".join(warnings)
    return response


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def yara_scan_files(
    target_path: str,
    rules: str | None = None,
    ruleset: str = "builtin",
) -> dict[str, object]:
    """Scan a mounted filesystem or extracted directory for malware using YARA rules.

    Call after extracting files from a disk image or archive. Uses the
    Neo23x0/signature-base ruleset (~4,000 rules) by default, or provide
    custom rules via the rules parameter. Requires ``yara`` on PATH.

    Indexes matches as ``yara.files``; use search(source='yara.files') to
    review match details. Rule names alone do not confirm malware; inspect
    matched strings to distinguish from generic content.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    audit_params: dict[str, object] = {
        "target_path": target_path,
        "rules": rules is not None,
        "ruleset": ruleset,
    }

    if ruleset not in _VALID_RULESETS:
        ruleset = "builtin"

    if not shutil.which("yara"):
        return _yara_error(
            ctx,
            tc_id,
            "yara_scan_files",
            audit_params,
            _SRC_FILE_SCAN,
            "yara not found on PATH",
            t0,
        )

    rule_failures: list[dict[str, str]] = []
    rules_args, cleanup = _build_rules_args(rules, ruleset=ruleset, failures=rule_failures)
    if not rules_args:
        return _yara_error(
            ctx,
            tc_id,
            "yara_scan_files",
            audit_params,
            _SRC_FILE_SCAN,
            _no_rules_message(rule_failures),
            t0,
            error_type="no_rules",
        )

    cmd = ["yara", *_YARA_EXTERNALS, "-r", "-s", *rules_args, target_path]
    return _run_yara_scan(
        cmd=cmd,
        timeout=adaptive_timeout(target_path, per_gib=300),
        source_name="yara.files",
        tool_name="yara_scan_files",
        rules_args=rules_args,
        cleanup=cleanup,
        ctx=ctx,
        tc_id=tc_id,
        t0=t0,
        audit_params=audit_params,
        target_path=target_path,
        rule_failures=rule_failures,
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def yara_scan_memory(
    rules: str | None = None,
    ruleset: str = "builtin",
) -> dict[str, object]:
    """Scan the memory dump with YARA rules for malware signatures.

    Call after run_volatility_batch has indexed memory sources (the memory
    path is resolved automatically from Volatility source metadata). Uses
    signature-base (~4,000 rules) by default. Requires ``yara`` on PATH.

    Indexes matches as ``yara.memory``; use search(source='yara.memory')
    to review.

    Interpreting results:
    - A single rule matching on generic strings (common paths, format
      specifiers, file extensions) is likely a false positive. Check
      the matched_strings content, not just the rule name.
    - Multiple DISTINCT rule families matching in the same process
      or memory region compounds significance. Evaluate matches in
      context: which process contained the match matters as much as
      what matched.
    - Rule names suggest but do not prove attribution. The underlying
      matched content is the evidence, not the label.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    audit_params: dict[str, object] = {"rules": rules is not None, "ruleset": ruleset}

    if ruleset not in _VALID_RULESETS:
        ruleset = "builtin"

    if not shutil.which("yara"):
        return _yara_error(
            ctx,
            tc_id,
            "yara_scan_memory",
            audit_params,
            _SRC_MEMORY_SCAN,
            "yara not found on PATH",
            t0,
        )

    try:
        image_path = _find_memory_image()
    except RuntimeError as exc:
        return _yara_error(
            ctx,
            tc_id,
            "yara_scan_memory",
            audit_params,
            _SRC_MEMORY_SCAN,
            str(exc),
            t0,
        )

    rule_failures: list[dict[str, str]] = []
    rules_args, cleanup = _build_rules_args(rules, ruleset=ruleset, failures=rule_failures)
    if not rules_args:
        return _yara_error(
            ctx,
            tc_id,
            "yara_scan_memory",
            audit_params,
            _SRC_MEMORY_SCAN,
            _no_rules_message(rule_failures),
            t0,
            error_type="no_rules",
        )

    cmd = ["yara", *_YARA_EXTERNALS, "-s", *rules_args, image_path]
    return _run_yara_scan(
        cmd=cmd,
        timeout=adaptive_timeout(image_path, per_gib=300),
        source_name="yara.memory",
        tool_name="yara_scan_memory",
        rules_args=rules_args,
        cleanup=cleanup,
        ctx=ctx,
        tc_id=tc_id,
        t0=t0,
        audit_params=audit_params,
        target_path=image_path,
        rule_failures=rule_failures,
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def yara_scan_with_volatility(
    pid: int | None = None, rules: str | None = None
) -> dict[str, object]:
    """Scan process virtual address descriptors with YARA via Volatility 3's vadyarascan.

    Call after run_volatility_batch when you need per-process YARA
    scanning (more precise than raw memory scan). Optionally target a
    single PID. Requires Volatility 3 on PATH.

    Indexes matches as ``yara.volatility``; results include PID and
    virtual address for each match, enabling targeted process analysis.
    """
    from mulder.extractors.volatility import _find_vol_binary

    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    audit_params: dict[str, object] = {"pid": pid, "rules": rules is not None}

    try:
        vol_cmd = _find_vol_binary()
    except RuntimeError as exc:
        return _yara_error(
            ctx,
            tc_id,
            "yara_scan_with_volatility",
            audit_params,
            _SRC_VOL_SCAN,
            str(exc),
            t0,
        )

    try:
        image_path = _find_memory_image()
    except RuntimeError as exc:
        return _yara_error(
            ctx,
            tc_id,
            "yara_scan_with_volatility",
            audit_params,
            _SRC_VOL_SCAN,
            str(exc),
            t0,
        )

    rule_failures: list[dict[str, str]] = []
    rules_args, cleanup = _build_rules_args(rules, failures=rule_failures, externals=False)
    if not rules_args:
        return _yara_error(
            ctx,
            tc_id,
            "yara_scan_with_volatility",
            audit_params,
            _SRC_VOL_SCAN,
            _no_rules_message(rule_failures),
            t0,
            error_type="no_rules",
        )

    rules_path = rules_args[0]
    cmd = [
        *vol_cmd,
        "-f",
        image_path,
        "windows.vadyarascan.VadYaraScan",
        "--yara-file",
        rules_path,
    ]
    if pid is not None:
        cmd.extend(["--pid", str(pid)])

    return _run_yara_scan(
        cmd=cmd,
        timeout=adaptive_timeout(image_path, per_gib=300),
        source_name="yara.volatility",
        tool_name="yara_scan_with_volatility",
        rules_args=rules_args,
        cleanup=cleanup,
        ctx=ctx,
        tc_id=tc_id,
        t0=t0,
        audit_params=audit_params,
        target_path=image_path,
        rule_failures=rule_failures,
        volatility=True,
    )
