"""Shared masquerade/typo-squat detection logic and CSV parsers for the three
execution-artifact agents (Prefetch, Amcache, Shimcache) -- kept in one place
so a system binary's canonical path only has to be defined once and all
three sources evaluate it identically, and so the three Eric Zimmerman CSV
readers share one defensive column-resolution strategy.

VERIFICATION NOTE: PECmd/AmcacheParser/AppCompatCacheParser could not be run
against real live artifacts in this sandbox -- C:\\Windows\\Prefetch and
C:\\Windows\\appcompat\\Programs\\Amcache.hve both require administrator
(confirmed: os.listdir() on Prefetch and shutil.copy2() on Amcache.hve both
raise PermissionError(13) for this non-admin account), and Shimcache lives
inside the SYSTEM hive, which needs the same elevated access already
established as unavailable here. Column names below are each tool's
long-stable, widely-documented CSV headers; every reader still resolves
columns defensively (exact name first, then a fuzzy fallback) and reports a
clear diagnostic instead of guessing if a header doesn't match, so an
imperfect assumption fails loud rather than silently parsing garbage.
"""

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.models import ExecutionArtifact

# Canonical directory (lowercase, backslash) each binary is expected to run
# from. SysWOW64 is checked as an automatic alternate for 32-bit-capable
# system paths. Any exact-name match running outside both is flagged.
KNOWN_SYSTEM_BINARIES: Dict[str, List[str]] = {
    "svchost.exe": [r"\windows\system32", r"\windows\syswow64"],
    "lsass.exe": [r"\windows\system32"],
    "csrss.exe": [r"\windows\system32"],
    "winlogon.exe": [r"\windows\system32"],
    "services.exe": [r"\windows\system32"],
    "smss.exe": [r"\windows\system32"],
    "wininit.exe": [r"\windows\system32"],
    "explorer.exe": [r"\windows"],
    "certutil.exe": [r"\windows\system32", r"\windows\syswow64"],
    "rundll32.exe": [r"\windows\system32", r"\windows\syswow64"],
    "regsvr32.exe": [r"\windows\system32", r"\windows\syswow64"],
    "cmd.exe": [r"\windows\system32", r"\windows\syswow64"],
    "powershell.exe": [r"\windows\system32\windowspowershell", r"\windows\syswow64\windowspowershell"],
    "conhost.exe": [r"\windows\system32"],
    "taskhostw.exe": [r"\windows\system32"],
    "wmiprvse.exe": [r"\windows\system32\wbem"],
    "dllhost.exe": [r"\windows\system32"],
    "spoolsv.exe": [r"\windows\system32"],
}


def _levenshtein(a: str, b: str) -> int:
    """Classic edit-distance DP -- no external dependency needed for names
    this short."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def detect_path_masquerade(executable_name: str, full_path: Optional[str]) -> Optional[str]:
    """A file with the EXACT name of a well-known system binary running from
    anywhere other than its canonical directory."""
    if not full_path:
        return None
    name_lower = executable_name.lower()
    expected_dirs = KNOWN_SYSTEM_BINARIES.get(name_lower)
    if not expected_dirs:
        return None
    path_lower = full_path.lower().replace("/", "\\")
    if any(expected in path_lower for expected in expected_dirs):
        return None
    return (
        f"'{executable_name}' matches a well-known Windows system binary but is executing "
        f"from '{full_path}' instead of its expected location ({' or '.join(expected_dirs)})."
    )


def detect_typosquat(executable_name: str) -> Optional[str]:
    """A name that is NOT an exact match to a known system binary, but is
    within 1-2 character edits of one -- classic typosquatting (svch0st.exe,
    lsas.exe, scvhost.exe)."""
    name_lower = executable_name.lower()
    if name_lower in KNOWN_SYSTEM_BINARIES:
        return None  # exact match is handled by detect_path_masquerade, not a typosquat
    for known in KNOWN_SYSTEM_BINARIES:
        if abs(len(name_lower) - len(known)) > 2:
            continue
        distance = _levenshtein(name_lower, known)
        if 1 <= distance <= 2:
            return f"'{executable_name}' is {distance} character edit(s) away from the legitimate system binary '{known}' -- likely typosquatting."
    return None


def _parse_dt(value: Optional[str]) -> Optional[str]:
    """Best-effort parse of whatever timestamp format a given EZ tool CSV
    uses, normalized to an ISO-8601 UTC string. Returns the original string
    untouched if it can't be parsed -- a raw-but-present timestamp is more
    useful to the LLM than a silently dropped one."""
    if not value:
        return None
    value = value.strip()
    if not value or value.lower() in ("-", "n/a", "0"):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return value


def _resolve(header: List[str], exact_candidates: List[str], fuzzy_tokens: Optional[List[str]] = None) -> Optional[str]:
    """Exact case-insensitive match first; fuzzy fallback requires ALL given
    tokens to appear in the header name (e.g. ['run', 'count'] matches both
    'RunCount' and 'Run_Count')."""
    lower_map = {h.lower(): h for h in header}
    for cand in exact_candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    if fuzzy_tokens:
        for h in header:
            hl = h.lower()
            if all(tok in hl for tok in fuzzy_tokens):
                return h
    return None


def _read_csv_rows(csv_path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    with open(csv_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        rows = list(reader)
    return header, rows


# ---------------------------------------------------------------------------
# PECmd (Prefetch)
# ---------------------------------------------------------------------------

def parse_pecmd_csv(csv_path: Path) -> Tuple[List[ExecutionArtifact], Optional[str]]:
    if not csv_path.exists():
        return [], f"Prefetch CSV not found: {csv_path}"
    try:
        header, rows = _read_csv_rows(csv_path)
    except Exception as e:
        return [], f"Failed to read {csv_path.name}: {e}"

    name_col = _resolve(header, ["ExecutableName"], ["executable", "name"])
    run_count_col = _resolve(header, ["RunCount"], ["run", "count"])
    last_run_col = _resolve(header, ["LastRun"], ["last", "run"])
    volume_serial_col = _resolve(header, ["Volume0Serial"], ["volume", "serial"])
    hash_col = _resolve(header, ["Hash"])
    size_col = _resolve(header, ["Size"])
    files_loaded_col = _resolve(header, ["FilesLoaded"], ["files", "loaded"])
    source_file_col = _resolve(header, ["SourceFilename"], ["source", "file"])

    if not name_col:
        return [], f"Could not identify an ExecutableName column in {csv_path.name} (header: {header})"

    artifacts: List[ExecutionArtifact] = []
    for row in rows:
        exe_name = (row.get(name_col) or "").strip()
        if not exe_name:
            continue

        full_path = None
        if files_loaded_col:
            files_loaded_raw = row.get(files_loaded_col) or ""
            # PECmd delimits FilesLoaded with '|'; be defensive about ',' too.
            candidates = [p.strip() for p in files_loaded_raw.split("|") if p.strip()]
            if len(candidates) <= 1:
                candidates = [p.strip() for p in files_loaded_raw.split(",") if p.strip()]
            for cand in candidates:
                if Path(cand.replace("/", "\\")).name.lower() == exe_name.lower():
                    full_path = cand
                    break

        run_count = None
        if run_count_col:
            try:
                run_count = int(row.get(run_count_col) or 0)
            except ValueError:
                run_count = None

        size_bytes = None
        if size_col:
            try:
                size_bytes = int(float(row.get(size_col) or 0))
            except ValueError:
                size_bytes = None

        artifact = ExecutionArtifact(
            source="Prefetch",
            executable_name=exe_name,
            full_path=full_path,
            run_count=run_count,
            last_execution_utc=_parse_dt(row.get(last_run_col)) if last_run_col else None,
            volume_serial=(row.get(volume_serial_col) or None) if volume_serial_col else None,
            sha1=(row.get(hash_col) or None) if hash_col else None,
            size_bytes=size_bytes,
            details={"prefetch_file": row.get(source_file_col)} if source_file_col else {},
        )
        artifacts.append(evaluate_execution_artifact(artifact))

    return artifacts, None


# ---------------------------------------------------------------------------
# AmcacheParser (Amcache.hve)
# ---------------------------------------------------------------------------

def parse_amcacheparser_csv(csv_path: Path) -> Tuple[List[ExecutionArtifact], Optional[str]]:
    if not csv_path.exists():
        return [], f"Amcache CSV not found: {csv_path}"
    try:
        header, rows = _read_csv_rows(csv_path)
    except Exception as e:
        return [], f"Failed to read {csv_path.name}: {e}"

    path_col = _resolve(header, ["FullPath"], ["full", "path"])
    if not path_col:
        # AmcacheParser writes several CSVs per hive (ProgramEntries,
        # ShortCuts, DriverBinaries, ...) -- only file-entry tables carry a
        # FullPath column. Skip the others without treating it as an error.
        return [], None

    name_col = _resolve(header, ["Name"], ["name"])
    sha1_col = _resolve(header, ["SHA1"], ["sha1"])
    size_col = _resolve(header, ["Size"], ["size"])
    is_os_component_col = _resolve(header, ["IsOsComponent"], ["os", "component"])
    last_modified_col = _resolve(header, ["FileKeyLastWriteTimestamp", "LastModifiedTimestamp"], ["last", "modified"])
    created_col = _resolve(header, ["CreatedTimestamp"], ["created"])
    link_date_col = _resolve(header, ["LinkDate"], ["link", "date"])

    artifacts: List[ExecutionArtifact] = []
    for row in rows:
        full_path = (row.get(path_col) or "").strip()
        if not full_path:
            continue
        exe_name = (row.get(name_col) or "").strip() if name_col else Path(full_path.replace("/", "\\")).name

        size_bytes = None
        if size_col:
            try:
                size_bytes = int(float(row.get(size_col) or 0))
            except ValueError:
                size_bytes = None

        is_os_component = str(row.get(is_os_component_col) or "").strip().lower() in ("true", "1", "yes")

        artifact = ExecutionArtifact(
            source="Amcache",
            executable_name=exe_name,
            full_path=full_path,
            last_execution_utc=_parse_dt(row.get(last_modified_col)) if last_modified_col else None,
            first_seen_utc=_parse_dt(row.get(created_col)) if created_col else None,
            sha1=(row.get(sha1_col) or None) if sha1_col else None,
            size_bytes=size_bytes,
            details={
                "is_os_component": is_os_component,
                "compile_link_date": row.get(link_date_col) if link_date_col else None,
            },
        )
        artifacts.append(evaluate_execution_artifact(artifact))

    return artifacts, None


# ---------------------------------------------------------------------------
# AppCompatCacheParser (Shimcache)
# ---------------------------------------------------------------------------

def parse_appcompatcache_csv(csv_path: Path) -> Tuple[List[ExecutionArtifact], Optional[str]]:
    if not csv_path.exists():
        return [], f"Shimcache CSV not found: {csv_path}"
    try:
        header, rows = _read_csv_rows(csv_path)
    except Exception as e:
        return [], f"Failed to read {csv_path.name}: {e}"

    last_modified_col = _resolve(header, ["LastModifiedTimeUTC"], ["last", "modified"])
    executed_col = _resolve(header, ["Executed"], ["executed"])
    control_set_col = _resolve(header, ["ControlSet"], ["control", "set"])
    position_col = _resolve(header, ["CacheEntryPosition"], ["entry", "position"])

    # Registry/metadata/ can also hold registry_persistence_entries.csv
    # (Registry_Hive_Miner) alongside AppCompatCacheParser's own output --
    # require an AppCompatCache-specific column, not just any path-like one,
    # before treating this file as Shimcache data. Skip silently (not an
    # error) if it doesn't look like one, exactly like Amcache's non-file
    # tables are skipped.
    if not (position_col or control_set_col or last_modified_col):
        return [], None

    path_col = _resolve(header, ["Path", "Name"], ["path"])
    if not path_col:
        return [], f"Could not identify a Path/Name column in {csv_path.name} (header: {header})"

    artifacts: List[ExecutionArtifact] = []
    for row in rows:
        full_path = (row.get(path_col) or "").strip()
        if not full_path:
            continue
        exe_name = Path(full_path.replace("/", "\\")).name

        executed_raw = str(row.get(executed_col) or "").strip().lower() if executed_col else ""
        artifact = ExecutionArtifact(
            source="Shimcache",
            executable_name=exe_name,
            full_path=full_path,
            last_execution_utc=_parse_dt(row.get(last_modified_col)) if last_modified_col else None,
            details={
                # NB: Shimcache's "Executed" flag is a well-known unreliable
                # indicator on several Windows versions -- presence in the
                # cache does not guarantee the binary actually ran, and the
                # flag itself is sometimes absent depending on OS build. The
                # LLM prompt is told this explicitly rather than treating it
                # as ground truth.
                "executed_flag": executed_raw or None,
                "control_set": row.get(control_set_col) if control_set_col else None,
                "cache_entry_position": row.get(position_col) if position_col else None,
            },
        )
        artifacts.append(evaluate_execution_artifact(artifact))

    return artifacts, None


def evaluate_execution_artifact(artifact: ExecutionArtifact) -> ExecutionArtifact:
    """Pre-compute the masquerade/typosquat flag in code (a reliable string
    comparison) rather than leaving pattern-matching entirely to the LLM --
    the LLM is then asked to judge severity/context, not to spot the pattern
    from scratch."""
    reason = detect_path_masquerade(artifact.executable_name, artifact.full_path)
    if reason is None:
        reason = detect_typosquat(artifact.executable_name)
    if reason:
        artifact.is_masquerade_suspect = True
        artifact.masquerade_reason = reason
    return artifact
