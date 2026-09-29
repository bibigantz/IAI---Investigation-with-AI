"""
Cross-agent file handoff -- the mechanism that lets any Windows Forensics or
Memory Analysis agent's finding result in an actual file landing in front of
the File / Malware Analysis pipeline within the SAME investigation run.

The problem this solves: most agents only ever *describe* a suspicious file
in their `ForensicAnomaly.filepath` field (e.g. a Services/Drivers/Autoruns
agent reading a registry ImagePath, or a ProgramData_Analyzer reading a
directory listing) -- but the referenced binary was often never actually
copied into the staging folder by collectors/collector.py (e.g. ProgramData
is only listed, not collected; a persistence target buried in a user's
AppData subfolder is never swept, only top-level files are). Without an
explicit handoff, that file is simply invisible to File_Analysis_Father_Agent
no matter how loudly a Windows Forensics agent flagged it.

scan_and_handoff_suspicious_files() is called once by MasterAnalystAgent after
each father agent completes (see agents/orchestrators/master_analyst.py) --
not by individual leaf agents -- so this required touching one file instead
of every leaf agent: it recursively walks that father's entire (arbitrarily
nested) compiled report for every `anomalies_found[].filepath` at any depth,
and for every one that is a real, existing, not-yet-staged Windows path to a
file type File Analysis's Static Triage module actually knows how to parse,
copies it into ProgramDataList/raw/ (the same intake folder /api/upload/
extract and the memory module's malware handoff already use) and records a
HandoffRecord for the final executive report's cross-agent traceability.
"""
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

HANDOFF_LOG_FILENAME = "handoffs.json"
HANDOFF_INTAKE_CATEGORY = "ProgramDataList"

# Matches an absolute Windows path (C:\..., \\server\share\...) -- deliberately
# excludes the non-filesystem identifier styles other agents already use as
# their own anomalies_found join-key: memory analysis's "PID 1337 @ 0x10000",
# registry key strings ("HKLM\\..."), and socket descriptions ("TCP 10.0.0.5:
# 51000 -> ..."). Requiring a drive letter or UNC prefix is what excludes all
# of those without needing to special-case each one.
_WINDOWS_PATH_RE = re.compile(r"^(?:[A-Za-z]:\\|\\\\)[^<>:\"|?*\n]+$")

# Kept in sync with pestudio_analysis.py's own `binary_extensions` -- no point
# handing off a file type File Analysis's Static Triage doesn't parse anyway.
_HANDOFF_ELIGIBLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".cpl", ".ocx", ".drv", ".elf", ".so", ".bin"}
_MAX_HANDOFF_FILE_BYTES = 50_000_000


def iter_anomalies(node: Any) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Recursively walks an arbitrarily-nested father-agent report (sub-master
    reports nest inside father reports nest inside the investigation summary)
    and yields (agent_name, anomaly_dict) for every anomalies_found entry at
    any depth, without assuming any specific report shape."""
    if isinstance(node, dict):
        agent_name = node.get("agent_name", "unknown_agent")
        anomalies = node.get("anomalies_found")
        if isinstance(anomalies, list):
            for a in anomalies:
                if isinstance(a, dict):
                    yield agent_name, a
        for value in node.values():
            yield from iter_anomalies(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_anomalies(item)


def _sha256(path: Path, chunk_size: int = 4 * 1024 * 1024) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _collect_staged_hashes(staging_root: Path) -> set:
    """sha256 of every already-collected binary under any category's raw/ --
    used so a file already sitting in e.g. Downloads/raw/ (already
    discoverable by File Analysis's generic per-category scan) isn't copied
    a second time just because a Windows Forensics agent also flagged it."""
    hashes = set()
    for raw_dir in staging_root.glob("*/raw"):
        if not raw_dir.is_dir():
            continue
        for fpath in raw_dir.rglob("*"):
            if not fpath.is_file() or fpath.suffix.lower() not in _HANDOFF_ELIGIBLE_EXTENSIONS:
                continue
            try:
                if fpath.stat().st_size > _MAX_HANDOFF_FILE_BYTES:
                    continue
                hashes.add(_sha256(fpath))
            except Exception:
                continue
    return hashes


def _append_handoff_log(staging_root: Path, records: List[Dict[str, Any]]) -> None:
    log_path = staging_root / HANDOFF_LOG_FILENAME
    try:
        existing = json.loads(log_path.read_text(encoding="utf-8")) if log_path.is_file() else []
    except Exception:
        existing = []
    try:
        log_path.write_text(json.dumps(existing + records, indent=2, default=str), encoding="utf-8")
    except Exception:
        pass


def scan_and_handoff_suspicious_files(report_tree: Any, staging_root: Path) -> List[Dict[str, Any]]:
    """Call once per father agent, immediately after it completes (see
    master_analyst.py). Best-effort throughout: a file that can no longer be
    read, a hash that fails, a copy that fails -- every failure mode is
    skipped silently rather than raised, since a missed handoff should never
    be allowed to abort the rest of the investigation."""
    handoffs: List[Dict[str, Any]] = []
    staged_hashes = None  # computed lazily, only if a real candidate is found

    for agent_name, anomaly in iter_anomalies(report_tree):
        filepath = anomaly.get("filepath")
        if not filepath or not isinstance(filepath, str):
            continue
        filepath = filepath.strip()
        if not _WINDOWS_PATH_RE.match(filepath):
            continue

        src = Path(filepath)
        if src.suffix.lower() not in _HANDOFF_ELIGIBLE_EXTENSIONS:
            continue
        try:
            if not src.is_file() or src.stat().st_size > _MAX_HANDOFF_FILE_BYTES:
                continue
            file_hash = _sha256(src)
        except Exception:
            continue

        if staged_hashes is None:
            staged_hashes = _collect_staged_hashes(staging_root)
        if file_hash in staged_hashes:
            continue  # already discoverable by File Analysis's generic scan

        dest_dir = staging_root / HANDOFF_INTAKE_CATEGORY / "raw"
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / f"handoff_{agent_name}_{src.name}"
            shutil.copy2(src, dest)
        except Exception:
            continue

        staged_hashes.add(file_hash)
        record = {
            "source_agent": agent_name,
            "original_path": str(src),
            "staged_path": str(dest),
            "sha256": file_hash,
            "reason": anomaly.get("justification", ""),
            "severity": anomaly.get("severity"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        handoffs.append(record)
        try:
            from bridge.hitl_bridge import bridge
            bridge.log_event(
                agent_name,
                f"Handed off '{src.name}' to the File Analysis pipeline for deeper inspection.",
                level="WARN",
            )
        except Exception:
            pass

    if handoffs:
        _append_handoff_log(staging_root, handoffs)
    return handoffs
