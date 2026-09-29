import asyncio
import csv
import json
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.base_agent import BaseHITLAgent
from core.models import TimelineEvent, TimestompingCandidate
from core.utils import locate_staging_directory
from .evtx_sysmon import parse_evtx_file

# ===========================================================================
# Shared flexible datetime parsing
# ===========================================================================

_DATETIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
]


def _parse_datetime_flexible(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _DATETIME_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ===========================================================================
# MFT ($STANDARD_INFORMATION vs $FILE_NAME) timestomping detection
#
# NOTE ON VERIFICATION: MFTECmd's exact CSV header could not be empirically
# confirmed in this sandbox -- reading a live $MFT requires SeBackupPrivilege
# (administrator), which this environment does not have (confirmed: MFTECmd
# itself reports "Administrator privileges not found!" when tested here; see
# collectors/collector.py::extract_mft()). Column names below are MFTECmd's
# documented/expected names; resolution falls back to fuzzy matching against
# whatever header is actually present, and reports a clear diagnostic instead
# of silently returning nothing if neither matches. This code path should be
# validated against a real MFTECmd CSV on a machine with admin rights.
# ===========================================================================

_SI_CREATED_CANDIDATES = ["Created0x10", "SI Created", "StandardInfoCreated"]
_FN_CREATED_CANDIDATES = ["Created0x30", "FN Created", "FileNameCreated"]
_PATH_CANDIDATES = ["ParentPath", "FullPath", "Path"]
_NAME_CANDIDATES = ["FileName", "Name"]

TIMESTOMP_THRESHOLD_SECONDS = 60  # legitimate copy/move can shift $FN vs $SI slightly; timestomping produces far larger gaps


def _resolve_column(header: List[str], exact_candidates: List[str], fuzzy_token: str) -> Optional[str]:
    lower_map = {h.lower(): h for h in header}
    for cand in exact_candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    for h in header:
        hl = h.lower()
        if "creat" in hl and fuzzy_token in hl:
            return h
    return None


def parse_mftecmd_csv(
    csv_path: Path,
    threshold_seconds: int = TIMESTOMP_THRESHOLD_SECONDS,
) -> Tuple[List[TimestompingCandidate], Optional[str]]:
    if not csv_path.exists():
        return [], f"MFT CSV not found: {csv_path}"
    try:
        with open(csv_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            si_col = _resolve_column(header, _SI_CREATED_CANDIDATES, "0x10")
            fn_col = _resolve_column(header, _FN_CREATED_CANDIDATES, "0x30")
            if not si_col or not fn_col:
                return [], (
                    f"Could not identify $SI/$FN created-time columns in {csv_path.name} "
                    f"(looked for {_SI_CREATED_CANDIDATES} / {_FN_CREATED_CANDIDATES} "
                    f"among header: {header})"
                )
            path_col = next((h for h in header if h in _PATH_CANDIDATES), None)
            name_col = next((h for h in header if h in _NAME_CANDIDATES), None)

            candidates: List[TimestompingCandidate] = []
            for row in reader:
                si_dt = _parse_datetime_flexible(row.get(si_col))
                fn_dt = _parse_datetime_flexible(row.get(fn_col))
                if si_dt is None or fn_dt is None:
                    continue
                delta = (si_dt - fn_dt).total_seconds()
                if abs(delta) < threshold_seconds:
                    continue
                parts = [row.get(path_col), row.get(name_col)] if (path_col or name_col) else []
                full_path = "\\".join(p for p in parts if p) or row.get(name_col) or "unknown"
                candidates.append(TimestompingCandidate(
                    full_path=full_path,
                    si_created_utc=si_dt.isoformat(),
                    fn_created_utc=fn_dt.isoformat(),
                    discrepancy_seconds=delta,
                    reason=f"$STANDARD_INFORMATION and $FILE_NAME creation times differ by {delta:.0f}s",
                ))
            return candidates, None
    except Exception as e:
        return [], f"Failed to parse MFT CSV: {e}"


# ===========================================================================
# Plaso / log2timeline output parsing (l2tcsv, JSONL, SQLite export)
# ===========================================================================

def parse_l2t_csv(csv_path: Path, max_events: int = 500) -> Tuple[List[TimelineEvent], Optional[str]]:
    """Plaso's l2tcsv export format: date,time,timezone,MACB,source,
    sourcetype,type,user,host,short,desc,version,filename,inode,notes,
    format,extra -- a decade-stable, widely documented Plaso output format."""
    if not csv_path.exists():
        return [], f"L2T CSV not found: {csv_path}"
    events: List[TimelineEvent] = []
    try:
        with open(csv_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            header_lower = {h.lower() for h in header}
            if "macb" not in header_lower or "date" not in header_lower:
                return [], f"{csv_path.name} does not look like a Plaso l2tcsv export (missing date/MACB columns)"
            field_map = {h.lower(): h for h in header}

            def col(name):
                return field_map.get(name)

            for row in reader:
                if len(events) >= max_events:
                    break
                date_val = row.get(col("date"), "") if col("date") else ""
                time_val = row.get(col("time"), "") if col("time") else ""
                dt = _parse_datetime_flexible(f"{date_val} {time_val}".strip())
                if dt is None:
                    continue
                events.append(TimelineEvent(
                    timestamp_utc=dt.isoformat(),
                    source="Plaso",
                    macb=row.get(col("macb")) if col("macb") else None,
                    description=row.get(col("desc"), "") if col("desc") else "",
                    path=row.get(col("filename")) if col("filename") else None,
                    details={k: row.get(field_map[k]) for k in
                             ("source", "sourcetype", "type", "user", "host", "short", "notes", "format", "extra")
                             if k in field_map},
                ))
    except Exception as e:
        return [], f"Failed to parse l2t CSV: {e}"
    return events, None


def parse_plaso_jsonl(path: Path, max_events: int = 500) -> Tuple[List[TimelineEvent], Optional[str]]:
    """Plaso's psort `json_line` export: one JSON object per line, typically
    carrying a 'datetime' ISO string (or a raw 'timestamp' in microseconds
    since epoch), 'timestamp_desc', 'message'/'display_name', 'parser', etc."""
    if not path.exists():
        return [], f"JSONL file not found: {path}"
    events: List[TimelineEvent] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(events) >= max_events:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue

                dt = None
                ts_raw = obj.get("datetime")
                if isinstance(ts_raw, str):
                    dt = _parse_datetime_flexible(ts_raw)
                if dt is None:
                    raw_ts = obj.get("timestamp")
                    if isinstance(raw_ts, (int, float)):
                        try:
                            dt = datetime.fromtimestamp(raw_ts / 1_000_000, tz=timezone.utc)
                        except (ValueError, OverflowError, OSError):
                            dt = None
                if dt is None:
                    continue

                events.append(TimelineEvent(
                    timestamp_utc=dt.isoformat(),
                    source="Plaso",
                    macb=obj.get("timestamp_desc"),
                    description=obj.get("message") or obj.get("display_name") or "",
                    path=obj.get("filename") or obj.get("path_spec"),
                    details={k: obj[k] for k in ("parser", "data_type", "source_short", "source_long") if k in obj},
                ))
    except Exception as e:
        return [], f"Failed to parse Plaso JSONL: {e}"
    return events, None


def parse_plaso_sqlite(path: Path, max_events: int = 500) -> Tuple[List[TimelineEvent], Optional[str]]:
    """Best-effort Plaso storage-file reader. Plaso's native SQLite storage
    schema is internal/version-specific and requires the `plaso` package
    itself to deserialize correctly; if it is installed, use it for full
    fidelity. Otherwise fall back to treating the file as a plain flattened
    export table (e.g. `psort -o sqlite`) with timeline-shaped columns, and
    report clearly which mode produced the result.

    NOT independently verified end-to-end here: `plaso` cannot be installed
    in this sandbox (heavy native dependency chain), so the native-reader
    branch below has no real Plaso storage file to test against. It fails
    closed (returns an error string, never raises) if its internal API
    assumptions are wrong on whatever `plaso` version is actually installed.
    """
    if not path.exists():
        return [], f"SQLite file not found: {path}"

    try:
        import plaso  # noqa: F401
        plaso_available = True
    except ImportError:
        plaso_available = False

    if plaso_available:
        try:
            from plaso.storage.sqlite import reader as plaso_sqlite_reader  # type: ignore
            events: List[TimelineEvent] = []
            with plaso_sqlite_reader.SQLiteStorageFileReader(str(path)) as reader:
                for event in reader.GetSortedEvents():
                    if len(events) >= max_events:
                        break
                    dt = datetime.fromtimestamp(event.timestamp / 1_000_000, tz=timezone.utc)
                    events.append(TimelineEvent(
                        timestamp_utc=dt.isoformat(),
                        source="Plaso",
                        macb=getattr(event, "timestamp_desc", None),
                        description=getattr(event, "message", "") or "",
                        path=getattr(event, "filename", None),
                        details={},
                    ))
            return events, None
        except Exception as e:
            return [], f"`plaso` is installed but native storage reading failed: {e}"

    try:
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r["name"] for r in cur.fetchall()]

        events: List[TimelineEvent] = []
        note: Optional[str] = None
        for table in tables:
            if table.lower() in ("metadata", "sqlite_sequence"):
                continue
            cur.execute(f"PRAGMA table_info('{table}')")
            cols = [r["name"] for r in cur.fetchall()]
            cols_lower = {c.lower(): c for c in cols}
            has_datetime = "datetime" in cols_lower
            has_date_time = "date" in cols_lower and "time" in cols_lower
            if not (has_datetime or has_date_time):
                continue

            cur.execute(f"SELECT * FROM '{table}' LIMIT {max_events}")
            for row in cur.fetchall():
                row_dict = dict(row)
                dt = None
                if has_datetime:
                    dt = _parse_datetime_flexible(row_dict.get(cols_lower["datetime"]))
                elif has_date_time:
                    dt = _parse_datetime_flexible(f"{row_dict.get(cols_lower['date'])} {row_dict.get(cols_lower['time'])}")
                if dt is None:
                    continue
                events.append(TimelineEvent(
                    timestamp_utc=dt.isoformat(),
                    source="Plaso",
                    macb=row_dict.get(cols_lower.get("macb")) or row_dict.get(cols_lower.get("timestamp_desc")),
                    description=row_dict.get(cols_lower.get("desc")) or row_dict.get(cols_lower.get("message")) or "",
                    path=row_dict.get(cols_lower.get("filename")) or row_dict.get(cols_lower.get("path")),
                    details={},
                ))
            if events:
                note = (f"Read as a flattened export table '{table}' -- install the `plaso` package "
                        f"for full-fidelity native storage-file parsing.")
                break
        conn.close()
        if not events and note is None:
            note = (f"No timeline-shaped table found among {tables}. Native Plaso .plaso storage files "
                    f"require the `plaso` package to parse.")
        return events, note
    except Exception as e:
        return [], f"Failed to open SQLite file: {e}"


# ===========================================================================
# Time-window slicing -- keeps the LLM payload bounded to only the moments
# that matter, instead of a full multi-thousand-event timeline dump.
# ===========================================================================

def _to_aware(dt_str: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(dt_str)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def slice_timeline_window(events: List[TimelineEvent], pivot_iso: str, window_minutes: int) -> List[TimelineEvent]:
    """Every event within +/- window_minutes of pivot_iso, chronologically sorted."""
    pivot = _to_aware(pivot_iso)
    if pivot is None:
        return []
    delta = timedelta(minutes=window_minutes)
    lo, hi = pivot - delta, pivot + delta

    sliced = []
    for e in events:
        ts = _to_aware(e.timestamp_utc)
        if ts is not None and lo <= ts <= hi:
            sliced.append((ts, e))
    sliced.sort(key=lambda pair: pair[0])
    return [e for _, e in sliced]


def find_densest_window(events: List[TimelineEvent], window_minutes: int = 10) -> Optional[str]:
    """Auto-pick a pivot when no explicit alert timestamp is available: the
    center of the window containing the most events, via a linear sliding-
    window density scan over sorted timestamps."""
    parsed = sorted(ts for ts in (_to_aware(e.timestamp_utc) for e in events) if ts is not None)
    if not parsed:
        return None

    window = timedelta(minutes=window_minutes)
    best_start, best_count = parsed[0], 0
    left = 0
    for right in range(len(parsed)):
        while parsed[right] - parsed[left] > window:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_start = parsed[left]
    return (best_start + window / 2).isoformat()


# ===========================================================================
# Defense evasion: log clearing (reuses the EVTX pre-filter infrastructure)
# ===========================================================================

_LOG_CLEAR_EVENTS: Dict[Tuple[str, int], str] = {
    ("Microsoft-Windows-Eventlog", 1102): "Security Audit Log Cleared",
    ("Microsoft-Windows-Eventlog", 104): "Event Log Cleared",
}

_PROCESS_CREATION_EVENTS: Dict[Tuple[str, int], str] = {
    ("Microsoft-Windows-Sysmon", 1): "Process Creation",
    ("Microsoft-Windows-Security-Auditing", 4688): "Process Creation (Security Audit)",
}


def detect_log_clearing_events(staging_root: Path, max_events: int = 50) -> List[TimelineEvent]:
    raw_dir = staging_root / "Logs" / "raw"
    events: List[TimelineEvent] = []
    if not raw_dir.exists():
        return events
    for evtx_path in sorted(raw_dir.glob("*.evtx")):
        correlated, _error = parse_evtx_file(evtx_path, allowed_events=_LOG_CLEAR_EVENTS, max_events=max_events)
        for ce in correlated:
            events.append(TimelineEvent(
                timestamp_utc=ce.time_created_utc or "",
                source="EVTX",
                macb=None,
                description=ce.event_type_label,
                path=None,
                details={"provider": ce.provider, "event_id": ce.event_id, "source_file": ce.source_file, **ce.key_fields},
            ))
    return [e for e in events if e.timestamp_utc]


# ===========================================================================
# Anti-forensics tool execution: Prefetch evidence + process-creation command
# lines matching known evidence-destruction patterns.
# ===========================================================================

_ANTI_FORENSIC_TOOL_NAMES = [
    "vssadmin.exe", "wevtutil.exe", "wbadmin.exe", "cipher.exe", "sdelete.exe",
    "sdelete64.exe", "bcdedit.exe", "fsutil.exe",
]

_ANTI_FORENSIC_CMDLINE_PATTERNS = [
    re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.I),
    re.compile(r"wmic\s+shadowcopy\s+delete", re.I),
    re.compile(r"wevtutil(\.exe)?\s+cl\s", re.I),
    re.compile(r"cipher(\.exe)?\s+/w", re.I),
    re.compile(r"bcdedit(\.exe)?.*(recoveryenabled\s+no|ignoreallfailures)", re.I),
    re.compile(r"fsutil\s+usn\s+deletejournal", re.I),
]


def detect_anti_forensic_tool_usage(staging_root: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    prefetch_meta = staging_root / "Prefetch" / "metadata"
    if prefetch_meta.exists():
        for csv_path in prefetch_meta.glob("*.csv"):
            try:
                with open(csv_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    name_col = next(
                        (h for h in (reader.fieldnames or [])
                         if h.lower() in ("sourcefilename", "executablename", "filename")),
                        None,
                    )
                    for row in reader:
                        haystack = (row.get(name_col) if name_col else " ".join(str(v) for v in row.values())) or ""
                        low = haystack.lower()
                        for tool in _ANTI_FORENSIC_TOOL_NAMES:
                            if tool in low:
                                findings.append({"source": "Prefetch", "tool": tool, "evidence": haystack, "file": csv_path.name})
            except Exception:
                continue

    raw_dir = staging_root / "Logs" / "raw"
    if raw_dir.exists():
        for evtx_path in sorted(raw_dir.glob("*.evtx")):
            correlated, _error = parse_evtx_file(evtx_path, allowed_events=_PROCESS_CREATION_EVENTS, max_events=500)
            for ce in correlated:
                cmdline = str(ce.key_fields.get("CommandLine") or ce.key_fields.get("ProcessCommandLine") or "")
                image = str(ce.key_fields.get("Image") or ce.key_fields.get("NewProcessName") or "")
                haystack = f"{image} {cmdline}".strip()
                for pattern in _ANTI_FORENSIC_CMDLINE_PATTERNS:
                    if pattern.search(haystack):
                        findings.append({
                            "source": "EVTX", "tool": pattern.pattern, "evidence": haystack,
                            "timestamp_utc": ce.time_created_utc, "file": evtx_path.name,
                        })
    return findings


# ===========================================================================
# Hidden data / staging: archive created shortly after a burst of file
# creations in the same directory. Reuses the *_file_inventory.csv artifacts
# the malware-path agents (Feature 1) already write -- no re-parsing needed.
# ===========================================================================

_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".cab", ".gz", ".tar"}


def detect_staging_clusters(
    staging_root: Path,
    window_seconds: int = 120,
    min_prior_files: int = 3,
) -> List[Dict[str, Any]]:
    by_dir: Dict[str, List[Tuple[datetime, str, str]]] = {}

    for csv_path in staging_root.glob("*/metadata/*_file_inventory.csv"):
        try:
            with open(csv_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    full_path = row.get("full_path") or ""
                    created = _parse_datetime_flexible(row.get("created_utc"))
                    if not full_path or created is None:
                        continue
                    directory = str(Path(full_path).parent)
                    ext = (row.get("extension") or "").lower()
                    by_dir.setdefault(directory, []).append((created, row.get("filename", ""), ext))
        except Exception:
            continue

    findings: List[Dict[str, Any]] = []
    for directory, entries in by_dir.items():
        entries.sort(key=lambda t: t[0])
        for i, (created, name, ext) in enumerate(entries):
            if ext not in _ARCHIVE_EXTENSIONS:
                continue
            window_start = created - timedelta(seconds=window_seconds)
            prior = [e for e in entries[:i] if window_start <= e[0] <= created]
            if len(prior) >= min_prior_files:
                findings.append({
                    "directory": directory,
                    "archive_file": name,
                    "archive_created_utc": created.isoformat(),
                    "prior_file_count_in_window": len(prior),
                    "prior_files": [p[1] for p in prior][-10:],
                })
    return findings


class TimelineAnomalyAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="Timeline_Anomaly_Detector",
            system_prompt=(
                "You are a Forensic Timeline Analyst. You are given a bounded set of pre-sliced timeline "
                "windows (never a full raw timeline) plus three pre-computed signal groups: "
                "(1) MFT timestomping candidates, where $STANDARD_INFORMATION and $FILE_NAME creation "
                "timestamps for the same file disagree by more than a noise threshold; "
                "(2) event-log-clearing events (ID 1102 Security audit log cleared / 104 event log "
                "cleared) and anti-forensics tool execution evidence (vssadmin shadow deletion, wevtutil "
                "cl, cipher /w, sdelete, bcdedit recovery tampering, fsutil usn deletejournal) found in "
                "Prefetch execution history or process-creation telemetry; and "
                "(3) staging clusters, where an archive (.zip/.rar/.7z/.iso) was created immediately after "
                "several other files landed in the same directory -- classic stage-then-exfiltrate behavior. "
                "For each signal: state what it means, how confident you are it reflects malicious activity "
                "versus a benign explanation (e.g. a scheduled backup job also clears logs and prunes "
                "shadow copies), and cite the MACB activity in the corresponding sliced time window that "
                "supports or undermines that read. Never invent an event that is not in the provided data."
            )
        )

    def _load_available_events(self, staging_root: Path) -> Tuple[List[TimelineEvent], List[str]]:
        events: List[TimelineEvent] = []
        issues: List[str] = []

        timeline_raw = staging_root / "Timeline" / "raw"
        if timeline_raw.exists():
            for path in sorted(timeline_raw.iterdir()):
                if not path.is_file():
                    continue
                suffix = path.suffix.lower()
                if suffix == ".csv":
                    parsed, err = parse_l2t_csv(path)
                elif suffix in (".jsonl", ".json", ".ndjson"):
                    parsed, err = parse_plaso_jsonl(path)
                elif suffix in (".db", ".sqlite", ".sqlite3", ".plaso"):
                    parsed, err = parse_plaso_sqlite(path)
                else:
                    continue
                events.extend(parsed)
                if err:
                    issues.append(f"{path.name}: {err}")

        events.extend(detect_log_clearing_events(staging_root))
        return events, issues

    def _load_timestomping_candidates(self, staging_root: Path) -> Tuple[List[TimestompingCandidate], Optional[str]]:
        meta_dir = staging_root / "MFT" / "metadata"
        if not meta_dir.exists():
            return [], f"No MFT/metadata/ folder present under {staging_root / 'MFT'}"
        csvs = sorted(meta_dir.glob("*.csv"))
        if not csvs:
            return [], "MFT/metadata/ exists but contains no MFTECmd CSV output."
        return parse_mftecmd_csv(csvs[0])

    async def process_task(self, staging_root: Path):
        events, timeline_issues = self._load_available_events(staging_root)
        timestomping, mft_issue = self._load_timestomping_candidates(staging_root)
        anti_forensic_findings = detect_anti_forensic_tool_usage(staging_root)
        staging_clusters = detect_staging_clusters(staging_root)

        # Pivot on every high-signal moment we found -- log clears, timestomped
        # files, anti-forensics tool runs -- and fall back to the single
        # densest activity window if nothing else stands out. This is the
        # "inspect a targeted window instead of the whole timeline" mechanism.
        pivots: List[str] = []
        pivots.extend(e.timestamp_utc for e in events if e.source == "EVTX")
        pivots.extend(tc.fn_created_utc for tc in timestomping if tc.fn_created_utc)
        pivots.extend(f["timestamp_utc"] for f in anti_forensic_findings if f.get("timestamp_utc"))
        if not pivots and events:
            densest = find_densest_window(events, window_minutes=10)
            if densest:
                pivots.append(densest)

        window_minutes = 15
        sliced_windows: Dict[str, List[Dict[str, Any]]] = {}
        for pivot in dict.fromkeys(pivots):  # de-dupe, preserve order
            window_events = slice_timeline_window(events, pivot, window_minutes)
            if window_events:
                sliced_windows[pivot] = [e.dict() for e in window_events[:100]]

        if timestomping:
            meta_dir = staging_root / "Timeline" / "metadata"
            meta_dir.mkdir(parents=True, exist_ok=True)
            self.write_records_csv(timestomping, meta_dir / "timestomping_candidates.csv")

        payload: Dict[str, Any] = {
            "category": "Timeline",
            "window_minutes": window_minutes,
            "total_events_ingested": len(events),
            "sliced_window_count": len(sliced_windows),
            "sliced_windows": sliced_windows,
            "timestomping_candidates": [t.dict() for t in timestomping],
            "anti_forensic_tool_evidence": anti_forensic_findings,
            "staging_clusters": staging_clusters,
            "parsing_issues": timeline_issues + ([mft_issue] if mft_issue else []),
        }

        parsed_json_data = self._truncate_payload(json.dumps(payload, default=str))
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = TimelineAnomalyAgent()
    asyncio.run(agent.process_task(staging_root))
