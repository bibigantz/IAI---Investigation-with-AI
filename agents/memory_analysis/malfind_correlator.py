"""
MALFIND Correlator -- pure automation, zero LLM tokens.

Cross-references windows.malfind.Malfind against windows.thrdscan.ThrdScan
(thread start addresses), windows.handles.Handles (remote-process handles),
and windows.dlllist.DllList (legitimate loaded-module ranges) using a fixed,
auditable rule set, and derives a 0-100 confidence score -> severity from
whichever rules fired. This exists specifically so a 200-hit malfind run on a
busy system doesn't burn 200 LLM calls just to find the handful that actually
matter -- see InjectedCodeAnalyzerAgent (malfind.py), which spends its LLM
budget only on the subset this module already scored Medium or above.

Note on plugin naming: the brief for this module named windows.modules for the
"legitimate loaded module" check. windows.modules.Modules lists *kernel*
drivers, not per-process user-mode DLLs, so it cannot answer "does this VA
belong to a module loaded in *this* process" -- windows.dlllist.DllList (per-
process base+size ranges) is the plugin that actually answers that question,
and is what R4 below uses.
"""
import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base_agent import BaseHITLAgent
from core.models import MalfindCorrelation
from core.utils import locate_staging_directory
from . import volatility_runner as vol

AGENT_NAME = "Malfind_Correlator"

# --- Deterministic scoring rules -------------------------------------------
# Every rule is a fixed point delta; the sum (clamped to [0, 100]) is the
# confidence_score, and severity is a fixed threshold off of that -- nothing
# here is probabilistic or LLM-derived, by design (see module docstring).
POINTS_UNBACKED_VAD = 30          # base signal: this row came from malfind at all
POINTS_THREAD_START_IN_REGION = 30
POINTS_REMOTE_HANDLE = 25
POINTS_REMOTE_HANDLE_STRONG_ACCESS_BONUS = 10
POINTS_RWX_PROTECTION = 15
POINTS_BELONGS_TO_LOADED_MODULE = -40  # strong de-prioritization / likely explainable

SEVERITY_THRESHOLDS = (
    (70, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (0, "Low"),
)

_STRONG_ACCESS_MARKERS = ("VM_WRITE", "CREATE_THREAD", "ALL_ACCESS", "VM_OPERATION")


def _score_to_severity(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


def _first(row: Dict[str, Any], *keys: str, default=None):
    """Volatility3's JSON column names have drifted across releases/plugins
    (e.g. 'PID' vs 'Pid', 'Start VPN' vs 'StartVPN'); every row lookup in this
    module goes through this instead of a single hardcoded key."""
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return default


def _as_int(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value), 0) if str(value).lower().startswith("0x") else int(value)
    except (ValueError, TypeError):
        return None


def _normalize_malfind_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for row in rows:
        pid = _as_int(_first(row, "PID", "Pid"))
        if pid is None:
            continue
        va = _first(row, "Start VPN", "Start", "StartVPN", "Address")
        normalized.append({
            "pid": pid,
            "process_name": _first(row, "Process", "ImageFileName"),
            "virtual_address": str(va) if va is not None else "0x0",
            "protection": _first(row, "Protection"),
            "region_size_bytes": _as_int(_first(row, "CommitCharge", "Size")),
        })
    return normalized


def _build_thread_start_map(rows: List[Dict[str, Any]]) -> Dict[int, List[int]]:
    """pid -> [thread start addresses] from windows.thrdscan.ThrdScan."""
    mapping: Dict[int, List[int]] = {}
    for row in rows:
        pid = _as_int(_first(row, "Pid", "PID", "Owner"))
        start = _as_int(_first(row, "StartAddress", "Start Address", "Start"))
        if pid is None or start is None:
            continue
        mapping.setdefault(pid, []).append(start)
    return mapping


def _build_remote_handle_map(rows: List[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    """target_pid -> [{owner_pid, granted_access}] from windows.handles.Handles,
    keeping only Type == 'Process' handles (a handle onto another process
    object -- e.g. what OpenProcess()/CreateRemoteThread() rely on)."""
    mapping: Dict[int, List[Dict[str, Any]]] = {}
    for row in rows:
        if str(_first(row, "Type", default="")).strip().lower() != "process":
            continue
        owner_pid = _as_int(_first(row, "Pid", "PID"))
        name = str(_first(row, "Name", default=""))
        target_pid = _as_int("".join(c for c in name if c.isdigit()) or None)
        if owner_pid is None or target_pid is None or owner_pid == target_pid:
            continue
        mapping.setdefault(target_pid, []).append({
            "owner_pid": owner_pid,
            "granted_access": str(_first(row, "GrantedAccess", "Granted Access", default="")),
        })
    return mapping


def _build_module_range_map(rows: List[Dict[str, Any]]) -> Dict[int, List[tuple]]:
    """pid -> [(base, base+size)] from windows.dlllist.DllList."""
    mapping: Dict[int, List[tuple]] = {}
    for row in rows:
        pid = _as_int(_first(row, "Pid", "PID"))
        base = _as_int(_first(row, "Base"))
        size = _as_int(_first(row, "Size"))
        if pid is None or base is None:
            continue
        mapping.setdefault(pid, []).append((base, base + (size or 0)))
    return mapping


def correlate(
    malfind_rows: List[Dict[str, Any]],
    thread_rows: List[Dict[str, Any]],
    handle_rows: List[Dict[str, Any]],
    module_rows: List[Dict[str, Any]],
) -> List[MalfindCorrelation]:
    """Pure function: raw plugin rows in, scored+ranked MalfindCorrelation
    records out. No I/O, no LLM, no bridge/asyncio -- deliberately trivial to
    unit test with hand-built row lists."""
    thread_map = _build_thread_start_map(thread_rows)
    handle_map = _build_remote_handle_map(handle_rows)
    module_map = _build_module_range_map(module_rows)

    results: List[MalfindCorrelation] = []
    for hit in _normalize_malfind_rows(malfind_rows):
        pid = hit["pid"]
        va = _as_int(hit["virtual_address"]) or 0
        region_size = hit["region_size_bytes"] or 0
        region_end = va + region_size

        matched_rules: List[str] = ["Unbacked VAD (malfind hit)"]
        score = POINTS_UNBACKED_VAD

        thread_start_in_region = any(va <= t < region_end for t in thread_map.get(pid, []))
        if thread_start_in_region:
            matched_rules.append("Thread start address inside VAD")
            score += POINTS_THREAD_START_IN_REGION

        remote_handles = handle_map.get(pid, [])
        remote_handle_present = bool(remote_handles)
        remote_handle_owner_pid = remote_handles[0]["owner_pid"] if remote_handles else None
        if remote_handle_present:
            matched_rules.append(f"Remote process handle held by PID {remote_handle_owner_pid}")
            score += POINTS_REMOTE_HANDLE
            if any(marker in h["granted_access"].upper() for h in remote_handles for marker in _STRONG_ACCESS_MARKERS):
                matched_rules.append("Remote handle grants VM write / thread creation / all-access")
                score += POINTS_REMOTE_HANDLE_STRONG_ACCESS_BONUS

        belongs_to_loaded_module = any(
            base <= va < end for base, end in module_map.get(pid, [])
        )
        if belongs_to_loaded_module:
            matched_rules.append("VA falls inside a legitimately loaded module range")
            score += POINTS_BELONGS_TO_LOADED_MODULE

        protection = (hit["protection"] or "")
        if "EXECUTE_READWRITE" in protection.upper():
            matched_rules.append("PAGE_EXECUTE_READWRITE (RWX, not just RX)")
            score += POINTS_RWX_PROTECTION

        score = max(0, min(100, score))
        results.append(MalfindCorrelation(
            pid=pid,
            process_name=hit["process_name"],
            virtual_address=hit["virtual_address"],
            protection=hit["protection"],
            region_size_bytes=hit["region_size_bytes"],
            unbacked_vad=True,
            thread_start_in_region=thread_start_in_region,
            remote_handle_present=remote_handle_present,
            remote_handle_owner_pid=remote_handle_owner_pid,
            belongs_to_loaded_module=belongs_to_loaded_module,
            matched_rules=matched_rules,
            confidence_score=score,
            severity=_score_to_severity(score),
        ))

    results.sort(key=lambda r: r.confidence_score, reverse=True)
    return results


class MalfindCorrelatorAgent(BaseHITLAgent):
    """Pure-automation sub-module. Deliberately never calls
    execute_llm_analysis() -- see run_automated_with_hitl() in
    core/base_agent.py -- the system_prompt below only exists because
    BaseHITLAgent's constructor always builds one; it is never sent anywhere.
    """

    def __init__(self):
        super().__init__(
            agent_name=AGENT_NAME,
            system_prompt=(
                "Deterministic rule-engine agent -- this system prompt is unused. "
                "See agents/memory_analysis/malfind_correlator.py:correlate()."
            ),
            include_event_context=False,
        )

    async def process_task(self, staging_root: Path):
        image_path = vol.locate_memory_image(staging_root)
        output_dir = staging_root / AGENT_NAME / "raw"

        if image_path is None:
            deterministic_analysis = {
                "agent_name": self.agent_name,
                "status": "Clean",
                "anomalies_found": [],
                "summary": "No memory image found under MemoryDumps/raw/ -- correlation skipped.",
            }
            return await self.run_automated_with_hitl(
                parsed_tool_data={"error": "no memory image staged"},
                deterministic_analysis=deterministic_analysis,
            )

        malfind_rows = vol.run_plugin(image_path, "windows.malfind.Malfind", output_dir=output_dir)
        thread_rows = vol.run_plugin(image_path, "windows.thrdscan.ThrdScan")
        handle_rows = vol.run_plugin(image_path, "windows.handles.Handles")
        module_rows = vol.run_plugin(image_path, "windows.dlllist.DllList")

        correlations = correlate(malfind_rows, thread_rows, handle_rows, module_rows)

        anomalies_found = [
            {
                "filepath": f"PID {c.pid} ({c.process_name or 'unknown'}) @ {c.virtual_address}",
                "anomaly_type": "Correlated Code Injection",
                "severity": c.severity,
                "justification": "; ".join(c.matched_rules),
                "recommended_action": (
                    "Escalate to Injected Code Analyzer for dump review and malware handoff"
                    if c.severity in ("Critical", "High")
                    else "Review during triage; low deterministic corroboration"
                ),
            }
            for c in correlations
        ]
        highest_severity = "Clean"
        if any(c.severity == "Critical" for c in correlations):
            highest_severity = "Critical"
        elif any(c.severity == "High" for c in correlations):
            highest_severity = "Suspicious"
        elif correlations:
            highest_severity = "Suspicious"

        deterministic_analysis = {
            "agent_name": self.agent_name,
            "status": highest_severity,
            "anomalies_found": anomalies_found,
            "summary": (
                f"{len(correlations)} malfind hit(s) correlated against "
                f"{len(thread_rows)} thread(s), {len(handle_rows)} handle(s), "
                f"{len(module_rows)} loaded module(s). "
                f"{sum(1 for c in correlations if c.severity in ('Critical', 'High'))} scored Critical/High."
            ),
        }

        parsed_tool_data = {
            "memory_image": str(image_path),
            "malfind_hit_count": len(malfind_rows),
            "correlations": [c.dict() for c in correlations],
        }

        return await self.run_automated_with_hitl(
            parsed_tool_data=parsed_tool_data,
            deterministic_analysis=deterministic_analysis,
        )


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = MalfindCorrelatorAgent()
    asyncio.run(agent.process_task(staging_root))
