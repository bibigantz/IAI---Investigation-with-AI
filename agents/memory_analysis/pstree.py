"""
Process & Thread Mapper -- Automation -> LLM Agent.

Runs windows.pslist.PsList, windows.pstree.PsTree, and windows.psxview.PsXView,
deterministically pre-computes the pslist/psxview visibility discrepancy and a
parent-child legitimacy check (cheap, exact, no LLM needed for these two), then
hands the LLM the full picture -- including the pre-flagged candidates -- to
reason about masquerading names, non-standard binary paths, and anything the
fixed parent/child rule table doesn't already know about.
"""
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory
from . import volatility_runner as vol

AGENT_NAME = "PsTree_Process_Mapper"

# Well-known legitimate parent processes on a stock Windows box, by lowercase
# child image name. A parent NOT in this set is not automatically malicious --
# it's a candidate the LLM is specifically pointed at, since this table can
# never be exhaustive across every legitimate third-party install.
_EXPECTED_PARENTS = {
    "svchost.exe": {"services.exe", "wininit.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "winlogon.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "smss.exe": {"system"},
    "explorer.exe": {"userinit.exe"},
    "userinit.exe": {"winlogon.exe"},
    "csrss.exe": {"smss.exe"},
    "spoolsv.exe": {"services.exe"},
}
_SYSTEM_CRITICAL_NAMES = set(_EXPECTED_PARENTS.keys()) | {"system", "wermgr.exe"}


def _first(row: Dict[str, Any], *keys: str, default=None):
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return default


def _as_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _normalize_pslist(rows: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    out = {}
    for row in rows:
        pid = _as_int(_first(row, "PID", "Pid"))
        if pid is None:
            continue
        out[pid] = {
            "pid": pid,
            "ppid": _as_int(_first(row, "PPID", "Ppid")),
            "name": _first(row, "ImageFileName", "Process", default="?"),
        }
    return out


def _build_tree(pslist: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_ppid: Dict[Any, List[int]] = {}
    for pid, info in pslist.items():
        by_ppid.setdefault(info["ppid"], []).append(pid)

    def _node(pid: int) -> Dict[str, Any]:
        info = pslist[pid]
        return {
            "pid": pid, "name": info["name"], "ppid": info["ppid"],
            "children": [_node(child) for child in by_ppid.get(pid, [])],
        }

    roots = [pid for pid, info in pslist.items() if info["ppid"] not in pslist]
    return [_node(pid) for pid in roots]


def compute_hidden_pids(pslist_rows: List[Dict[str, Any]], psxview_rows: List[Dict[str, Any]]) -> List[int]:
    """PIDs psxview's cross-view scan (csrss handles, thread scanning, etc.)
    sees that windows.pslist.PsList's linked-list walk does not -- the classic
    DKOM unlinking tell."""
    pslist_pids = {_as_int(_first(r, "PID", "Pid")) for r in pslist_rows} - {None}
    hidden = []
    for row in psxview_rows:
        pid = _as_int(_first(row, "PID", "Pid"))
        if pid is None or pid in pslist_pids:
            continue
        # psxview marks per-source visibility as True/False columns
        # (pslist, psscan, thrdproc, pspcid, csrss, session, deskthrd, ...).
        seen_elsewhere = any(
            str(v).strip().lower() == "true"
            for k, v in row.items()
            if k.lower() != "pslist" and isinstance(v, (str, bool))
        )
        if seen_elsewhere:
            hidden.append(pid)
    return hidden


def compute_parent_anomalies(pslist: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    anomalies = []
    for pid, info in pslist.items():
        name = (info["name"] or "").lower()
        ppid = info["ppid"]
        if name not in _EXPECTED_PARENTS:
            continue
        parent = pslist.get(ppid)
        parent_name = (parent["name"] or "").lower() if parent else None
        if parent_name is None:
            anomalies.append({
                "pid": pid, "process_name": info["name"], "ppid": ppid,
                "anomaly_type": "Orphaned Process",
                "detail": f"{info['name']} (PID {pid}) has PPID {ppid}, which is not a live process -- parent exited or was terminated.",
                "severity": "Medium",
            })
        elif parent_name not in _EXPECTED_PARENTS[name]:
            anomalies.append({
                "pid": pid, "process_name": info["name"], "ppid": ppid,
                "anomaly_type": "Unexpected Parent",
                "detail": f"{info['name']} (PID {pid}) was spawned by {parent['name']} (PID {ppid}); expected one of {sorted(_EXPECTED_PARENTS[name])}.",
                "severity": "High",
            })
    return anomalies


class ProcessTreeMapperAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name=AGENT_NAME,
            system_prompt=(
                "You are a Volatile Memory Forensic Expert analyzing process listings from Volatility3. "
                "You are given: (1) the reconstructed process tree, (2) PIDs already flagged as hidden/unlinked "
                "because they were seen by psxview's cross-view scan but not by pslist's linked-list walk, and "
                "(3) parent-child anomalies already flagged by a fixed table of well-known Windows process "
                "relationships. Your job is what the fixed table CANNOT do: judge whether the already-flagged "
                "candidates are truly suspicious given full context, and independently find masquerading process "
                "names (e.g. 'svch0st.exe', 'scvhost.exe', lookalike Unicode characters), processes running from "
                "non-standard paths (e.g. an explorer.exe outside System32/SysWOW64), and any other anomaly the "
                "fixed table has no entry for. Do not re-flag something the automation already flagged unless you "
                "have a materially different or additional reason. For every anomaly you report, set the "
                "'filepath' field to EXACTLY 'PID <pid> (<process_name>)' (e.g. 'PID 1337 (svch0st.exe)') -- "
                "the Father Agent parses the PID back out of this field verbatim."
            )
        )

    async def process_task(self, staging_root: Path):
        image_path = vol.locate_memory_image(staging_root)
        if image_path is None:
            parsed_json_data = json.dumps({"error": "No memory image found under MemoryDumps/raw/"})
            return await self.run_with_hitl(parsed_tool_data=parsed_json_data)

        pslist_rows = vol.run_plugin(image_path, "windows.pslist.PsList")
        pstree_rows = vol.run_plugin(image_path, "windows.pstree.PsTree")
        psxview_rows = vol.run_plugin(image_path, "windows.psxview.PsXView")

        pslist = _normalize_pslist(pslist_rows)
        hidden_pids = compute_hidden_pids(pslist_rows, psxview_rows)
        parent_anomalies = compute_parent_anomalies(pslist)
        tree = _build_tree(pslist) if pslist else []

        # Cheap heuristic used only to seed ProcessTreeFinding.anomaly_score in
        # the Father Agent's aggregated report -- hidden/unlinked processes
        # weigh far more than a parent/child mismatch, since DKOM unlinking
        # has no benign explanation while an unusual parent sometimes does.
        anomaly_score = min(100.0, len(hidden_pids) * 40 + sum(
            15 if a["severity"] == "High" else 8 for a in parent_anomalies
        ))

        payload = {
            "memory_image": str(image_path),
            "total_processes": len(pslist),
            "process_tree": tree,
            "pstree_raw_row_count": len(pstree_rows),
            "automation_flagged_hidden_pids": hidden_pids,
            "automation_flagged_parent_anomalies": parent_anomalies,
            "automation_anomaly_score": anomaly_score,
        }
        parsed_json_data = self._truncate_payload(json.dumps(payload, default=str))
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = ProcessTreeMapperAgent()
    asyncio.run(agent.process_task(staging_root))
