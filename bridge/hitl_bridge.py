import asyncio
import os
import sys
import time
import json
import glob
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

from core.finding_utils import compute_finding_id, compute_cluster_key, default_confidence_for_severity

DASHBOARD_STATE_FILENAME = "dashboard_state.json"


class WebHITLBridge:
    def __init__(self):
        self.execution_mode = "SUPERVISED"
        self.active_investigation_id: Optional[str] = None
        self.pipeline_status = "IDLE"
        self.is_paused = False
        self.pause_event = asyncio.Event()
        self.pause_event.set()
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}
        self.agent_states: Dict[str, Dict[str, Any]] = {}
        self.prompt_overrides: Dict[str, str] = {}
        self.logs: List[Dict[str, Any]] = []
        self._last_snapshot_save = 0.0
        self._init_topology_nodes()

    def _init_topology_nodes(self):
        self.nodes = {
            "Master_Analyst_Agent": {
                "id": "Master_Analyst_Agent", "label": "Master Analyst Agent",
                "type": "master", "state": "GRAY", "parent": None,
                "role": "Top-Level Master Orchestrator"
            },
            "Windows_Forensics_Father_Agent": {
                "id": "Windows_Forensics_Father_Agent", "label": "Windows Forensics Father Agent",
                "type": "father", "state": "GRAY", "parent": "Master_Analyst_Agent",
                "role": "Windows Disk & OS Triage Orchestrator"
            },
            "File_Analysis_Father_Agent": {
                "id": "File_Analysis_Father_Agent", "label": "File Analysis Father Agent",
                "type": "father", "state": "GRAY", "parent": "Master_Analyst_Agent",
                "role": "Malware & Binary Dissection Orchestrator"
            },
            "Memory_Analysis_Father_Agent": {
                "id": "Memory_Analysis_Father_Agent", "label": "Memory Analysis Father Agent",
                "type": "father", "state": "GRAY", "parent": "Master_Analyst_Agent",
                "role": "Volatile Memory Triage Orchestrator"
            },
            "Master_Execution_Artifacts_Analyzer": {
                "id": "Master_Execution_Artifacts_Analyzer", "label": "Artifacts Sub-Master",
                "type": "submaster", "state": "GRAY", "parent": "Windows_Forensics_Father_Agent",
                "role": "Prefetch, Amcache & Shimcache Orchestrator"
            },
            "Master_Execution_Paths_Analyzer": {
                "id": "Master_Execution_Paths_Analyzer", "label": "Malware Paths Sub-Master",
                "type": "submaster", "state": "GRAY", "parent": "Windows_Forensics_Father_Agent",
                "role": "Execution Paths & Autoruns Orchestrator"
            },
            "Prefetch_Analyzer": {
                "id": "Prefetch_Analyzer", "label": "Prefetch Tool Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Artifacts_Analyzer",
                "role": "Executions & Frequency Parser"
            },
            "Amcache_Analyzer": {
                "id": "Amcache_Analyzer", "label": "Amcache Tool Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Artifacts_Analyzer",
                "role": "SHA1 & PE Metadata Inspector"
            },
            "Shimcache_Analyzer": {
                "id": "Shimcache_Analyzer", "label": "Shimcache Tool Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Artifacts_Analyzer",
                "role": "AppCompatCache Timeline Agent"
            },
            "Temp_Folder_Analyzer": {
                "id": "Temp_Folder_Analyzer", "label": "Temp Folder Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Paths_Analyzer",
                "role": "Temp Droppers & Script Hunter"
            },
            "Downloads_Folder_Analyzer": {
                "id": "Downloads_Folder_Analyzer", "label": "Downloads Folder Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Paths_Analyzer",
                "role": "MotW & Payload Inspector"
            },
            "AppData_Public_Paths_Analyzer": {
                "id": "AppData_Public_Paths_Analyzer", "label": "AppData/Public Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Paths_Analyzer",
                "role": "Top-Level AppData & Public Dropper Hunter"
            },
            "ProgramData_Analyzer": {
                "id": "ProgramData_Analyzer", "label": "ProgramData Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Paths_Analyzer",
                "role": "ProgramData Manifest Hunter"
            },
            "Scheduled_Tasks_Analyzer": {
                "id": "Scheduled_Tasks_Analyzer", "label": "Scheduled Tasks Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Paths_Analyzer",
                "role": "Task Persistence Inspector"
            },
            "Services_Analyzer": {
                "id": "Services_Analyzer", "label": "Services Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Paths_Analyzer",
                "role": "Service ImagePath Inspector"
            },
            "Drivers_Analyzer": {
                "id": "Drivers_Analyzer", "label": "Drivers Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Paths_Analyzer",
                "role": "Kernel BYOVD Driver Hunter"
            },
            "Autoruns_Analyzer": {
                "id": "Autoruns_Analyzer", "label": "Autoruns Agent",
                "type": "child", "state": "GRAY", "parent": "Master_Execution_Paths_Analyzer",
                "role": "Startup & Logon Persistence"
            },
            "EVTX_Sysmon_Correlator": {
                "id": "EVTX_Sysmon_Correlator", "label": "EVTX & Sysmon Agent",
                "type": "child", "state": "GRAY", "parent": "Windows_Forensics_Father_Agent",
                "role": "Event Log & Process Tree Correlator"
            },
            "Registry_Hive_Miner": {
                "id": "Registry_Hive_Miner", "label": "Registry Hive Miner",
                "type": "child", "state": "GRAY", "parent": "Windows_Forensics_Father_Agent",
                "role": "Registry Key & Hive Parser"
            },
            "Timeline_Anomaly_Detector": {
                "id": "Timeline_Anomaly_Detector", "label": "Timeline Anomaly Agent",
                "type": "child", "state": "GRAY", "parent": "Windows_Forensics_Father_Agent",
                "role": "Plaso Super Timeline Detector"
            },
            "PeStudio_Static_Triage_Analyzer": {
                "id": "PeStudio_Static_Triage_Analyzer", "label": "Static Triage & Capability Mapper",
                "type": "child", "state": "GRAY", "parent": "File_Analysis_Father_Agent",
                "role": "PE/ELF Header, Hashes & CAPA Mapper (No LLM)"
            },
            "Ghidra_Reverse_Engineering_Agent": {
                "id": "Ghidra_Reverse_Engineering_Agent", "label": "Reverse Engineering & String Analyzer",
                "type": "child", "state": "GRAY", "parent": "File_Analysis_Father_Agent",
                "role": "Ghidra Headless Decompiler, XOR/Base64 Decode & C2 Logic"
            },
            "Dynamic_Sandbox_Correlator": {
                "id": "Dynamic_Sandbox_Correlator", "label": "Dynamic Sandbox Correlator",
                "type": "child", "state": "GRAY", "parent": "File_Analysis_Father_Agent",
                "role": "Cuckoo Sandbox Behavior vs. Static Capability Correlation"
            },
            "PsTree_Process_Mapper": {
                "id": "PsTree_Process_Mapper", "label": "PsTree Agent",
                "type": "child", "state": "GRAY", "parent": "Memory_Analysis_Father_Agent",
                "role": "Volatility Process Tree Mapper"
            },
            "Network_Socket_Correlator": {
                "id": "Network_Socket_Correlator", "label": "Network Agent",
                "type": "child", "state": "GRAY", "parent": "Memory_Analysis_Father_Agent",
                "role": "Volatility NetScan Socket Correlator"
            },
            "MalFind_Injected_Code_Analyzer": {
                "id": "MalFind_Injected_Code_Analyzer", "label": "Injected Code Analyzer",
                "type": "child", "state": "GRAY", "parent": "Memory_Analysis_Father_Agent",
                "role": "Hybrid LLM Triage + Malware Analysis Handoff"
            },
            "Malfind_Correlator": {
                "id": "Malfind_Correlator", "label": "Malfind Correlator",
                "type": "child", "state": "GRAY", "parent": "Memory_Analysis_Father_Agent",
                "role": "Deterministic Injection Scoring (No LLM)"
            }
        }

    def reset_state(self):
        """Clear all per-investigation state (topology, agent snapshots, HITL
        queue, logs) so a brand new investigation starts from a clean slate
        instead of bleeding agent/findings/log data from whatever investigation
        ran previously. Use load_snapshot() instead when resuming an existing
        investigation, to restore its own saved state rather than wiping it."""
        self._init_topology_nodes()
        self.agent_states = {}
        self.pending_approvals = {}
        self.logs = []

    def _snapshot_path(self, staging_dir: str) -> Optional[str]:
        if not staging_dir or os.sep in staging_dir or (os.altsep and os.altsep in staging_dir):
            return None
        return os.path.join(staging_dir, DASHBOARD_STATE_FILENAME)

    def save_snapshot(self, force: bool = False):
        """Persist the current topology/agent/log state into the active
        investigation's staging folder so it survives across stop/resume and
        server restarts. Best-effort: failures are logged but never raised,
        since this is a view-state cache, not the source of truth."""
        if not self.active_investigation_id:
            return
        now = time.time()
        if not force and (now - self._last_snapshot_save) < 1.0:
            return
        path = self._snapshot_path(self.active_investigation_id)
        if not path or not os.path.isdir(self.active_investigation_id):
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "nodes": self.nodes,
                    "agent_states": self.agent_states,
                    "logs": self.logs,
                }, f)
            self._last_snapshot_save = now
        except Exception:
            pass

    def load_snapshot(self, staging_dir: str):
        """Restore a previously-saved dashboard snapshot for staging_dir, so
        resuming/choosing an existing investigation shows exactly the
        topology/findings/logs it was left with. Falls back to a clean reset
        if no snapshot exists yet (e.g. a folder that was never run)."""
        path = self._snapshot_path(staging_dir)
        if not path or not os.path.isfile(path):
            self.reset_state()
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._init_topology_nodes()
            self.nodes.update(data.get("nodes") or {})
            self.agent_states = data.get("agent_states") or {}
            self.logs = data.get("logs") or []
            self.pending_approvals = {}
        except Exception:
            self.reset_state()

    def log_event(self, source: str, message: str, level: str = "INFO", raw_data: Optional[Any] = None):
        entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "source": source,
            "message": message,
            "level": level,
            "raw_data": raw_data
        }
        self.logs.append(entry)
        if len(self.logs) > 2000:
            self.logs = self.logs[-2000:]
        self.save_snapshot()

    def update_node_state(self, agent_name: str, state: str):
        if agent_name in self.nodes:
            self.nodes[agent_name]["state"] = state
            parent_id = self.nodes[agent_name].get("parent")
            if parent_id and parent_id in self.nodes:
                if state in ["GREEN", "YELLOW"]:
                    self.nodes[parent_id]["state"] = "GREEN"
            self.save_snapshot(force=True)

    def register_hitl_pause(self, agent_name: str, raw_data_parsed: Any, ai_analysis: Dict) -> asyncio.Event:
        loop = asyncio.get_event_loop()
        event = asyncio.Event()

        self.pending_approvals[agent_name] = {
            "agent_name": agent_name,
            "raw_data_parsed": raw_data_parsed,
            "ai_analysis": ai_analysis,
            "status": "PENDING_APPROVAL",
            "timestamp": time.strftime("%H:%M:%S"),
            "event": event,
            "decision": None,
            "loop": loop
        }

        self.update_node_state(agent_name, "YELLOW")
        self.log_event(agent_name, f"Agent paused: Awaiting analyst HITL verification", level="HITL")
        return event

    def submit_hitl_decision(self, agent_name: str, action: str, feedback: Optional[str] = None) -> bool:
        if agent_name not in self.pending_approvals:
            return False

        record = self.pending_approvals[agent_name]
        record["decision"] = {"action": action.upper(), "feedback": feedback}

        if action.upper() == "APPROVE":
            self.update_node_state(agent_name, "BLUE")
            self.log_event(agent_name, f"Analyst APPROVED findings.", level="HITL")
        else:
            self.update_node_state(agent_name, "GREEN")
            self.log_event(agent_name, f"Analyst requested REVISION: {feedback}", level="HITL")

        event: asyncio.Event = record["event"]
        loop = record.get("loop")
        if loop and loop.is_running():
            loop.call_soon_threadsafe(event.set)
        else:
            event.set()

        return True

    _SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def get_all_findings(self, include_deleted: bool = False, include_excluded: bool = False) -> List[Dict[str, Any]]:
        """Aggregate every ForensicAnomaly out of every agent's latest ai_analysis
        plus any manually-added findings for the active investigation, tagged
        with its agent and current approval state, layered with any persisted
        overlay (status/assignment/tags/confidence/cluster), sorted most-severe
        first.

        Approval is read from the node's topology state (BLUE = analyst approved)
        rather than agent_states[...]['status'], since the AgentResponse stored in
        agent_states is snapshotted at PENDING_APPROVAL time and never mutated in
        place once the analyst actually approves -- the node color is the only
        place the post-approval state actually lives.

        Each derived finding gets a stable finding_id (content hash) so overlay
        rows, comments, locks, and IOC/report exports have something durable to
        key on even though the underlying finding itself is recomputed fresh
        every call.
        """
        from db.database import get_session
        from db.models import FindingOverlay, ManualFinding

        findings: List[Dict[str, Any]] = []
        for agent_id, state in self.agent_states.items():
            node = self.nodes.get(agent_id, {})
            ai_analysis = state.get("ai_analysis") or {}
            anomalies = ai_analysis.get("anomalies_found") or []
            if not isinstance(anomalies, list):
                continue
            for anomaly in anomalies:
                if not isinstance(anomaly, dict):
                    continue
                filepath = anomaly.get("filepath")
                anomaly_type = anomaly.get("anomaly_type")
                justification = anomaly.get("justification")
                severity = anomaly.get("severity")
                findings.append({
                    "finding_id": compute_finding_id(agent_id, filepath, anomaly_type, justification),
                    "source": "agent",
                    "agent_id": agent_id,
                    "agent_label": node.get("label", agent_id),
                    "approved": node.get("state") == "BLUE",
                    "node_state": node.get("state", "GRAY"),
                    "filepath": filepath,
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                    "justification": justification,
                    "recommended_action": anomaly.get("recommended_action"),
                    "cluster_key": compute_cluster_key(filepath, anomaly_type),
                })

        with get_session() as session:
            manual_rows = session.query(ManualFinding).filter(
                ManualFinding.case_staging_dir == self.active_investigation_id
            ).all() if self.active_investigation_id else []
            for m in manual_rows:
                findings.append({
                    "finding_id": m.finding_id,
                    "source": "manual",
                    "agent_id": "manual",
                    "agent_label": m.agent_label,
                    "approved": True,
                    "node_state": "BLUE",
                    "filepath": m.filepath,
                    "anomaly_type": m.anomaly_type,
                    "severity": m.severity,
                    "justification": m.justification,
                    "recommended_action": m.recommended_action,
                    "cluster_key": compute_cluster_key(m.filepath, m.anomaly_type),
                    "created_by": m.created_by,
                    "created_at": m.created_at,
                    "artifact_note": m.artifact_note,
                })

            from core.exclusion_engine import get_matcher
            matcher = get_matcher()
            if matcher.rules:
                kept: List[Dict[str, Any]] = []
                for f in findings:
                    excluded, rule_id, reason, action = matcher.evaluate(f)
                    if excluded and action == "hide_completely":
                        continue  # never surfaced, not even in an "include_excluded" view
                    f["excluded"] = excluded
                    f["excluded_by_rule_id"] = rule_id
                    f["excluded_reason"] = reason
                    kept.append(f)
                findings = kept
            else:
                for f in findings:
                    f["excluded"] = False
                    f["excluded_by_rule_id"] = None
                    f["excluded_reason"] = None

            overlays = {
                o.finding_id: o for o in session.query(FindingOverlay).filter(
                    FindingOverlay.finding_id.in_([f["finding_id"] for f in findings])
                ).all()
            } if findings else {}

            for f in findings:
                o = overlays.get(f["finding_id"])
                f["status"] = o.status if o else "new"
                f["assigned_to"] = o.assigned_to if o else None
                f["tags"] = (o.tags or []) if o else []
                f["mitre_techniques"] = (o.mitre_techniques or []) if o else []
                f["confidence"] = o.confidence if (o and o.confidence is not None) else default_confidence_for_severity(f.get("severity"))
                f["dismissed_by"] = o.dismissed_by if o else None
                f["dismissed_reason"] = o.dismissed_reason if o else None
                f["dismissed_at"] = o.dismissed_at if o else None
                if o and o.cluster_id:
                    f["cluster_key"] = o.cluster_id

        # "deleted" (permanent delete, as opposed to soft dismiss/false_positive)
        # is excluded unconditionally -- there is no "show deleted" view, by
        # design. See web/routes.py's /api/findings/delete.
        findings = [f for f in findings if f["status"] != "deleted"]
        if not include_deleted:
            findings = [f for f in findings if f["status"] not in ("dismissed", "false_positive")]
        if not include_excluded:
            findings = [f for f in findings if not f.get("excluded")]

        findings.sort(key=lambda f: self._SEVERITY_RANK.get(str(f.get("severity") or "").strip().upper(), 99))
        return findings

    def get_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        for f in self.get_all_findings(include_deleted=True, include_excluded=True):
            if f["finding_id"] == finding_id:
                return f
        return None

    def get_topology(self) -> Dict[str, Any]:
        nodes_list = list(self.nodes.values())
        links = []
        for n in nodes_list:
            if n["parent"]:
                links.append({"source": n["parent"], "target": n["id"]})
        return {"nodes": nodes_list, "links": links}

    async def wait_if_paused(self):
        if self.is_paused:
            self.log_event("SYSTEM", "Pipeline execution paused by analyst. Waiting for resume...", level="WARN")
            await self.pause_event.wait()

    def set_pause_state(self, pause: bool):
        self.is_paused = pause
        loop = asyncio.get_event_loop()

        if pause:
            self.pipeline_status = "PAUSED"
            if loop.is_running():
                loop.call_soon_threadsafe(self.pause_event.clear)
            else:
                self.pause_event.clear()
            self.log_event("SYSTEM", "Investigation execution PAUSED.", level="WARN")
        else:
            self.pipeline_status = "RUNNING"
            if loop.is_running():
                loop.call_soon_threadsafe(self.pause_event.set)
            else:
                self.pause_event.set()
            self.log_event("SYSTEM", "Investigation execution RESUMED.", level="WARN")

    def get_available_drives(self) -> List[Dict[str, Any]]:
        drives = []
        if sys.platform == 'win32':
            import ctypes
            import string
            bitmask = ctypes.cdll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drive_path = f"{letter}:\\"
                    drives.append({"letter": letter, "path": drive_path, "exists": os.path.exists(drive_path)})
                bitmask >>= 1
        else:
            drives.append({"letter": "ROOT", "path": "/", "exists": True})
        return drives

    def get_existing_investigations(self, search_root=".") -> List[Dict[str, Any]]:
        folders = [Path(p) for p in glob.glob(os.path.join(search_root, "investigation_staging_*"))]
        results = []
        for f in sorted(folders, key=lambda x: x.stat().st_mtime, reverse=True):
            if f.is_dir():
                raw_files = list(f.glob("**/raw/*"))
                meta_files = list(f.glob("**/metadata/*"))
                reports = list(f.glob("*.json"))
                results.append({
                    "folder_name": f.name,
                    "full_path": str(f.resolve().as_posix()),
                    "mtime": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "raw_count": len(raw_files),
                    "meta_count": len(meta_files),
                    "has_master_report": any("Master" in r.name for r in reports)
                })
        return results


bridge = WebHITLBridge()
