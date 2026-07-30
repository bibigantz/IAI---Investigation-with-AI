import asyncio
import os
import sys
import time
import glob
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional


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
                "id": "PeStudio_Static_Triage_Analyzer", "label": "PeStudio Triage Agent",
                "type": "child", "state": "GRAY", "parent": "File_Analysis_Father_Agent",
                "role": "PE Header & CAPA Mapper"
            },
            "Strings_Analyzer": {
                "id": "Strings_Analyzer", "label": "Strings Analyzer Agent",
                "type": "child", "state": "GRAY", "parent": "File_Analysis_Father_Agent",
                "role": "Binary String & IOC Extractor"
            },
            "Ghidra_Reverse_Engineering_Agent": {
                "id": "Ghidra_Reverse_Engineering_Agent", "label": "Ghidra Agent",
                "type": "child", "state": "GRAY", "parent": "File_Analysis_Father_Agent",
                "role": "Headless Decompiler & C2 Logic"
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
                "id": "MalFind_Injected_Code_Analyzer", "label": "MalFind Agent",
                "type": "child", "state": "GRAY", "parent": "Memory_Analysis_Father_Agent",
                "role": "Volatility MalFind Code Injection"
            }
        }

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

    def update_node_state(self, agent_name: str, state: str):
        if agent_name in self.nodes:
            self.nodes[agent_name]["state"] = state
            parent_id = self.nodes[agent_name].get("parent")
            if parent_id and parent_id in self.nodes:
                if state in ["GREEN", "YELLOW"]:
                    self.nodes[parent_id]["state"] = "GREEN"

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
