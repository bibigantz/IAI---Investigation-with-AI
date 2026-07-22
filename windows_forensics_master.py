import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime

# Prevent cp1252 encoding errors on Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

from core_agents import locate_staging_directory
from execution_artifacts_master import ArtifactsAnalyzerMaster
from malware_path_master import CommonMalwarePathsMaster
from evtx_sysmon_agent import EvtxSysmonAgent
from registry_miner_agent import RegistryMinerAgent
from timeline_anomaly_agent import TimelineAnomalyAgent


class WindowsForensicsMaster:
    """
    Windows Forensics Father Agent
    Developer Owner: [ Y / G / N ]
    
    Orchestrates the entire Windows disk & OS forensic investigation:
    1. Collector Automation (triage & raw evidence staging)
    2. Artifacts Analyzer Master (Prefetch, Amcache, Shimcache)
    3. Common Malware Paths Master (Temp, Downloads, ProgramData, Scheduled Tasks, Services, Drivers, Autoruns)
    4. EVTX & Sysmon Correlator Agent
    5. Registry Hive Miner Agent
    6. Timeline Anomaly Detector Agent
    """
    def __init__(self):
        self.master_name = "Windows_Forensics_Father_Agent"
        self.execution_artifacts_master = ArtifactsAnalyzerMaster()
        self.malware_paths_master = CommonMalwarePathsMaster()
        self.direct_agents = [
            EvtxSysmonAgent(),
            RegistryMinerAgent(),
            TimelineAnomalyAgent()
        ]

    async def execute_investigation(self, staging_dir: str = None, search_root: str = "."):
        staging_root = locate_staging_directory(search_root=search_root, explicit_path=staging_dir)

        print(f"\n{'='*70}")
        print(f"[{self.master_name}] Initiating Windows Forensics Master Analysis Pipeline")
        print(f"Target Directory: {staging_root}")
        print(f"{'='*70}\n")

        all_reports = []

        # 1. Run Execution Artifacts Sub-Master
        print(f"[{self.master_name}] Invoking Execution Artifacts Sub-Master...")
        artifacts_report = await self.execution_artifacts_master.execute_investigation(staging_dir=str(staging_root))
        all_reports.append({"source": "Execution_Artifacts_SubMaster", "report": artifacts_report})

        # 2. Run Common Malware Paths Sub-Master
        print(f"[{self.master_name}] Invoking Common Malware Paths Sub-Master...")
        malware_paths_report = await self.malware_paths_master.execute_investigation(staging_dir=str(staging_root))
        all_reports.append({"source": "Common_Malware_Paths_SubMaster", "report": malware_paths_report})

        # 3. Run Direct Child Agents (EVTX, Registry, Timeline)
        for agent in self.direct_agents:
            print(f"[{self.master_name}] Executing {agent.agent_name}...")
            res = await agent.process_task(staging_root)
            all_reports.append({"source": agent.agent_name, "report": res.dict()})

        return self._compile_master_report(all_reports, staging_root)

    def _compile_master_report(self, sub_reports: list, staging_root: Path) -> dict:
        print(f"\n[{self.master_name}] Compiling comprehensive Windows Forensics Master Report...")

        folder_name = staging_root.name
        parts = folder_name.split('_')
        investigation_id = '_'.join(parts[-2:]) if len(parts) >= 2 else folder_name

        master_report = {
            "investigation_id": investigation_id,
            "orchestrator": self.master_name,
            "staging_root": str(staging_root),
            "timestamp": datetime.now().isoformat(),
            "summary_findings": [],
            "sub_reports": sub_reports
        }

        report_path = staging_root / "Windows_Forensics_Master_Report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(master_report, f, indent=4)

        print(f"[{self.master_name}] Investigation Complete. Windows Forensics Master Report saved to: {report_path}")
        return master_report


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    master = WindowsForensicsMaster()
    asyncio.run(master.execute_investigation(staging_dir=explicit_path))
