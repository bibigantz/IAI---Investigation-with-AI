import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime

from core.utils import locate_staging_directory
from .execution_artifacts_master import ArtifactsAnalyzerMaster
from .malware_path_master import CommonMalwarePathsMaster
from ..windows_forensics.evtx_sysmon import EvtxSysmonAgent
from ..windows_forensics.registry_miner import RegistryMinerAgent
from ..windows_forensics.timeline_anomaly import TimelineAnomalyAgent


class WindowsForensicsMaster:
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
        all_reports = []

        artifacts_report = await self.execution_artifacts_master.execute_investigation(staging_dir=str(staging_root))
        all_reports.append({"source": "Execution_Artifacts_SubMaster", "report": artifacts_report})

        malware_paths_report = await self.malware_paths_master.execute_investigation(staging_dir=str(staging_root))
        all_reports.append({"source": "Common_Malware_Paths_SubMaster", "report": malware_paths_report})

        for agent in self.direct_agents:
            res = await agent.process_task(staging_root)
            all_reports.append({"source": agent.agent_name, "report": res.dict()})

        return self._compile_master_report(all_reports, staging_root)

    def _compile_master_report(self, sub_reports: list, staging_root: Path) -> dict:
        master_report = {
            "orchestrator": self.master_name,
            "staging_root": str(staging_root),
            "timestamp": datetime.now().isoformat(),
            "summary_findings": [],
            "sub_reports": sub_reports
        }
        report_path = staging_root / "Windows_Forensics_Master_Report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(master_report, f, indent=4)
        return master_report


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    master = WindowsForensicsMaster()
    asyncio.run(master.execute_investigation(staging_dir=explicit_path))
