import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime

from core.utils import locate_staging_directory
from .windows_forensics_master import WindowsForensicsMaster
from .file_analysis_master import FileAnalysisMaster
from .memory_analysis_master import MemoryAnalysisMaster


class MasterAnalystAgent:
    def __init__(self):
        self.master_name = "Master_Analyst_Agent"
        self.windows_forensics_father = WindowsForensicsMaster()
        self.file_analysis_father = FileAnalysisMaster()
        self.memory_analysis_father = MemoryAnalysisMaster()

    async def execute_full_investigation(self, staging_dir: str = None, search_root: str = ".", scope: str = "ALL"):
        staging_root = locate_staging_directory(search_root=search_root, explicit_path=staging_dir)

        investigation_summary = {
            "master_orchestrator": self.master_name,
            "staging_root": str(staging_root),
            "scope": scope,
            "timestamp": datetime.now().isoformat(),
            "father_agent_reports": {}
        }

        if scope in ["ALL", "WINDOWS"]:
            win_report = await self.windows_forensics_father.execute_investigation(staging_dir=str(staging_root))
            investigation_summary["father_agent_reports"]["windows_forensics"] = win_report

        if scope in ["ALL", "FILE"]:
            file_report = await self.file_analysis_father.execute_investigation(staging_dir=str(staging_root))
            investigation_summary["father_agent_reports"]["file_analysis"] = file_report

        if scope in ["ALL", "MEMORY"]:
            mem_report = await self.memory_analysis_father.execute_investigation(staging_dir=str(staging_root))
            investigation_summary["father_agent_reports"]["memory_analysis"] = mem_report

        return self._compile_executive_intelligence_report(investigation_summary, staging_root)

    def _compile_executive_intelligence_report(self, summary_data: dict, staging_root: Path) -> dict:
        report_path = staging_root / "Master_Executive_Intelligence_Report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=4)
        return summary_data


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    scope = sys.argv[2] if len(sys.argv) > 2 else "ALL"
    master = MasterAnalystAgent()
    asyncio.run(master.execute_full_investigation(staging_dir=explicit_path, scope=scope))
