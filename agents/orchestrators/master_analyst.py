import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime

from core.utils import locate_staging_directory
from core.handoff import iter_anomalies, scan_and_handoff_suspicious_files
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
        """
        Execution order is deliberately Memory -> Windows -> File, not the
        Windows -> File -> Memory order this once was: File_Analysis_Father_
        Agent is the one destination every cross-agent handoff (see
        core/handoff.py) feeds into, so it has to run LAST for a Windows
        Forensics or Memory Analysis finding to be handed off and picked up
        by File Analysis within the SAME investigation run, rather than only
        on a subsequent re-run of the same staging folder.

        Each father agent is awaited inside its own try/except: one father
        crashing must not prevent the other two from running, and must never
        prevent the final executive report from being compiled and written --
        see _compile_executive_intelligence_report(), which always runs.
        """
        staging_root = locate_staging_directory(search_root=search_root, explicit_path=staging_dir)

        investigation_summary = {
            "master_orchestrator": self.master_name,
            "staging_root": str(staging_root),
            "scope": scope,
            "timestamp": datetime.now().isoformat(),
            "father_agent_reports": {},
            "father_agent_errors": {},
            "cross_agent_handoffs": [],
        }

        if scope in ("ALL", "MEMORY"):
            await self._run_father(
                "memory_analysis", self.memory_analysis_father, staging_root, investigation_summary
            )

        if scope in ("ALL", "WINDOWS"):
            await self._run_father(
                "windows_forensics", self.windows_forensics_father, staging_root, investigation_summary
            )

        if scope in ("ALL", "FILE"):
            # No handoff scan after this one -- File Analysis is the terminal
            # destination for every handoff this pipeline currently makes.
            await self._run_father(
                "file_analysis", self.file_analysis_father, staging_root, investigation_summary
            )

        return self._compile_executive_intelligence_report(investigation_summary, staging_root)

    async def _run_father(self, key: str, father, staging_root: Path, investigation_summary: dict):
        try:
            report = await father.execute_investigation(staging_dir=str(staging_root))
            investigation_summary["father_agent_reports"][key] = report
            if key != "file_analysis":
                handoffs = scan_and_handoff_suspicious_files(report, staging_root)
                investigation_summary["cross_agent_handoffs"].extend(handoffs)
        except Exception as e:
            investigation_summary["father_agent_errors"][key] = str(e)
            try:
                from bridge.hitl_bridge import bridge
                bridge.log_event(
                    "MASTER", f"{key} father agent failed: {e} -- continuing with remaining phases.", level="ERROR"
                )
            except Exception:
                pass

    def _compile_executive_intelligence_report(self, summary_data: dict, staging_root: Path) -> dict:
        """Always runs, no matter how many (if any) father agents failed --
        a partial report beats no report. Aggregates counts/critical findings
        across the ENTIRE nested report tree (every father, every sub-master,
        every leaf) rather than just listing each father's own already-
        aggregated numbers, so nothing is double-counted or missed if a
        father's own aggregation logic differs slightly from another's."""
        all_anomalies = list(iter_anomalies(summary_data["father_agent_reports"]))
        summary_data["total_anomalies_flagged"] = len(all_anomalies)
        summary_data["critical_findings"] = [
            {"agent": agent_name, "finding": anomaly}
            for agent_name, anomaly in all_anomalies
            if str(anomaly.get("severity", "")).upper() in ("HIGH", "CRITICAL")
        ]
        if any(str(a.get("severity", "")).upper() == "CRITICAL" for _, a in all_anomalies):
            summary_data["overall_verdict"] = "Critical"
        elif summary_data["critical_findings"]:
            summary_data["overall_verdict"] = "Suspicious"
        elif all_anomalies:
            summary_data["overall_verdict"] = "Suspicious"
        else:
            summary_data["overall_verdict"] = "Clean"

        report_path = staging_root / "Master_Executive_Intelligence_Report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=4, default=str)
        return summary_data


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    scope = sys.argv[2] if len(sys.argv) > 2 else "ALL"
    master = MasterAnalystAgent()
    asyncio.run(master.execute_full_investigation(staging_dir=explicit_path, scope=scope))
