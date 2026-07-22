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
from windows_forensics_master import WindowsForensicsMaster
from file_analysis_master import FileAnalysisMaster
from memory_analysis_master import MemoryAnalysisMaster


class MasterAnalystAgent:
    """
    Top-Level Orchestrator: Master Analyst Agent
    
    Orchestrates the entire multi-agent DFIR framework across:
    1. Windows Forensics Father Agent (Disk, Artifacts, Persistence, EVTX, Timeline)
    2. File / Malware Analysis Father Agent (Static Triage, Strings, Ghidra)
    3. Memory Analysis Father Agent (Volatility PsTree, NetScan, MalFind)
    
    Synthesizes all findings into a unified, high-assurance Executive Intelligence Report.
    """
    def __init__(self):
        self.master_name = "Master_Analyst_Agent"
        self.windows_forensics_father = WindowsForensicsMaster()
        self.file_analysis_father = FileAnalysisMaster()
        self.memory_analysis_father = MemoryAnalysisMaster()

    async def execute_full_investigation(self, staging_dir: str = None, search_root: str = ".", scope: str = "ALL"):
        staging_root = locate_staging_directory(search_root=search_root, explicit_path=staging_dir)

        print(f"\n{'='*80}")
        print(f"[{self.master_name}] Initiating FULL DFIR SYSTEM INVESTIGATION")
        print(f"Target Staging Directory: {staging_root}")
        print(f"Investigation Scope: {scope}")
        print(f"{'='*80}\n")

        investigation_summary = {
            "master_orchestrator": self.master_name,
            "staging_root": str(staging_root),
            "scope": scope,
            "timestamp": datetime.now().isoformat(),
            "father_agent_reports": {}
        }

        # 1. Execute Windows Forensics Pipeline
        if scope in ["ALL", "WINDOWS"]:
            print(f"\n>>> Step 1/3: Running Windows Forensics Father Agent...")
            win_report = await self.windows_forensics_father.execute_investigation(staging_dir=str(staging_root))
            investigation_summary["father_agent_reports"]["windows_forensics"] = win_report
        else:
            print(f"\n>>> Skipping Step 1/3: Windows Forensics (Scope: {scope})")

        # 2. Execute File / Malware Analysis Pipeline
        if scope in ["ALL", "FILE"]:
            print(f"\n>>> Step 2/3: Running File / Malware Analysis Father Agent...")
            file_report = await self.file_analysis_father.execute_investigation(staging_dir=str(staging_root))
            investigation_summary["father_agent_reports"]["file_analysis"] = file_report
        else:
            print(f"\n>>> Skipping Step 2/3: File Analysis (Scope: {scope})")

        # 3. Execute Memory Analysis Pipeline
        if scope in ["ALL", "MEMORY"]:
            print(f"\n>>> Step 3/3: Running Memory Analysis Father Agent...")
            mem_report = await self.memory_analysis_father.execute_investigation(staging_dir=str(staging_root))
            investigation_summary["father_agent_reports"]["memory_analysis"] = mem_report
        else:
            print(f"\n>>> Skipping Step 3/3: Memory Analysis (Scope: {scope})")

        return self._compile_executive_intelligence_report(investigation_summary, staging_root)

    def _compile_executive_intelligence_report(self, summary_data: dict, staging_root: Path) -> dict:
        print(f"\n[{self.master_name}] Compiling Master Executive Intelligence Report...")

        folder_name = staging_root.name
        parts = folder_name.split('_')
        investigation_id = '_'.join(parts[-2:]) if len(parts) >= 2 else folder_name

        report_path = staging_root / "Master_Executive_Intelligence_Report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=4)

        print(f"\n{'='*80}")
        print(f"[{self.master_name}] INVESTIGATION COMPLETE!")
        print(f"Master Executive Report saved to: {report_path}")
        print(f"{'='*80}\n")
        return summary_data


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    scope = sys.argv[2] if len(sys.argv) > 2 else "ALL"
    master = MasterAnalystAgent()
    asyncio.run(master.execute_full_investigation(staging_dir=explicit_path, scope=scope))
