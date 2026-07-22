import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime

from core_agents import locate_staging_directory
from prefetch_agent import PrefetchAgent
from amcache_agent import AmcacheAgent
from shimcache_agent import ShimcacheAgent


class ArtifactsAnalyzerMaster:
    """
    Sub-Master / Father Agent for Execution Artifacts Analysis
    Developer Owner: [ G ]
    
    Orchestrates Prefetch, Amcache, and Shimcache child agents to deliver a unified
    execution timeline and anomaly summary.
    """
    def __init__(self):
        self.master_name = "Master_Execution_Artifacts_Analyzer"
        self.sub_agents = [
            PrefetchAgent(),
            AmcacheAgent(),
            ShimcacheAgent()
        ]

    async def execute_investigation(self, staging_dir: str = None, search_root: str = "."):
        staging_root = locate_staging_directory(search_root=search_root, explicit_path=staging_dir)

        print(f"\n{'='*60}")
        print(f"[{self.master_name}] Initiating Execution Artifacts Swarm")
        print(f"Target Directory: {staging_root}")
        print(f"{'='*60}\n")

        results = []
        for agent in self.sub_agents:
            print(f"Executing {agent.agent_name}...")
            result = await agent.process_task(staging_root)
            results.append(result)

        return self._compile_master_report(results, staging_root)

    def _compile_master_report(self, agent_results: list, staging_root: Path) -> dict:
        print(f"\n[{self.master_name}] Sub-agents complete. Aggregating execution artifacts findings...")

        folder_name = staging_root.name
        parts = folder_name.split('_')
        investigation_id = '_'.join(parts[-2:]) if len(parts) >= 2 else folder_name

        master_report = {
            "investigation_id": investigation_id,
            "orchestrator": self.master_name,
            "staging_root": str(staging_root),
            "timestamp": datetime.now().isoformat(),
            "total_anomalies_flagged": 0,
            "critical_findings": [],
            "detailed_agent_reports": []
        }

        for result in agent_results:
            report_dict = result.dict()
            master_report["detailed_agent_reports"].append(report_dict)

            anomalies = result.ai_analysis.get("anomalies_found", [])
            master_report["total_anomalies_flagged"] += len(anomalies)

            for anomaly in anomalies:
                if anomaly.get("severity", "").upper() in ["HIGH", "CRITICAL"]:
                    master_report["critical_findings"].append({
                        "agent": result.agent_name,
                        "finding": anomaly
                    })

        report_path = staging_root / "Execution_Artifacts_Report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(master_report, f, indent=4)

        print(f"[{self.master_name}] Report saved to: {report_path}")
        return master_report


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    master = ArtifactsAnalyzerMaster()
    asyncio.run(master.execute_investigation(staging_dir=explicit_path))
