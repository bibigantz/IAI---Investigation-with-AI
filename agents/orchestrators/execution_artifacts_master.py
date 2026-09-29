import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime

from core.utils import locate_staging_directory
from ..windows_forensics.prefetch import PrefetchAgent
from ..windows_forensics.amcache import AmcacheAgent
from ..windows_forensics.shimcache import ShimcacheAgent


class ArtifactsAnalyzerMaster:
    def __init__(self):
        self.master_name = "Master_Execution_Artifacts_Analyzer"
        self.sub_agents = [
            PrefetchAgent(),
            AmcacheAgent(),
            ShimcacheAgent()
        ]

    async def execute_investigation(self, staging_dir: str = None, search_root: str = "."):
        staging_root = locate_staging_directory(search_root=search_root, explicit_path=staging_dir)
        results = []
        for agent in self.sub_agents:
            result = await agent.process_task(staging_root)
            results.append(result)
        return self._compile_master_report(results, staging_root)

    def _cross_reference_sources(self, agent_results: list) -> dict:
        """Prefetch/Amcache/Shimcache all share the ExecutionArtifact schema
        specifically so execution evidence can be correlated across them --
        e.g. a binary Amcache says ran with no corresponding Prefetch entry
        (Prefetch has a limited ~1024-slot rolling window and can age out, or
        be deliberately cleared as anti-forensics)."""
        names_by_source: dict = {"Prefetch": set(), "Amcache": set(), "Shimcache": set()}
        for result in agent_results:
            raw = result.raw_data_parsed
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except json.JSONDecodeError:
                    continue  # payload was truncated or malformed -- skip, don't crash the report
            for art in (raw or {}).get("artifacts", []):
                source = art.get("source")
                name = (art.get("executable_name") or "").lower()
                if source in names_by_source and name:
                    names_by_source[source].add(name)

        return {
            "binary_counts_by_source": {k: len(v) for k, v in names_by_source.items()},
            "amcache_entries_without_prefetch": sorted(names_by_source["Amcache"] - names_by_source["Prefetch"])[:50],
            "shimcache_entries_without_prefetch": sorted(names_by_source["Shimcache"] - names_by_source["Prefetch"])[:50],
        }

    def _compile_master_report(self, agent_results: list, staging_root: Path) -> dict:
        master_report = {
            "orchestrator": self.master_name,
            "staging_root": str(staging_root),
            "timestamp": datetime.now().isoformat(),
            "total_anomalies_flagged": 0,
            "critical_findings": [],
            "cross_reference": self._cross_reference_sources(agent_results),
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
                        "agent": result.agent_name, "finding": anomaly
                    })
        report_path = staging_root / "Execution_Artifacts_Report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(master_report, f, indent=4)
        return master_report


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    master = ArtifactsAnalyzerMaster()
    asyncio.run(master.execute_investigation(staging_dir=explicit_path))
