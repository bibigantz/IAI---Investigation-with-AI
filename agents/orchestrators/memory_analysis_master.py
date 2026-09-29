"""
Memory Analysis Father Agent.

Execution lifecycle (see docstrings on each sub-module for why):

    Stage 1 (must run first, deterministic, zero LLM tokens):
        Malfind_Correlator  -- scores every raw malfind hit against
                                threads/handles/loaded-modules

    Stage 2 (Stage 1's output feeds Injected Code Analyzer; the other two
             sub-modules are fully independent of Stage 1 and of each other
             -- all three run concurrently via asyncio.gather):
        Injected Code Analyzer  <- consumes Stage 1's ranked candidates
        Process & Thread Mapper <- independent evidence source
        Network Socket Correlator <- independent evidence source

This is the first orchestrator in the codebase to actually run its sub-agents
concurrently (every sibling Father/Master orchestrator awaits its children
strictly sequentially -- see ARCHITECTURE.md's known-gaps list). It's safe to
do here specifically because Stage 2's three agents don't share mutable state
with each other (each pulls its own Volatility3 rows and drives its own HITL
node independently through the bridge) -- Stage 1 -> Stage 2 stays a real
dependency, not something concurrency would break.
"""
import asyncio
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List

from core.models import (
    InjectedMemoryRegion, MalfindCorrelation, MalwareHandoffPayload, MemoryAnalysisReport,
    ProcessAnomaly, ProcessTreeFinding, SocketCorrelation,
)
from core.utils import locate_staging_directory
from ..memory_analysis import volatility_runner as vol
from ..memory_analysis.malfind import InjectedCodeAnalyzerAgent
from ..memory_analysis.malfind_correlator import MalfindCorrelatorAgent
from ..memory_analysis.network import NetworkSocketCorrelatorAgent
from ..memory_analysis.pstree import ProcessTreeMapperAgent


class MemoryAnalysisMaster:
    def __init__(self):
        self.master_name = "Memory_Analysis_Father_Agent"
        self.malfind_correlator = MalfindCorrelatorAgent()
        self.injected_code_analyzer = InjectedCodeAnalyzerAgent()
        self.process_mapper = ProcessTreeMapperAgent()
        self.network_correlator = NetworkSocketCorrelatorAgent()
        # Kept for introspection/tests -- NOT iterated sequentially like the
        # sibling orchestrators' self.sub_agents; see execute_investigation().
        self.sub_agents = [
            self.malfind_correlator, self.injected_code_analyzer,
            self.process_mapper, self.network_correlator,
        ]

    async def execute_investigation(self, staging_dir: str = None, search_root: str = "."):
        staging_root = locate_staging_directory(search_root=search_root, explicit_path=staging_dir)
        image_path = vol.locate_memory_image(staging_root)

        # Stage 1
        malfind_result = await self.malfind_correlator.process_task(staging_root)
        correlations = self._extract_correlations(malfind_result)

        # Stage 2 -- concurrent. A failure in one must not take the others
        # down: return_exceptions=True, then each result is checked below.
        injected_result, process_result, network_result = await asyncio.gather(
            self.injected_code_analyzer.process_task(staging_root, correlations=correlations),
            self.process_mapper.process_task(staging_root),
            self.network_correlator.process_task(staging_root),
            return_exceptions=True,
        )

        return self._compile_master_report(
            staging_root=staging_root,
            image_path=image_path,
            malfind_result=malfind_result,
            injected_result=injected_result,
            process_result=process_result,
            network_result=network_result,
            correlations=correlations,
        )

    @staticmethod
    def _extract_correlations(malfind_result) -> List[MalfindCorrelation]:
        raw = malfind_result.raw_data_parsed
        if not isinstance(raw, dict):
            return []
        return [MalfindCorrelation(**row) for row in raw.get("correlations", [])]

    def _compile_master_report(
        self, staging_root: Path, image_path, malfind_result,
        injected_result, process_result, network_result, correlations: List[MalfindCorrelation],
    ) -> dict:
        detailed_reports = []
        total_anomalies = 0
        critical_findings = []

        agent_results = {
            "Malfind_Correlator": malfind_result,
            "MalFind_Injected_Code_Analyzer": injected_result,
            "PsTree_Process_Mapper": process_result,
            "Network_Socket_Correlator": network_result,
        }
        for agent_name, result in agent_results.items():
            if isinstance(result, Exception):
                detailed_reports.append({"agent_name": agent_name, "status": "ERROR", "error": str(result)})
                continue
            report_dict = result.dict()
            detailed_reports.append(report_dict)
            anomalies = result.ai_analysis.get("anomalies_found", []) if isinstance(result.ai_analysis, dict) else []
            total_anomalies += len(anomalies)
            for anomaly in anomalies:
                if isinstance(anomaly, dict) and str(anomaly.get("severity", "")).upper() in ("HIGH", "CRITICAL"):
                    critical_findings.append({"agent": result.agent_name, "finding": anomaly})

        process_tree = self._build_process_tree_finding(process_result)
        socket_correlation = self._build_socket_correlation(network_result)
        handoffs = self._extract_handoffs(injected_result)
        injected_regions = self._extract_injected_regions(injected_result)

        report = MemoryAnalysisReport(
            orchestrator=self.master_name,
            staging_root=str(staging_root),
            timestamp=datetime.now().isoformat(),
            memory_image=str(image_path) if image_path else None,
            process_tree=process_tree,
            injected_regions=injected_regions,
            malfind_correlations=correlations,
            socket_correlation=socket_correlation,
            total_anomalies_flagged=total_anomalies,
            critical_findings=critical_findings,
            handoffs_to_malware_analysis=handoffs,
            detailed_agent_reports=detailed_reports,
        )

        report_path = staging_root / "Memory_Analysis_Master_Report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report.dict(), f, indent=4, default=str)
        return report.dict()

    @staticmethod
    def _build_process_tree_finding(process_result):
        if isinstance(process_result, Exception):
            return None
        try:
            payload = json.loads(process_result.raw_data_parsed)
        except (TypeError, ValueError):
            return None

        anomalies = [ProcessAnomaly(**a) for a in payload.get("automation_flagged_parent_anomalies", [])]
        # Fold in anything the LLM caught that the fixed rule table didn't --
        # ForensicAnomaly has no 'pid' field, so best-effort-parse it back out
        # of the filepath text the LLM was asked to report against.
        llm_anomalies = process_result.ai_analysis.get("anomalies_found", []) if isinstance(process_result.ai_analysis, dict) else []
        for a in llm_anomalies:
            if not isinstance(a, dict):
                continue
            filepath = str(a.get("filepath", ""))
            match = re.search(r"PID\s+(\d+)\s*(?:\(([^)]*)\))?", filepath, re.IGNORECASE)
            anomalies.append(ProcessAnomaly(
                pid=int(match.group(1)) if match else -1,
                process_name=match.group(2) if match and match.group(2) else None,
                ppid=None,
                anomaly_type=a.get("anomaly_type", "LLM-Flagged Anomaly"),
                detail=a.get("justification", ""),
                severity=a.get("severity", "Medium"),
            ))

        return ProcessTreeFinding(
            total_processes=payload.get("total_processes", 0),
            hidden_or_unlinked_pids=payload.get("automation_flagged_hidden_pids", []),
            anomalies=anomalies,
            anomaly_score=payload.get("automation_anomaly_score", 0.0),
            process_tree=payload.get("process_tree", []),
        )

    @staticmethod
    def _build_socket_correlation(network_result):
        if isinstance(network_result, Exception):
            return None
        raw = network_result.raw_data_parsed
        if not isinstance(raw, dict) or "socket_correlation" not in raw:
            return None
        return SocketCorrelation(**raw["socket_correlation"])

    @staticmethod
    def _extract_handoffs(injected_result) -> List[MalwareHandoffPayload]:
        if isinstance(injected_result, Exception):
            return []
        regions = injected_result.ai_analysis.get("_injected_regions", []) if isinstance(injected_result.ai_analysis, dict) else []
        return [MalwareHandoffPayload(**r["handoff"]) for r in regions if r.get("handoff")]

    @staticmethod
    def _extract_injected_regions(injected_result):
        if isinstance(injected_result, Exception):
            return []
        regions = injected_result.ai_analysis.get("_injected_regions", []) if isinstance(injected_result.ai_analysis, dict) else []
        return [InjectedMemoryRegion(**r) for r in regions]


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    master = MemoryAnalysisMaster()
    asyncio.run(master.execute_investigation(staging_dir=explicit_path))
