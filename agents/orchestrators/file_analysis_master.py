"""
File / Malware Analysis Father Agent.

Execution lifecycle:

    Stage 1 (blocking, always runs, pure automation, zero LLM tokens):
        Static Triage & Capability Mapper
            -> one StaticAnalysisReport per PE/ELF binary found

    Conditional gate: if every binary triaged Clean (no deterministic
    indicators, no CAPA capabilities), Reverse Engineering AND Dynamic
    Sandbox are both skipped entirely -- there is nothing to reverse engineer
    or detonate, and sandbox execution is by far the most expensive/riskiest
    step in this pipeline, exactly the case the brief calls out.

    Stage 2 (only when Stage 1 found something; concurrent via
    asyncio.gather -- both branches depend only on Stage 1's output, not on
    each other, so there is no reason to serialize them):
        Reverse Engineering & String Analyzer   <- independent of Stage 2's sibling
        Dynamic Sandbox Correlator              <- takes the highest-severity
                                                    binary's CAPA capabilities
                                                    from Stage 1, not from RE

Error handling: every MCP call (Ghidra/CAPA/Cuckoo) already degrades to {}
inside mcp_client.call_tool() on any failure (server missing, tool error,
timeout) -- a sub-module never crashes the Father Agent, it just reports
"0 functions analyzed" / "execution_succeeded: False". asyncio.gather(...,
return_exceptions=True) is the second layer: even an unexpected exception in
one Stage-2 branch surfaces as an "ERROR" entry in the compiled report
instead of taking the other branch down with it.
"""
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from core.models import (
    DynamicAnalysisReport, MalwareAnalysisReport, ReverseEngineeringModel, StaticAnalysisReport,
)
from core.utils import locate_staging_directory
from ..file_analysis.dynamic_sandbox import DynamicSandboxCorrelatorAgent
from ..file_analysis.pestudio_analysis import StaticTriageAndCapabilityMapperAgent
from ..file_analysis.reverse_engineering import ReverseEngineeringAndStringAnalyzerAgent

_STATUS_RANK = {"Critical": 2, "Suspicious": 1, "Clean": 0}


class FileAnalysisMaster:
    def __init__(self):
        self.master_name = "File_Analysis_Father_Agent"
        self.static_triage = StaticTriageAndCapabilityMapperAgent()
        self.reverse_engineering = ReverseEngineeringAndStringAnalyzerAgent()
        self.dynamic_sandbox = DynamicSandboxCorrelatorAgent()
        self.sub_agents = [self.static_triage, self.reverse_engineering, self.dynamic_sandbox]

    async def execute_investigation(self, staging_dir: str = None, search_root: str = "."):
        staging_root = locate_staging_directory(search_root=search_root, explicit_path=staging_dir)

        # Stage 1
        static_result = await self.static_triage.process_task(staging_root)
        static_reports = self._extract_static_reports(static_result)

        if not static_reports or all(r.status == "Clean" for r, _ in static_reports):
            skip_reason = (
                "No PE/ELF binaries found." if not static_reports else
                "Every triaged binary was Clean (no deterministic indicators, no CAPA capabilities) -- "
                "Reverse Engineering and Dynamic Sandbox both skipped."
            )
            return self._compile_master_report(
                staging_root=staging_root, static_result=static_result, static_reports=static_reports,
                re_result=None, re_skipped_reason=skip_reason,
                dynamic_result=None, dynamic_skipped_reason=skip_reason,
            )

        # The most severe binary (tie-broken by capability count) is the one
        # worth the expense of dynamic execution -- this pipeline sandboxes
        # the primary suspicious artifact, not every file the collector staged.
        worst_report, worst_path = max(
            static_reports, key=lambda pair: (_STATUS_RANK.get(pair[0].status, 0), len(pair[0].capa_capabilities))
        )

        re_result, dynamic_result = await asyncio.gather(
            self.reverse_engineering.process_task(staging_root),
            self.dynamic_sandbox.process_task(
                staging_root, target_file=worst_path, static_capabilities=worst_report.capa_capabilities
            ),
            return_exceptions=True,
        )

        return self._compile_master_report(
            staging_root=staging_root, static_result=static_result, static_reports=static_reports,
            re_result=re_result, re_skipped_reason=None,
            dynamic_result=dynamic_result, dynamic_skipped_reason=None,
        )

    @staticmethod
    def _extract_static_reports(static_result) -> List[Tuple[StaticAnalysisReport, Path]]:
        entries = static_result.ai_analysis.get("_static_reports", []) if isinstance(static_result.ai_analysis, dict) else []
        out = []
        for entry in entries:
            try:
                out.append((StaticAnalysisReport(**entry["report"]), Path(entry["filepath"])))
            except Exception:
                continue
        return out

    def _compile_master_report(
        self, staging_root: Path, static_result, static_reports,
        re_result, re_skipped_reason: Optional[str],
        dynamic_result, dynamic_skipped_reason: Optional[str],
    ) -> dict:
        detailed_reports = [static_result.dict()]
        total_anomalies = len(static_result.ai_analysis.get("anomalies_found", [])) if isinstance(static_result.ai_analysis, dict) else 0
        critical_findings = [
            {"agent": static_result.agent_name, "finding": a}
            for a in (static_result.ai_analysis.get("anomalies_found", []) if isinstance(static_result.ai_analysis, dict) else [])
            if isinstance(a, dict) and str(a.get("severity", "")).upper() in ("HIGH", "CRITICAL")
        ]

        re_model = None
        if re_result is not None and not isinstance(re_result, Exception):
            detailed_reports.append(re_result.dict())
            anomalies = re_result.ai_analysis.get("anomalies_found", []) if isinstance(re_result.ai_analysis, dict) else []
            total_anomalies += len(anomalies)
            critical_findings += [
                {"agent": re_result.agent_name, "finding": a} for a in anomalies
                if isinstance(a, dict) and str(a.get("severity", "")).upper() in ("HIGH", "CRITICAL")
            ]
            re_model = self._build_re_model(re_result, static_reports)
        elif isinstance(re_result, Exception):
            detailed_reports.append({"agent_name": "Ghidra_Reverse_Engineering_Agent", "status": "ERROR", "error": str(re_result)})

        dynamic_model = None
        if dynamic_result is not None and not isinstance(dynamic_result, Exception):
            detailed_reports.append(dynamic_result.dict())
            anomalies = dynamic_result.ai_analysis.get("anomalies_found", []) if isinstance(dynamic_result.ai_analysis, dict) else []
            total_anomalies += len(anomalies)
            critical_findings += [
                {"agent": dynamic_result.agent_name, "finding": a} for a in anomalies
                if isinstance(a, dict) and str(a.get("severity", "")).upper() in ("HIGH", "CRITICAL")
            ]
            dyn_raw = dynamic_result.ai_analysis.get("_dynamic_report") if isinstance(dynamic_result.ai_analysis, dict) else None
            if dyn_raw:
                dynamic_model = DynamicAnalysisReport(**dyn_raw)
        elif isinstance(dynamic_result, Exception):
            detailed_reports.append({"agent_name": "Dynamic_Sandbox_Correlator", "status": "ERROR", "error": str(dynamic_result)})

        target_file = str(static_reports[0][1]) if static_reports else None
        report = MalwareAnalysisReport(
            orchestrator=self.master_name,
            staging_root=str(staging_root),
            timestamp=datetime.now().isoformat(),
            target_file=target_file,
            static=static_reports[0][0] if static_reports else None,
            reverse_engineering=re_model,
            reverse_engineering_skipped_reason=re_skipped_reason,
            dynamic=dynamic_model,
            dynamic_skipped_reason=dynamic_skipped_reason,
            total_anomalies_flagged=total_anomalies,
            critical_findings=critical_findings,
            detailed_agent_reports=detailed_reports,
        )

        report_path = staging_root / "File_Analysis_Master_Report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report.dict(), f, indent=4, default=str)
        return report.dict()

    @staticmethod
    def _build_re_model(re_result, static_reports) -> Optional[ReverseEngineeringModel]:
        findings = re_result.ai_analysis.get("_function_findings", []) if isinstance(re_result.ai_analysis, dict) else []
        if not findings and not static_reports:
            return None
        filepath = str(static_reports[0][1]) if static_reports else ""
        c2_config = next(
            (f.get("c2_config_extracted") for f in findings if f.get("c2_config_extracted")), None
        )
        functions_total = 0
        try:
            raw = json.loads(re_result.raw_data_parsed)
            functions_total = sum(b.get("functions_total", 0) for b in raw.get("binaries", []))
        except (TypeError, ValueError, AttributeError):
            pass
        return ReverseEngineeringModel(
            filepath=filepath,
            functions_total=functions_total,
            functions_analyzed_by_llm=len(findings),
            high_priority_functions=findings,
            extracted_c2_config=c2_config,
            status="Suspicious" if findings else "Clean",
            summary=re_result.ai_analysis.get("summary", "") if isinstance(re_result.ai_analysis, dict) else "",
        )


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    master = FileAnalysisMaster()
    asyncio.run(master.execute_investigation(staging_dir=explicit_path))
