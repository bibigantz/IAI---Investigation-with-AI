"""
Injected Code Analyzer -- Hybrid Automation + LLM + Handoff.

Deliberately does NOT re-run windows.malfind.Malfind itself. The Father Agent
runs Malfind_Correlator first (pure automation, zero LLM tokens -- see
malfind_correlator.py) and passes its ranked MalfindCorrelation list in here;
this module spends LLM budget only on the candidates that already cleared the
deterministic bar (score >= 25 / severity Medium+), instead of blindly
re-analyzing every raw malfind hit -- on a busy system that's the difference
between a handful of LLM calls and hundreds.

For every candidate the LLM does NOT dismiss as a false positive (JIT/.NET/
Mono/legitimate self-modifying code) -- and that the analyst then approves
through the normal HITL step -- this module extracts the already-dumped VAD
payload, hashes it, sniffs a PE header, and stages it into ProgramDataList/raw/
so File_Analysis_Father_Agent's PeStudio/Strings agents pick it up on the next
run, with a MalwareHandoffPayload recording exactly what was handed off and why.
"""
import asyncio
import json
import shutil
import sys
from pathlib import Path
from typing import List, Optional

from core.base_agent import BaseHITLAgent
from core.models import AgentResponse, InjectedMemoryRegion, MalfindCorrelation, MalwareHandoffPayload
from core.utils import locate_staging_directory
from . import volatility_runner as vol
from .malfind_correlator import AGENT_NAME as CORRELATOR_AGENT_NAME

AGENT_NAME = "MalFind_Injected_Code_Analyzer"

# Below this deterministic score, a candidate is cheap noise (a bare unbacked
# VAD with no corroboration) -- not worth an LLM call. Matches
# malfind_correlator.SEVERITY_THRESHOLDS' Medium cutoff.
_MIN_SCORE_FOR_LLM_REVIEW = 25


def _candidate_key(c: MalfindCorrelation) -> str:
    """Must exactly match the filepath format Malfind_Correlator uses in its
    own anomalies_found, and the format this module's system prompt instructs
    the LLM to echo back -- this string is the join key between the
    deterministic candidate list and the LLM's per-candidate verdict."""
    return f"PID {c.pid} ({c.process_name or 'unknown'}) @ {c.virtual_address}"


class InjectedCodeAnalyzerAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name=AGENT_NAME,
            system_prompt=(
                "You are a Memory Forensics Specialist reviewing a PRE-FILTERED list of code-injection "
                "candidates. Every candidate already passed a deterministic correlation check (unbacked VAD, "
                "cross-referenced against thread start addresses, remote process handles, and loaded-module "
                "ranges) -- your job is NOT to re-derive that, it's to catch what deterministic rules cannot: "
                "false positives that look identical to real injection at the metadata level. Specifically rule "
                "out JIT-compiled code (Java, .NET CLR, Mono, JavaScript engines, PowerShell AMSI bypass shims), "
                "and legitimate self-modifying/packed code from a signed, well-known application. "
                "For every candidate you judge to be a GENUINE injection, include exactly one entry in "
                "anomalies_found whose 'filepath' field is copied VERBATIM from the candidate's identifier line "
                "(e.g. 'PID 1337 (evil.exe) @ 0x10000'), with anomaly_type set to the specific technique "
                "(e.g. 'Reflective DLL Injection', 'Process Hollowing', 'Shellcode Injection', 'Thread Hijacking'). "
                "For every candidate you judge to be a FALSE POSITIVE, do NOT include it in anomalies_found at "
                "all -- omission IS your false-positive verdict, do not add a Low-severity entry for it instead."
            )
        )

    async def process_task(
        self,
        staging_root: Path,
        correlations: Optional[List[MalfindCorrelation]] = None,
    ) -> AgentResponse:
        image_path = vol.locate_memory_image(staging_root)
        if image_path is None:
            parsed_json_data = json.dumps({"error": "No memory image found under MemoryDumps/raw/"})
            return await self.run_with_hitl(parsed_tool_data=parsed_json_data)

        if correlations is None:
            # Standalone invocation (python -m agents.memory_analysis.malfind) --
            # the Father Agent normally supplies this already-computed list.
            from . import malfind_correlator
            output_dir = staging_root / CORRELATOR_AGENT_NAME / "raw"
            malfind_rows = vol.run_plugin(image_path, "windows.malfind.Malfind", output_dir=output_dir)
            thread_rows = vol.run_plugin(image_path, "windows.thrdscan.ThrdScan")
            handle_rows = vol.run_plugin(image_path, "windows.handles.Handles")
            module_rows = vol.run_plugin(image_path, "windows.dlllist.DllList")
            correlations = malfind_correlator.correlate(malfind_rows, thread_rows, handle_rows, module_rows)

        review_candidates = [c for c in correlations if c.confidence_score >= _MIN_SCORE_FOR_LLM_REVIEW]

        payload = {
            "memory_image": str(image_path),
            "total_malfind_hits": len(correlations),
            "candidates_sent_for_llm_review": len(review_candidates),
            "candidates_skipped_low_confidence": len(correlations) - len(review_candidates),
            "review_candidates": [
                {"identifier": _candidate_key(c), **c.dict()} for c in review_candidates
            ],
        }
        parsed_json_data = self._truncate_payload(json.dumps(payload, default=str))

        response = await self.run_with_hitl(parsed_tool_data=parsed_json_data)

        # Build handoff payloads only for candidates the LLM flagged AND the
        # analyst then approved -- response.status is only "APPROVED" once
        # send_to_dashboard_and_wait() resolves with an APPROVE decision.
        if response.status == "APPROVED":
            confirmed_filepaths = {
                a.get("filepath") for a in response.ai_analysis.get("anomalies_found", [])
                if isinstance(a, dict)
            }
            dump_dir = staging_root / CORRELATOR_AGENT_NAME / "raw"
            analysis_raw_dir = staging_root / "ProgramDataList" / "raw"
            regions: List[InjectedMemoryRegion] = []
            for c in review_candidates:
                key = _candidate_key(c)
                is_confirmed = key in confirmed_filepaths
                handoff = self._build_handoff(c, dump_dir, analysis_raw_dir) if is_confirmed else None
                regions.append(InjectedMemoryRegion(
                    pid=c.pid, process_name=c.process_name, virtual_address=c.virtual_address,
                    protection=c.protection, region_size_bytes=c.region_size_bytes,
                    is_false_positive=not is_confirmed,
                    false_positive_reason=None if is_confirmed else "LLM did not include this candidate in anomalies_found",
                    injection_technique=next(
                        (a.get("anomaly_type") for a in response.ai_analysis.get("anomalies_found", [])
                         if isinstance(a, dict) and a.get("filepath") == key), None
                    ) if is_confirmed else None,
                    confidence=c.severity,
                    handoff=handoff,
                ))
            # Stash for the Father Agent to pull into the master report without
            # re-deriving it -- see memory_analysis_master.py.
            response.ai_analysis["_injected_regions"] = [r.dict() for r in regions]

        return response

    def _build_handoff(
        self, candidate: MalfindCorrelation, dump_dir: Path, analysis_raw_dir: Path
    ) -> Optional[MalwareHandoffPayload]:
        dumped_file = vol.find_malfind_dump(dump_dir, candidate.pid, candidate.virtual_address)
        if dumped_file is None:
            try:
                from bridge.hitl_bridge import bridge
                bridge.log_event(
                    self.agent_name,
                    f"Confirmed injection at PID {candidate.pid} @ {candidate.virtual_address} but no "
                    f"--dump file was found in {dump_dir} -- handoff metadata only, no payload staged.",
                    level="WARN",
                )
            except Exception:
                pass
            return MalwareHandoffPayload(
                dumped_file_path="",
                source_pid=candidate.pid,
                source_process_name=candidate.process_name,
                virtual_address=candidate.virtual_address,
                region_size_bytes=candidate.region_size_bytes,
                protection=candidate.protection,
            )

        staged_path = None
        try:
            analysis_raw_dir.mkdir(parents=True, exist_ok=True)
            dest = analysis_raw_dir / f"memdump_pid{candidate.pid}_{candidate.virtual_address}_{dumped_file.name}"
            shutil.copy2(dumped_file, dest)
            staged_path = str(dest)
            try:
                from bridge.hitl_bridge import bridge
                bridge.log_event(
                    self.agent_name,
                    f"Staged injected-memory dump for PID {candidate.pid} into ProgramDataList/raw/ "
                    f"for File Analysis pipeline pickup.",
                    level="WARN",
                )
            except Exception:
                pass
        except Exception:
            pass

        return MalwareHandoffPayload(
            dumped_file_path=str(dumped_file),
            staged_for_analysis_path=staged_path,
            sha256=vol.sha256_of_file(dumped_file),
            md5=vol.md5_of_file(dumped_file),
            source_pid=candidate.pid,
            source_process_name=candidate.process_name,
            virtual_address=candidate.virtual_address,
            region_size_bytes=candidate.region_size_bytes,
            protection=candidate.protection,
            pe_header_detected=vol.sniff_pe_header(dumped_file),
        )


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = InjectedCodeAnalyzerAgent()
    asyncio.run(agent.process_task(staging_root))
