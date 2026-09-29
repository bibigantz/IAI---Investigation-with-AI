"""
Dynamic Sandbox Correlator & Behavior Evaluator -- Hybrid Automation + LLM.

Automation step: submits the artifact to Cuckoo v3 MCP (or any MCP server
speaking the same 'submit_and_wait' contract -- see mcp_client.CUCKOO_MCP)
and normalizes the behavioral report into BehavioralIOC / NetworkArtifact
records. Then -- the actual "missing feature" this module exists to
implement -- deterministically cross-references what the Static Triage &
Capability Mapper *expected* (its CAPA/MITRE capability list) against what
Cuckoo *actually observed*, producing one StaticDynamicCorrelation per
expected capability: corroborated (with the matching behavior) or not (a
real finding in its own right -- a capability that never fired at runtime is
either a false static positive or a sign the sample detected the sandbox and
didn't run its full payload).

LLM step: exactly one call, over the correlation table plus a bounded
behavioral summary -- asked to explain *why* an uncorroborated capability
might not have fired (anti-sandbox check? unmet C2 dependency? wrong OS/arch?)
and to flag anomalies the deterministic rules don't cover (sleep-heavy
timelines, cleartext C2 payloads, anti-VM artifact checks).
"""
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base_agent import BaseHITLAgent
from core.models import BehavioralIOC, MitreMapping, NetworkArtifact, StaticDynamicCorrelation
from core.utils import locate_staging_directory
from . import mcp_client

AGENT_NAME = "Dynamic_Sandbox_Correlator"

# Points contributed to DynamicAnalysisReport.risk_score by each deterministic
# signal -- same fixed-table philosophy as malfind_correlator.py, so the
# score is auditable rather than an LLM's private judgment call.
POINTS_CORROBORATED_CRITICAL_CAPABILITY = 30
POINTS_UNENCRYPTED_C2_TRAFFIC = 25
POINTS_ANTI_ANALYSIS_DETECTED = 20
POINTS_PROCESS_INJECTION_OBSERVED = 25
POINTS_PERSISTENCE_OBSERVED = 15

SEVERITY_THRESHOLDS = ((70, "Critical"), (45, "High"), (20, "Medium"), (0, "Low"))

# Capability-keyword -> behavioral rule. Each rule is (behavior_keywords,
# checker) where checker(dynamic) returns (observation_str_or_None). Kept as
# simple keyword matching against CAPA rule names / MITRE technique names
# rather than a technique-ID lookup table, since CAPA rule phrasing is more
# consistent across versions than assuming every deployment maps IDs the
# same way.
_INJECTION_TARGETS = {"svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe"}
_PERSISTENCE_REGISTRY_HINTS = ("\\run\\", "\\runonce\\", "currentversion\\run")
_ANTI_ANALYSIS_SIGNATURE_KEYWORDS = ("antisandbox", "anti-sandbox", "antivm", "anti-vm", "antidebug", "sandbox_detect")


def _first(d: Dict[str, Any], *keys: str, default=None):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def normalize_process_tree(cuckoo_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return cuckoo_report.get("process_tree") or cuckoo_report.get("processes") or []


def normalize_behavioral_iocs(cuckoo_report: Dict[str, Any]) -> List[BehavioralIOC]:
    iocs: List[BehavioralIOC] = []
    for f in cuckoo_report.get("dropped_files", []) or []:
        iocs.append(BehavioralIOC(
            ioc_type="file", action="created",
            value=_first(f, "path", "filepath", default=str(f)),
            process_name=_first(f, "process", "process_name"),
            pid=_first(f, "pid"),
            severity="Medium",
        ))
    for r in cuckoo_report.get("registry_modifications", []) or cuckoo_report.get("registry", []) or []:
        key_path = _first(r, "key", "path", default=str(r))
        is_persistence = any(h in key_path.lower() for h in _PERSISTENCE_REGISTRY_HINTS)
        iocs.append(BehavioralIOC(
            ioc_type="registry", action=_first(r, "action", default="modified"),
            value=key_path, process_name=_first(r, "process", "process_name"), pid=_first(r, "pid"),
            severity="High" if is_persistence else "Low",
        ))
    for p in cuckoo_report.get("process_tree", []) or cuckoo_report.get("processes", []) or []:
        iocs.append(BehavioralIOC(
            ioc_type="process", action="spawned",
            value=_first(p, "command_line", "cmdline", default=_first(p, "name", default=str(p))),
            process_name=_first(p, "name", "process_name"), pid=_first(p, "pid"),
            severity="Medium",
        ))
    return iocs


def normalize_network_artifacts(cuckoo_report: Dict[str, Any]) -> List[NetworkArtifact]:
    artifacts: List[NetworkArtifact] = []
    for d in cuckoo_report.get("network", {}).get("dns", []) if isinstance(cuckoo_report.get("network"), dict) else []:
        artifacts.append(NetworkArtifact(protocol="DNS", destination=_first(d, "request", "domain")))
    net = cuckoo_report.get("network") or {}
    for h in (net.get("http") or []):
        dest = _first(h, "host", "dst")
        artifacts.append(NetworkArtifact(
            protocol="HTTPS" if _first(h, "port") == 443 else "HTTP",
            destination=dest, port=_first(h, "port"),
            http_method=_first(h, "method"), http_uri=_first(h, "uri", "path"),
            is_encrypted=_first(h, "port") == 443,
        ))
    for t in (net.get("tcp") or []):
        artifacts.append(NetworkArtifact(
            protocol="TCP", destination=_first(t, "dst"), port=_first(t, "dport", "port"),
        ))
    return artifacts


def _capability_text(capability: MitreMapping) -> str:
    return f"{capability.capability} {capability.technique_name or ''}".lower()


def _text_matches_injection(text: str) -> bool:
    return any(k in text for k in ("inject", "hollow", "t1055"))


def _text_matches_network(text: str) -> bool:
    return any(k in text for k in ("network", "http", "socket", "c2", "command and control", "t1071"))


def _text_matches_persistence(text: str) -> bool:
    return any(k in text for k in ("persist", "registry", "startup", "t1547", "t1053"))


def _capability_matches_injection(capability: MitreMapping) -> bool:
    return _text_matches_injection(_capability_text(capability))


def _capability_matches_network(capability: MitreMapping) -> bool:
    return _text_matches_network(_capability_text(capability))


def _capability_matches_persistence(capability: MitreMapping) -> bool:
    return _text_matches_persistence(_capability_text(capability))


def correlate_static_and_dynamic(
    static_capabilities: List[MitreMapping],
    process_tree: List[Dict[str, Any]],
    behavioral_iocs: List[BehavioralIOC],
    network_artifacts: List[NetworkArtifact],
) -> List[StaticDynamicCorrelation]:
    """Pure function -- no I/O, independently unit-testable. For each static
    capability, deterministically checks whether runtime behavior backs it
    up; an uncorroborated capability is reported, not silently dropped, since
    "static claimed X but nothing at runtime did X" is itself a finding
    (sandbox evasion, wrong environment, or a static false positive)."""
    correlations: List[StaticDynamicCorrelation] = []

    injected_targets_seen = [
        p for p in process_tree
        if str(_first(p, "name", "process_name", default="")).lower() in _INJECTION_TARGETS
        and _first(p, "injected", "is_hollow", default=False)
    ]
    registry_persistence_seen = [i for i in behavioral_iocs if i.ioc_type == "registry" and i.severity == "High"]

    for cap in static_capabilities:
        if _capability_matches_injection(cap):
            if injected_targets_seen:
                target = injected_targets_seen[0]
                correlations.append(StaticDynamicCorrelation(
                    static_capability=cap.capability,
                    dynamic_observation=f"Process hollowing/injection observed into "
                                         f"{_first(target, 'name', 'process_name')} (PID {_first(target, 'pid')})",
                    corroborated=True,
                ))
            else:
                correlations.append(StaticDynamicCorrelation(
                    static_capability=cap.capability, dynamic_observation=None, corroborated=False,
                    discrepancy_note="CAPA flagged injection capability but no process hollowing/injection into a "
                                      "sensitive target was observed at runtime.",
                ))
        elif _capability_matches_network(cap):
            if network_artifacts:
                dest_summary = ", ".join(sorted({a.destination for a in network_artifacts if a.destination})[:5])
                correlations.append(StaticDynamicCorrelation(
                    static_capability=cap.capability,
                    dynamic_observation=f"{len(network_artifacts)} network event(s) observed: {dest_summary}",
                    corroborated=True,
                ))
            else:
                correlations.append(StaticDynamicCorrelation(
                    static_capability=cap.capability, dynamic_observation=None, corroborated=False,
                    discrepancy_note="CAPA flagged network capability but no network traffic was observed -- "
                                      "possible sandbox/environment detection, or a C2 dependency that wasn't met.",
                ))
        elif _capability_matches_persistence(cap):
            if registry_persistence_seen:
                correlations.append(StaticDynamicCorrelation(
                    static_capability=cap.capability,
                    dynamic_observation=f"Persistence registry write observed: {registry_persistence_seen[0].value}",
                    corroborated=True,
                ))
            else:
                correlations.append(StaticDynamicCorrelation(
                    static_capability=cap.capability, dynamic_observation=None, corroborated=False,
                    discrepancy_note="CAPA flagged persistence capability but no Run-key/startup registry write "
                                      "was observed at runtime.",
                ))
        # Capabilities outside the three rule categories above (e.g. anti-
        # debug, crypto) aren't runtime-observable via this behavioral report
        # shape, so they're deliberately left out of the correlation table
        # rather than reported as a spurious "not corroborated".

    return correlations


def detect_anti_analysis(cuckoo_report: Dict[str, Any]) -> List[str]:
    detected = []
    signatures = cuckoo_report.get("signatures", []) or []
    for sig in signatures:
        name = str(_first(sig, "name", "description", default="")).lower()
        if any(k in name for k in _ANTI_ANALYSIS_SIGNATURE_KEYWORDS):
            detected.append(_first(sig, "description", "name"))
    duration = cuckoo_report.get("duration") or cuckoo_report.get("analysis_duration")
    if duration is not None and duration < 5 and not cuckoo_report.get("network"):
        detected.append(f"Execution completed in {duration}s with zero network activity -- possible early exit / sandbox check.")
    return detected


def compute_risk_score(
    correlations: List[StaticDynamicCorrelation],
    anti_analysis: List[str],
    network_artifacts: List[NetworkArtifact],
    behavioral_iocs: List[BehavioralIOC],
) -> int:
    score = 0
    score += sum(POINTS_CORROBORATED_CRITICAL_CAPABILITY for c in correlations if c.corroborated)
    score += POINTS_ANTI_ANALYSIS_DETECTED * min(len(anti_analysis), 2)
    if any(not a.is_encrypted and a.protocol in ("HTTP", "TCP") for a in network_artifacts):
        score += POINTS_UNENCRYPTED_C2_TRAFFIC
    if any(c.corroborated and _text_matches_injection(c.static_capability.lower()) for c in correlations):
        score += POINTS_PROCESS_INJECTION_OBSERVED
    if any(i.ioc_type == "registry" and i.severity == "High" for i in behavioral_iocs):
        score += POINTS_PERSISTENCE_OBSERVED
    return max(0, min(100, score))


def _score_to_severity(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


class DynamicSandboxCorrelatorAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name=AGENT_NAME,
            system_prompt=(
                "You are a Malware Behavior Analyst reviewing a sandbox execution report alongside a "
                "DETERMINISTIC correlation table that already cross-checked each statically-claimed capability "
                "against what was actually observed at runtime -- do not redo that matching. Your job is to: "
                "(1) explain plausible reasons for every entry marked corroborated=false (anti-sandbox detection, "
                "unmet C2 dependency, wrong OS/architecture, or the static capability being a false positive), "
                "(2) flag behavioral anomalies the table doesn't cover -- sandbox-aware sleep/delay loops, "
                "cleartext C2 payloads in HTTP traffic, VM/sandbox artifact checks (registry keys, MAC address "
                "prefixes, process lists), and unusual process trees. "
                "Output strictly valid JSON matching the schema you were given at initialization; every "
                "anomalies_found entry's filepath must be either a static_capability string copied verbatim from "
                "the correlation table, or a short behavior label you invent for something not in that table."
            )
        )

    async def process_task(
        self, staging_root: Path, target_file: Optional[Path] = None,
        static_capabilities: Optional[List[MitreMapping]] = None,
    ) -> Any:
        if target_file is None:
            candidates = list((staging_root / "ProgramDataList" / "raw").glob("*")) if (staging_root / "ProgramDataList" / "raw").is_dir() else []
            target_file = candidates[0] if candidates else None

        if target_file is None:
            return await self.run_with_hitl(
                parsed_tool_data=json.dumps({"error": "No artifact found under ProgramDataList/raw/ to sandbox."})
            )

        cuckoo_report = await mcp_client.call_tool(
            mcp_client.CUCKOO_MCP, "submit_and_wait",
            {"path": str(target_file), "timeout": 120, "os": "windows"},
        )

        process_tree = normalize_process_tree(cuckoo_report)
        behavioral_iocs = normalize_behavioral_iocs(cuckoo_report)
        network_artifacts = normalize_network_artifacts(cuckoo_report)
        anti_analysis = detect_anti_analysis(cuckoo_report)
        correlations = correlate_static_and_dynamic(
            static_capabilities or [], process_tree, behavioral_iocs, network_artifacts
        )
        risk_score = compute_risk_score(correlations, anti_analysis, network_artifacts, behavioral_iocs)

        payload = {
            "target_file": str(target_file),
            "sandbox_task_id": cuckoo_report.get("task_id"),
            "execution_succeeded": bool(cuckoo_report),
            "execution_verdict": cuckoo_report.get("verdict") or cuckoo_report.get("score"),
            "process_tree": process_tree,
            "behavioral_iocs": [i.dict() for i in behavioral_iocs],
            "network_artifacts": [n.dict() for n in network_artifacts],
            "correlations": [c.dict() for c in correlations],
            "anti_analysis_detected": anti_analysis,
            "deterministic_risk_score": risk_score,
        }
        parsed_json_data = self._truncate_payload(json.dumps(payload, default=str))

        response = await self.run_with_hitl(parsed_tool_data=parsed_json_data)

        response.ai_analysis["_dynamic_report"] = {
            "filepath": str(target_file),
            "sandbox_task_id": cuckoo_report.get("task_id"),
            "execution_succeeded": bool(cuckoo_report),
            "execution_verdict": cuckoo_report.get("verdict") or cuckoo_report.get("score"),
            "process_tree": process_tree,
            "behavioral_iocs": [i.dict() for i in behavioral_iocs],
            "network_artifacts": [n.dict() for n in network_artifacts],
            "correlations": [c.dict() for c in correlations],
            "anti_analysis_detected": anti_analysis,
            "risk_score": risk_score,
            "severity": _score_to_severity(risk_score),
            "summary": (
                f"{len(correlations)} static capability correlation(s) checked "
                f"({sum(1 for c in correlations if c.corroborated)} corroborated), "
                f"{len(anti_analysis)} anti-analysis signal(s), risk_score={risk_score}."
            ),
        }
        return response


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = DynamicSandboxCorrelatorAgent()
    asyncio.run(agent.process_task(staging_root))
