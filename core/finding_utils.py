"""Pure helper functions backing the Findings page feature set: stable finding
IDs, dedup clustering keys, a local MITRE ATT&CK lookup, PII redaction, report
rendering (JSON/CSV/Markdown), STIX 2.1 export, and pivot/hunt URL building.

Kept separate from web/routes.py so the route file stays a thin list of
endpoints, matching this project's existing "one flat routes.py" convention.
"""
import csv
import hashlib
import io
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------
# Stable finding identity + clustering
# --------------------------------------------------------------------------


def compute_finding_id(agent_id: str, filepath: Optional[str], anomaly_type: Optional[str],
                        justification: Optional[str]) -> str:
    """Deterministic ID for a derived (agent-produced) finding. Derived findings
    have no natural primary key -- they're recomputed from bridge.agent_states
    every request -- so overlay/comment/lock rows need something stable to key
    on. Hashing the content means the same anomaly gets the same ID across
    server restarts as long as the agent's conclusion doesn't change."""
    basis = f"{agent_id}|{filepath or ''}|{anomaly_type or ''}|{justification or ''}"
    return "derived-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


def compute_cluster_key(filepath: Optional[str], anomaly_type: Optional[str]) -> Optional[str]:
    """Default (automatic) dedup group for findings that look like the same
    underlying artifact flagged by more than one agent. Returns None when
    there isn't enough to group on (no filepath)."""
    if not filepath:
        return None
    basis = f"{(anomaly_type or '').strip().lower()}|{filepath.strip().lower()}"
    return "auto-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]


# --------------------------------------------------------------------------
# Confidence heuristic
# --------------------------------------------------------------------------

_SEVERITY_DEFAULT_CONFIDENCE = {"CRITICAL": 90, "HIGH": 75, "MEDIUM": 55, "LOW": 35}


def default_confidence_for_severity(severity: Optional[str]) -> int:
    return _SEVERITY_DEFAULT_CONFIDENCE.get((severity or "").strip().upper(), 50)


# --------------------------------------------------------------------------
# Local MITRE ATT&CK lookup (curated subset relevant to DFIR/malware triage --
# no external ATT&CK STIX bundle is fetched, this is intentionally a small
# static table so tagging works fully offline).
# --------------------------------------------------------------------------

MITRE_TECHNIQUES = {
    "T1055": "Process Injection",
    "T1055.002": "Portable Executable Injection",
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1053.005": "Scheduled Task",
    "T1543.003": "Windows Service",
    "T1059.001": "PowerShell",
    "T1070.004": "File Deletion",
    "T1070.006": "Timestomp",
    "T1071.001": "Web Protocols (C2)",
    "T1041": "Exfiltration Over C2 Channel",
    "T1082": "System Information Discovery",
    "T1112": "Modify Registry",
    "T1129": "Shared Modules",
    "T1204.002": "Malicious File (User Execution)",
    "T1218": "System Binary Proxy Execution",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1562.001": "Disable or Modify Tools",
    "T1105": "Ingress Tool Transfer",
}


def mitre_lookup() -> List[Dict[str, str]]:
    return [{"id": tid, "name": name} for tid, name in sorted(MITRE_TECHNIQUES.items())]


# --------------------------------------------------------------------------
# Pivot & Hunt link building
# --------------------------------------------------------------------------

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,62}){1,}$")


def classify_pivot_value(value: str) -> str:
    if _IPV4_RE.match(value):
        return "ip"
    if _HASH_RE.match(value):
        return "file_hash"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "generic"


_REGISTRY_PREFIX_RE = re.compile(r"^(HKEY_|HKLM|HKCU|HKCR|HKU|HKCC)", re.IGNORECASE)


def classify_ioc_type(value: str) -> str:
    """Best-effort IOC type classification for arbitrary finding values (as
    opposed to classify_pivot_value(), which only recognizes indicator-shaped
    values). Falls back on structural cues -- registry-key prefixes, path
    separators -- rather than string length, since length alone is a
    coincidence, not a signal (a 40-character file path is not a SHA-1)."""
    kind = classify_pivot_value(value)
    if kind != "generic":
        return kind
    if _REGISTRY_PREFIX_RE.match(value):
        return "registry_key"
    if "\\" in value or "/" in value:
        return "file_path"
    return "process_name"


def build_pivot_links(value: str) -> List[Dict[str, str]]:
    """Build hunt/pivot links for one indicator value. The SIEM template is
    read from an env var so this points at whatever SIEM the deployment
    actually has -- there is no bundled SIEM integration in this codebase, so
    without SIEM_QUERY_URL_TEMPLATE configured this falls back to a clearly
    labeled placeholder."""
    kind = classify_pivot_value(value)
    links: List[Dict[str, str]] = []

    siem_template = os.environ.get("SIEM_QUERY_URL_TEMPLATE", "").strip()
    if siem_template:
        links.append({"label": "Query SIEM", "url": siem_template.replace("{value}", value)})
    else:
        links.append({
            "label": "Query SIEM (not configured)",
            "url": "",
            "note": "Set SIEM_QUERY_URL_TEMPLATE env var, e.g. https://siem.example/search?q={value}",
        })

    if kind == "file_hash":
        links.append({"label": "Look up on VirusTotal", "url": f"https://www.virustotal.com/gui/search/{value}"})
    elif kind == "ip":
        links.append({"label": "Look up on VirusTotal", "url": f"https://www.virustotal.com/gui/search/{value}"})
        links.append({"label": "Look up on AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{value}"})
    elif kind == "domain":
        links.append({"label": "Look up on VirusTotal", "url": f"https://www.virustotal.com/gui/search/{value}"})

    return links


# --------------------------------------------------------------------------
# PII redaction (best-effort, regex-based -- for export only)
# --------------------------------------------------------------------------

_USERNAME_PATH_RE = re.compile(r"(Users|home)([\\/])([^\\/]+)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


def redact_pii(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    text = _USERNAME_PATH_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED_USER]", text)
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    return text


def redact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    redacted = dict(finding)
    for field in ("filepath", "justification", "recommended_action"):
        if field in redacted:
            redacted[field] = redact_pii(redacted.get(field))
    return redacted


# --------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------

REPORT_TEMPLATES = {
    "executive_summary": "Executive Summary",
    "technical_forensic": "Technical Forensic Report",
    "incident_summary": "Incident Summary",
    "legal_hold": "Legal Hold Export",
}


def render_report_markdown(findings: List[Dict[str, Any]], template: str, case_label: str,
                            include_chain_of_custody: bool) -> str:
    title = REPORT_TEMPLATES.get(template, "Findings Report")
    lines = [f"# {title}", "", f"**Case:** {case_label}", f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
              f"**Findings included:** {len(findings)}", ""]

    if template == "executive_summary":
        by_sev: Dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "UNKNOWN").upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1
        lines.append("## Severity Breakdown")
        for sev, count in sorted(by_sev.items()):
            lines.append(f"- **{sev}**: {count}")
        lines.append("")
        lines.append("## Key Findings")
        for f in findings:
            if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH"):
                lines.append(f"- **[{f.get('severity')}] {f.get('anomaly_type')}** — {f.get('justification')}")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Findings")
    for f in findings:
        lines.append(f"### {f.get('anomaly_type') or 'Anomaly'} ({f.get('severity') or 'Unknown'})")
        lines.append(f"- **Finding ID:** `{f.get('finding_id')}`")
        lines.append(f"- **Source agent:** {f.get('agent_label') or f.get('agent_id')}")
        if f.get("filepath"):
            lines.append(f"- **Artifact path:** `{f.get('filepath')}`")
        lines.append(f"- **Status:** {f.get('status', 'new')}")
        if f.get("mitre_techniques"):
            techs = ", ".join(f"{t} ({MITRE_TECHNIQUES.get(t, 'Unknown')})" for t in f["mitre_techniques"])
            lines.append(f"- **MITRE ATT&CK:** {techs}")
        lines.append("")
        lines.append(f"**Justification:** {f.get('justification') or ''}")
        lines.append("")
        if f.get("recommended_action"):
            lines.append(f"**Recommended action:** {f.get('recommended_action')}")
            lines.append("")
        if include_chain_of_custody:
            lines.append(f"**Chain of custody:** produced by `{f.get('agent_id')}` "
                          f"({'analyst-approved' if f.get('approved') else 'pending analyst review'}).")
            lines.append("")
        if template == "legal_hold":
            lines.append(f"**Dismissed:** {f.get('dismissed_by') or 'n/a'} — {f.get('dismissed_reason') or 'n/a'}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def render_report_csv(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return ""
    fieldnames = ["finding_id", "agent_label", "severity", "status", "anomaly_type", "filepath",
                  "justification", "recommended_action", "confidence", "mitre_techniques", "tags"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        row = dict(f)
        row["mitre_techniques"] = ";".join(f.get("mitre_techniques") or [])
        row["tags"] = ";".join(f.get("tags") or [])
        writer.writerow(row)
    return buf.getvalue()


# --------------------------------------------------------------------------
# STIX 2.1 / local-IOC export
# --------------------------------------------------------------------------

def _file_path_pattern(v: str) -> str:
    basename = v.replace("/", "\\").rsplit("\\", 1)[-1]
    return f"[file:name = '{basename}']"


_STIX_PATTERN_BUILDERS = {
    "ip": lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url": lambda v: f"[url:value = '{v}']",
    "file_hash": lambda v: f"[file:hashes.'SHA-256' = '{v}']" if len(v) == 64 else f"[file:hashes.MD5 = '{v}']",
    "registry_key": lambda v: f"[windows-registry-key:key = '{v}']",
    "process_name": lambda v: f"[process:name = '{v}']",
    "mutex": lambda v: f"[mutex:name = '{v}']",
    "email": lambda v: f"[email-addr:value = '{v}']",
    "file_path": _file_path_pattern,
}


def build_stix_bundle(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a STIX 2.1 bundle from local IOC rows. Uses the `stix2` library's
    generic Indicator/Bundle constructors rather than pushing anywhere -- this
    deployment has no live MISP/TAXII server to publish to."""
    from stix2 import Indicator, Bundle

    objects = []
    for ioc in iocs:
        builder = _STIX_PATTERN_BUILDERS.get(ioc["ioc_type"])
        if not builder:
            continue
        description = ioc.get("notes") or f"Source finding: {ioc.get('source_finding_id')}"
        description += f" [TLP:{ioc.get('tlp', 'amber').upper()}, added {ioc.get('added_at', '')} by {ioc.get('added_by', 'unknown')}]"
        objects.append(Indicator(
            pattern=builder(ioc["value"]),
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            description=description,
        ))
    bundle = Bundle(objects=objects)
    return bundle.serialize(pretty=True)


# --------------------------------------------------------------------------
# Agent enrichment ("Deep Analyze with Agent")
# --------------------------------------------------------------------------

_ENRICHMENT_PROMPTS = {
    "deep_analyze": (
        "Re-examine this finding in more depth than your first pass. Look for additional "
        "corroborating detail in the raw data, alternate interpretations, and anything that "
        "would raise or lower confidence. If you find something new, add it as an additional "
        "entry in anomalies_found; otherwise return the same anomaly with a more detailed "
        "justification."
    ),
    "rescan": (
        "Assume the underlying artifact may have changed since your last pass. Re-derive your "
        "conclusion from the raw data provided as if seeing it for the first time, and flag any "
        "discrepancy with your prior conclusion explicitly in the justification."
    ),
    "reputation_lookup": (
        "Focus specifically on any IPs, domains, hashes, or filenames in this finding and note "
        "which of them are worth checking against external threat intelligence, and why."
    ),
}


async def run_deep_analysis(agent_label: str, raw_data_parsed: Any, prior_ai_analysis: Dict[str, Any],
                             action: str = "deep_analyze") -> Dict[str, Any]:
    """Re-run the LLM analysis step for one agent's already-collected raw data
    with a deeper/targeted prompt. Mirrors core/base_agent.py's LLM call setup
    exactly (same client/model/env vars) so enrichment results are produced
    the same way the original analysis was."""
    import json as _json
    from openai import AsyncOpenAI
    from .models import AgentAnalysisReport
    from .llm_config import get_active_llm_config

    llm_config = get_active_llm_config()
    client = AsyncOpenAI(api_key=llm_config["api_key"], base_url=llm_config["base_url"])
    model_name = llm_config["model_name"]
    instruction = _ENRICHMENT_PROMPTS.get(action, _ENRICHMENT_PROMPTS["deep_analyze"])

    messages = [
        {"role": "system", "content": (
            f"You are {agent_label}, performing a deeper follow-up analysis at an analyst's request. "
            f"You must output strictly valid JSON matching this schema:\n{AgentAnalysisReport.schema_json()}"
        )},
        {"role": "user", "content": (
            f"Original raw data:\n{str(raw_data_parsed)[:20000]}\n\n"
            f"Your prior analysis:\n{_json.dumps(prior_ai_analysis)[:8000]}\n\n"
            f"Task: {instruction}"
        )},
    ]

    try:
        response = await client.chat.completions.create(
            model=model_name, messages=messages, response_format={"type": "json_object"}, temperature=0.1,
        )
        return _json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"error": "Failed to generate deep analysis", "raw_exception": str(e)}


def build_misp_shaped_json(iocs: List[Dict[str, Any]], event_info: str) -> Dict[str, Any]:
    """A MISP Event-shaped JSON document (Attributes list) -- importable into
    a real MISP instance via its 'Add Event from file' flow, without this app
    needing direct MISP API credentials."""
    return {
        "Event": {
            "info": event_info,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "threat_level_id": "2",
            "analysis": "1",
            "Attribute": [
                {
                    "type": {"file_hash": "sha256", "ip": "ip-dst", "domain": "domain",
                              "registry_key": "regkey", "process_name": "text", "file_path": "filename",
                              "mutex": "mutex", "email": "email-src", "url": "url"}.get(ioc["ioc_type"], "text"),
                    "category": "Network activity" if ioc["ioc_type"] in ("ip", "domain", "url") else "Artifacts dropped",
                    "value": ioc["value"],
                    "to_ids": True,
                    "comment": ioc.get("notes") or "",
                }
                for ioc in iocs
            ],
        }
    }
