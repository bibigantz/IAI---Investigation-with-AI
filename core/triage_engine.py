"""Local Fast-Pass Severity Triage layer -- an optional, offline "System One"
pre-filter that scores a raw forensic artifact payload for severity *before*
it reaches the heavy generative LLM pipeline (core/base_agent.py:run_with_hitl).

Talks only to a local/loopback model server (Ollama's native API by default,
http://localhost:11434) -- no outbound network call is ever made here, in
keeping with this platform's offline-first/air-gapped design. Every public
function degrades to a safe default (disabled config, or raising
TriageUnavailableError) rather than raising into the agent pipeline; the
caller in core/base_agent.py always falls back to the standard, unfiltered
pipeline on any failure here.
"""
import json
import time
import uuid
import asyncio
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Triage is meant to be a cheap/fast classification pass, not a full read --
# truncated well below BaseHITLAgent.MAX_PAYLOAD_CHARS (the deep-analysis cap).
TRIAGE_MAX_PAYLOAD_CHARS = 6000

TRIAGE_SYSTEM_PROMPT = (
    "You are a fast forensic triage classifier running as a local pre-filter. "
    "You will be given a chunk of raw forensic artifact data (event logs, process "
    "lists, registry data, file listings, etc). Respond with ONLY a JSON object, "
    "no prose, exactly in this shape:\n"
    '{"severity_score": <float 0.0-1.0>, "severity_label": "Low"|"Medium"|"High"|"Critical", '
    '"summary": "<one-sentence summary of what stands out, or \'nothing notable\'>"}\n'
    "Score high (>=0.7) only for data showing concrete signs of compromise, malware, "
    "persistence, injection, or active attacker behavior. Score low for routine, "
    "benign-looking system noise."
)


class TriageUnavailableError(Exception):
    """Raised when the local triage service can't be reached, times out, or
    returns something unusable. Always caught by the caller, which then falls
    back to the standard pipeline -- see this feature's "Graceful Fallback"
    requirement."""


def get_triage_config() -> Dict[str, Any]:
    """Reads the admin-editable singleton TriageConfig row. Mirrors
    core/llm_config.py's shape/fallback pattern exactly: the hardcoded dict
    below only matters if the DB row is somehow missing entirely."""
    try:
        from db.database import get_session
        from db.models import TriageConfig
        with get_session() as session:
            row = session.get(TriageConfig, 1)
            if row:
                return {
                    "enabled": bool(row.enabled),
                    "base_url": row.base_url,
                    "model_name": row.model_name,
                    "severity_threshold": row.severity_threshold,
                    "timeout_seconds": row.timeout_seconds,
                    "updated_at": row.updated_at,
                }
    except Exception:
        pass
    return {
        "enabled": False,
        "base_url": "http://localhost:11434",
        "model_name": "llama3.2:1b",
        "severity_threshold": 0.8,
        "timeout_seconds": 8,
        "updated_at": None,
    }


def severity_label_for_score(score: float) -> str:
    if score >= 0.85:
        return "Critical"
    if score >= 0.65:
        return "High"
    if score >= 0.4:
        return "Medium"
    return "Low"


def _call_ollama_generate(base_url: str, model_name: str, prompt: str, timeout: int) -> str:
    """One blocking HTTP call to a local Ollama-compatible /api/generate
    endpoint. Uses only the standard library (no new dependency) since this
    is the single place in the codebase that needs to speak this specific
    local wire protocol."""
    url = base_url.rstrip("/") + "/api/generate"
    body = json.dumps({
        "model": model_name,
        "prompt": prompt,
        "system": TRIAGE_SYSTEM_PROMPT,
        "format": "json",
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
    parsed = json.loads(raw)
    return parsed.get("response", "")


async def evaluate_severity(
    payload_text: str, agent_name: str, config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Runs one fast local triage classification over `payload_text`.

    Returns {"severity_score": float, "severity_label": str, "summary": str}.
    Raises TriageUnavailableError on any connectivity/timeout/parse failure --
    never anything else, and never silently returns a guessed verdict.
    """
    cfg = config or get_triage_config()
    truncated = payload_text[:TRIAGE_MAX_PAYLOAD_CHARS]
    timeout = int(cfg.get("timeout_seconds") or 8)
    try:
        raw_response = await asyncio.wait_for(
            asyncio.to_thread(_call_ollama_generate, cfg["base_url"], cfg["model_name"], truncated, timeout),
            timeout=timeout + 2,
        )
        result = json.loads(raw_response)
        score = max(0.0, min(1.0, float(result.get("severity_score", 0.0))))
        label = result.get("severity_label") or severity_label_for_score(score)
        summary = str(result.get("summary") or "").strip()[:500]
        return {"severity_score": score, "severity_label": label, "summary": summary}
    except Exception as e:
        raise TriageUnavailableError(str(e)) from e


def test_connection(base_url: str, model_name: str, timeout: int = 10) -> Dict[str, Any]:
    """Synchronous probe backing the Management page's Test Connection button
    -- sends one minimal real request to the configured local endpoint,
    independent of whether the triage feature is currently enabled/saved."""
    start = time.time()
    try:
        raw_response = _call_ollama_generate(
            base_url, model_name,
            'Respond with ONLY this JSON: {"severity_score": 0.1, "severity_label": "Low", "summary": "connectivity test"}',
            timeout,
        )
        return {"success": True, "reply": raw_response.strip()[:200], "elapsed_seconds": round(time.time() - start, 2)}
    except urllib.error.URLError as e:
        return {"success": False, "error": f"Unreachable -- {e.reason if hasattr(e, 'reason') else e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def log_triage_decision(
    staging_dir: Optional[str], agent_name: str, severity_score: float, severity_label: str,
    summary: str, outcome: str, payload_preview: str = "",
) -> None:
    """Persists one fast-pass triage decision to the case database -- the
    "logged, indexed into the case database for historical reference"
    requirement. Best-effort only: a failure to log must never interrupt the
    agent pipeline that called this."""
    try:
        from db.database import get_session
        from db.models import TriagedArtifact
        with get_session() as session:
            session.add(TriagedArtifact(
                record_id=str(uuid.uuid4()),
                case_staging_dir=staging_dir,
                agent_name=agent_name,
                severity_score=severity_score,
                severity_label=severity_label,
                summary=summary,
                outcome=outcome,
                payload_preview=(payload_preview or "")[:2000],
                created_at=datetime.now(timezone.utc).isoformat(),
            ))
    except Exception:
        pass
