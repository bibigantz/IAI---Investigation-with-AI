"""Central place every agent (and the Findings-page enrichment helper) reads
its LLM endpoint from, backed by the Management page's LLM Provider config
(db.models.LlmProviderConfig, a singleton row). Defaults to a local Ollama
OpenAI-compatible endpoint so a fresh install works with zero external network
access -- this platform is expected to run fully offline."""
from typing import Dict


def get_active_llm_config() -> Dict[str, object]:
    try:
        from db.database import get_session
        from db.models import LlmProviderConfig
        with get_session() as session:
            row = session.get(LlmProviderConfig, 1)
            if row:
                return {
                    "provider_label": row.provider_label,
                    "base_url": row.base_url,
                    "api_key": row.api_key,
                    "model_name": row.model_name,
                    "context_limit": row.context_limit,
                }
    except Exception:
        pass
    return {
        "provider_label": "Local Ollama",
        "base_url": "http://localhost:11434/v1",
        "api_key": "ollama",
        "model_name": "llama3.1",
        "context_limit": 30000,
    }
