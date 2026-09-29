"""Central place every agent (and the Findings-page enrichment helper) reads
its LLM endpoint from, backed by the Management page's LLM Provider config
(db.models.LlmProviderConfig, a singleton row). Defaults to a local Open
WebUI instance's OpenAI-compatible API so a fresh install works with zero
external network access -- this platform is expected to run fully offline
against the offline AI stack Open WebUI provides. The fallback below only
matters if the DB row is somehow missing (e.g. a hand-rolled DB not created
via db.database.init_db()) -- the real, admin-editable defaults live on the
LlmProviderConfig model itself."""
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
        "provider_label": "Open WebUI (offline)",
        "base_url": "http://localhost:3000/api",
        "api_key": "replace-with-your-openwebui-api-key",
        "model_name": "llama3.1",
        "context_limit": 30000,
    }
