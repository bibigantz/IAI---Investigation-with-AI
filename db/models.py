import time
from sqlalchemy import Column, String, Float, Integer, Boolean, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# Overlay/lock rows are only considered "live" for this many seconds without a
# fresh heartbeat -- keeps a crashed tab from holding a finding locked forever.
LOCK_TTL_SECONDS = 25


class FindingOverlay(Base):
    """Mutable analyst-driven state layered onto a derived (agent-produced) or
    manual finding. Derived findings themselves are never persisted -- they're
    recomputed from bridge.agent_states on every request -- so this table is
    the only durable record of status/assignment/tags/dismissal/etc."""
    __tablename__ = "finding_overlays"

    finding_id = Column(String, primary_key=True)
    status = Column(String, default="new", nullable=False)
    assigned_to = Column(String, nullable=True)
    tags = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    confidence = Column(Float, nullable=True)
    cluster_id = Column(String, nullable=True)
    dismissed_by = Column(String, nullable=True)
    dismissed_reason = Column(String, nullable=True)
    dismissed_at = Column(String, nullable=True)
    updated_at = Column(String, nullable=True)


class ManualFinding(Base):
    """An analyst-authored finding, not derived from any agent run (e.g. notes
    from manual memory inspection or offline registry analysis)."""
    __tablename__ = "manual_findings"

    finding_id = Column(String, primary_key=True)
    case_staging_dir = Column(String, nullable=True)
    agent_label = Column(String, default="Manual Entry")
    filepath = Column(String, nullable=True)
    anomaly_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    justification = Column(String, nullable=False)
    recommended_action = Column(String, default="")
    artifact_note = Column(String, nullable=True)
    created_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)


class LocalIOC(Base):
    """A locally-tracked Indicator of Compromise saved off a finding. No live
    MISP instance exists in this deployment -- export() converts these into a
    STIX 2.1 bundle / CSV / MISP-shaped JSON on demand rather than pushing to
    an external server."""
    __tablename__ = "iocs"

    ioc_id = Column(String, primary_key=True)
    ioc_type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    source_finding_id = Column(String, nullable=True)
    case_staging_dir = Column(String, nullable=True)
    tlp = Column(String, default="amber")
    added_by = Column(String, nullable=False)
    added_at = Column(String, nullable=False)
    notes = Column(String, nullable=True)


class AuditLogEntry(Base):
    """Durable audit trail for finding-level actions (dismiss/restore/assign/
    enrich/comment/...). Mirrors bridge.log_event()'s role for pipeline events,
    but scoped to findings and queryable per finding_id."""
    __tablename__ = "finding_audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    reason = Column(String, nullable=True)
    timestamp = Column(String, nullable=False)
    details = Column(JSON, nullable=True)


class EnrichmentJob(Base):
    """One 'Deep Analyze with Agent' run. Executed the same way investigations
    already are -- a background threading.Thread, polled for status -- since
    this codebase has no job queue or websocket infrastructure."""
    __tablename__ = "enrichment_jobs"

    job_id = Column(String, primary_key=True)
    finding_id = Column(String, nullable=False, index=True)
    agent_id = Column(String, nullable=False)
    action = Column(String, nullable=False)
    status = Column(String, default="queued")
    submitted_at = Column(String, nullable=False)
    completed_at = Column(String, nullable=True)
    result_summary = Column(String, nullable=True)
    error = Column(String, nullable=True)


class SavedView(Base):
    """A persisted filter combination for the Findings triage list."""
    __tablename__ = "saved_views"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    filters = Column(JSON, default=dict)
    created_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)


class FindingLock(Base):
    """Poll-based 'someone else is looking at this' presence indicator.
    Refreshed by a heartbeat call while a finding's detail drawer is open;
    treated as stale (and ignorable) after LOCK_TTL_SECONDS with no heartbeat.
    There is no websocket/push layer in this app, so this is deliberately a
    polling primitive rather than a real-time lock -- it prevents accidental
    double-dismissal in practice without adding new server infrastructure."""
    __tablename__ = "finding_locks"

    finding_id = Column(String, primary_key=True)
    locked_by = Column(String, nullable=False)
    locked_at = Column(Float, nullable=False)

    def is_stale(self) -> bool:
        return (time.time() - self.locked_at) > LOCK_TTL_SECONDS


class FindingComment(Base):
    """A free-text analyst note/comment thread on a finding -- the
    collaborative-analysis equivalent of the bridge's HITL feedback log."""
    __tablename__ = "finding_comments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String, nullable=False, index=True)
    author = Column(String, nullable=False)
    body = Column(String, nullable=False)
    created_at = Column(String, nullable=False)


# ==========================================================================
# SYSTEM MANAGEMENT -- exclusion rules, auth, LLM config, YARA/Sigma, retention
# ==========================================================================


class ExclusionRule(Base):
    """A rule suppressing matching findings from the main dashboard. Evaluated
    at read time inside bridge.get_all_findings() -- see core/exclusion_engine.py
    -- since findings themselves are recomputed fresh on every request rather
    than inserted into a table."""
    __tablename__ = "exclusion_rules"

    rule_id = Column(String, primary_key=True)
    rule_type = Column(String, nullable=False)
    pattern_value = Column(String, nullable=False)
    pattern_mode = Column(String, default="exact")
    matching_action = Column(String, default="mark_excluded")
    description_reason = Column(String, nullable=False)
    source_agent_filter = Column(String, nullable=True)
    min_severity_filter = Column(String, nullable=True)
    created_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    expiration_date = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)


class User(Base):
    """Local account for this workstation-scoped tool. No external identity
    provider -- this is a single-box, potentially offline DFIR platform, so
    auth is deliberately minimal: username/password + a role string."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="analyst")  # 'admin', 'analyst', 'viewer'
    created_at = Column(String, nullable=False)
    must_change_password = Column(Boolean, default=False)


class LlmProviderConfig(Base):
    """Singleton (id=1) row holding the LLM endpoint every agent's
    BaseHITLAgent and the Findings-page enrichment helper read from, instead
    of the hardcoded Gemini key/URL that shipped originally. Defaults point at
    a local Ollama OpenAI-compatible endpoint so this works with zero external
    network access."""
    __tablename__ = "llm_provider_config"

    id = Column(Integer, primary_key=True)
    provider_label = Column(String, default="Local Ollama")
    base_url = Column(String, default="http://localhost:11434/v1")
    api_key = Column(String, default="ollama")
    model_name = Column(String, default="llama3.1")
    context_limit = Column(Integer, default=30000)
    updated_at = Column(String, nullable=True)


class YaraRule(Base):
    """A YARA rule executed against every raw file the File Analysis pipeline
    triages (see agents/file_analysis/pestudio_analysis.py). Compiled and
    cached by core/yara_engine.py, invalidated on any CRUD change."""
    __tablename__ = "yara_rules"

    rule_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    rule_text = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    last_match_count = Column(Integer, default=0)
    last_error = Column(String, nullable=True)


class SigmaRule(Base):
    """A stored Sigma detection rule (YAML). Management/CRUD only in this
    pass -- there is no live Sigma execution engine wired into the EVTX/Sysmon
    agent yet (that needs a proper sigma backend/translation layer, flagged as
    future work), so these are catalogued and toggleable but not yet enforced."""
    __tablename__ = "sigma_rules"

    rule_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    rule_yaml = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)


class RetentionPolicy(Base):
    """One row per evidence category (memory_dumps, pcaps, staging_general).
    Enforcement is analyst-triggered (a dry-run preview, then explicit
    confirm) rather than an unattended background sweep -- deleting forensic
    evidence automatically is exactly the kind of action that should never
    happen without a human looking at what's about to go."""
    __tablename__ = "retention_policies"

    category = Column(String, primary_key=True)
    max_age_days = Column(Integer, nullable=True)
    max_total_gb = Column(Float, nullable=True)
    auto_archive_enabled = Column(Boolean, default=False)
    updated_at = Column(String, nullable=True)
