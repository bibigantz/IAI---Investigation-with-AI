"""Findings Exclusion Rules engine.

Findings in this app are recomputed fresh on every GET /api/findings call
(from bridge.agent_states), not inserted into a table -- so there is no
insert-time "pipeline" to filter. This engine is evaluated inside
bridge.get_all_findings(), once per finding, per request.

Because the frontend polls /api/findings every 2 seconds, rules are compiled
once into an in-memory ExclusionMatcher and cached; the cache is invalidated
only on rule CRUD (see invalidate()), not rebuilt from scratch on every poll.
Per-rule expiration is still checked live (cheap timestamp comparison) so an
expired rule stops applying immediately without needing a cache rebuild.

Data-availability note: findings on this platform only carry a generic shape
(filepath, anomaly_type, justification, severity, agent_id/severity) -- there
is no structured pid/ppid/hash/ip field on the aggregated finding. So most
rule types (file_hash, ip, domain, port, process_name, pid, ppid) are matched
as a best-effort text search across filepath + anomaly_type + justification,
not an exact structured-field comparison. Only `file_path` (against the real
filepath field) and `finding_category` (against agent_id/severity) are exact.
This is documented behavior, not a bug -- it's the most useful thing possible
given what the finding shape actually carries today.
"""
import fnmatch
import ipaddress
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

_NUMERIC_TYPES = {"pid", "ppid", "port"}
_TEXT_SEARCH_TYPES = {"file_hash", "ip", "domain", "port", "process_name", "pid", "ppid"}

_lock = threading.Lock()
_cache: Optional["ExclusionMatcher"] = None


def new_rule_id() -> str:
    return "rule-" + uuid.uuid4().hex[:16]


class CompiledRule:
    def __init__(self, row):
        self.rule_id = row.rule_id
        self.rule_type = row.rule_type
        self.pattern_value = row.pattern_value
        self.pattern_mode = row.pattern_mode
        self.matching_action = row.matching_action
        self.description_reason = row.description_reason
        self.source_agent_filter = row.source_agent_filter
        self.min_severity_filter = row.min_severity_filter
        self.expiration_dt = self._parse_expiration(row.expiration_date)
        self._matcher = self._build_matcher(row)

    @staticmethod
    def _parse_expiration(expiration_date: Optional[str]):
        if not expiration_date:
            return None
        try:
            return datetime.fromisoformat(expiration_date)
        except Exception:
            return None

    def is_expired(self) -> bool:
        if not self.expiration_dt:
            return False
        now = datetime.now(timezone.utc) if self.expiration_dt.tzinfo else datetime.now()
        return now > self.expiration_dt

    def _build_matcher(self, row):
        if row.rule_type == "finding_category":
            return None  # handled structurally, not via a compiled text matcher
        if row.rule_type == "file_path":
            return self._build_text_matcher(row.pattern_value, row.pattern_mode)
        if row.rule_type == "ip" and row.pattern_mode == "cidr":
            try:
                network = ipaddress.ip_network(row.pattern_value, strict=False)
            except ValueError:
                return None
            ip_token_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,}\b")

            def matcher(text: str) -> bool:
                for token in ip_token_re.findall(text):
                    try:
                        if ipaddress.ip_address(token) in network:
                            return True
                    except ValueError:
                        continue
                return False
            return matcher
        if row.rule_type in _NUMERIC_TYPES:
            pattern = re.compile(r"\b" + re.escape(row.pattern_value) + r"\b")
            return lambda text: bool(pattern.search(text))
        # ip (exact/glob/regex), domain, file_hash, process_name -- plain text search
        return self._build_text_matcher(row.pattern_value, row.pattern_mode)

    @staticmethod
    def _build_text_matcher(pattern_value: str, pattern_mode: str):
        if pattern_mode == "regex":
            try:
                compiled = re.compile(pattern_value, re.IGNORECASE)
            except re.error:
                return lambda text: False
            return lambda text: bool(compiled.search(text))
        if pattern_mode == "glob":
            compiled = re.compile(fnmatch.translate(pattern_value), re.IGNORECASE)
            return lambda text: bool(compiled.match(text)) or bool(compiled.search(text))
        # exact -- substring, case-insensitive (a full-path "exact" rule still
        # needs to match a finding whose filepath has different casing)
        needle = pattern_value.lower()
        return lambda text: needle in text.lower()

    def matches(self, finding: Dict[str, Any]) -> bool:
        if self.is_expired():
            return False

        if self.rule_type == "finding_category":
            if self.source_agent_filter and finding.get("agent_id") != self.source_agent_filter:
                return False
            if self.min_severity_filter:
                rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                f_rank = rank.get((finding.get("severity") or "").upper(), 99)
                min_rank = rank.get(self.min_severity_filter.upper(), 99)
                if f_rank < min_rank:
                    return False
            return bool(self.source_agent_filter or self.min_severity_filter)

        if self.rule_type == "file_path":
            return bool(finding.get("filepath")) and self._matcher(finding["filepath"])

        haystack = " ".join(str(finding.get(f) or "") for f in ("filepath", "anomaly_type", "justification"))
        return self._matcher(haystack)


class ExclusionMatcher:
    def __init__(self, rules: List[CompiledRule]):
        self.rules = rules

    def evaluate(self, finding: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """Returns (excluded, rule_id, reason, matching_action) for the first
        active, non-expired rule that matches -- first match wins."""
        for rule in self.rules:
            if rule.matches(finding):
                return True, rule.rule_id, rule.description_reason, rule.matching_action
        return False, None, None, None


def _load_matcher() -> ExclusionMatcher:
    from db.database import get_session
    from db.models import ExclusionRule

    with get_session() as session:
        rows = session.query(ExclusionRule).filter(ExclusionRule.is_active == True).all()  # noqa: E712
        compiled = [CompiledRule(r) for r in rows]
    return ExclusionMatcher(compiled)


def get_matcher() -> ExclusionMatcher:
    global _cache
    with _lock:
        if _cache is None:
            _cache = _load_matcher()
        return _cache


def invalidate():
    """Call after any ExclusionRule create/update/delete/toggle."""
    global _cache
    with _lock:
        _cache = None


def test_rule(rule_type: str, pattern_value: str, pattern_mode: str, sample_value: str) -> bool:
    """Dry-run matcher for the 'test before you save' UI action -- builds a
    throwaway CompiledRule-like matcher without touching the DB."""
    class _FakeRow:
        pass
    row = _FakeRow()
    row.rule_id = "test"
    row.rule_type = rule_type
    row.pattern_value = pattern_value
    row.pattern_mode = pattern_mode
    row.matching_action = "mark_excluded"
    row.description_reason = ""
    row.source_agent_filter = None
    row.min_severity_filter = None
    row.expiration_date = None
    compiled = CompiledRule(row)
    fake_finding = {"filepath": sample_value, "anomaly_type": "", "justification": sample_value,
                     "agent_id": None, "severity": None}
    return compiled.matches(fake_finding)
