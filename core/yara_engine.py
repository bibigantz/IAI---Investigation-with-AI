"""YARA rule compilation + execution against raw evidence files.

Rules are stored in the DB (db.models.YaraRule) and managed from the
Management page. Compiled ruleset is cached in memory (same pattern as
core/exclusion_engine.py) and invalidated on any rule CRUD -- compiling a
YARA ruleset per file scanned would be wasteful given a File Analysis pass
can touch dozens of binaries.
"""
import threading
from typing import Any, Dict, List, Optional

import yara

_lock = threading.Lock()
_cache = None  # (yara.Rules, {namespace: rule_id}) or None


def invalidate():
    global _cache
    with _lock:
        _cache = None


def _compile_active_rules():
    from db.database import get_session
    from db.models import YaraRule

    with get_session() as session:
        rows = session.query(YaraRule).filter(YaraRule.is_active == True).all()  # noqa: E712
        sources = {}
        namespace_to_name = {}
        for row in rows:
            namespace = row.rule_id
            sources[namespace] = row.rule_text
            namespace_to_name[namespace] = row.name

    if not sources:
        return None, {}

    try:
        compiled = yara.compile(sources=sources)
        return compiled, namespace_to_name
    except yara.Error:
        # One bad rule shouldn't take down scanning for every other active
        # rule -- fall back to compiling each rule individually and drop
        # whichever one(s) fail, recording the error on that row.
        good_sources, namespace_to_name2 = {}, {}
        from db.database import get_session as _gs
        from db.models import YaraRule as _YR
        with _gs() as session:
            for namespace, source in sources.items():
                try:
                    yara.compile(source=source)
                    good_sources[namespace] = source
                    namespace_to_name2[namespace] = namespace_to_name[namespace]
                except yara.Error as e:
                    row = session.get(_YR, namespace)
                    if row:
                        row.last_error = str(e)
        if not good_sources:
            return None, {}
        compiled = yara.compile(sources=good_sources)
        return compiled, namespace_to_name2


def get_compiled_rules():
    global _cache
    with _lock:
        if _cache is None:
            _cache = _compile_active_rules()
        return _cache


def validate_rule_text(rule_text: str) -> Optional[str]:
    """Returns an error string if the rule fails to compile, else None."""
    try:
        yara.compile(source=rule_text)
        return None
    except yara.Error as e:
        return str(e)


def scan_file(filepath: str) -> List[Dict[str, Any]]:
    compiled, namespace_to_name = get_compiled_rules()
    if not compiled:
        return []
    try:
        matches = compiled.match(filepath, timeout=10)
    except (yara.Error, OSError):
        return []

    results = []
    for m in matches:
        namespace = getattr(m, "namespace", None)
        results.append({
            "rule_id": namespace,
            "rule_name": namespace_to_name.get(namespace, m.rule),
            "match_rule": m.rule,
            "tags": list(m.tags),
            "meta": dict(m.meta),
        })
    return results
