"""Sigma rule evaluation against extracted Windows Event Log fields.

Scope, stated precisely so nobody assumes more than this actually does:
supports named `detection` blocks (dict = AND across fields, list of dicts =
OR), field modifiers `|contains`/`|startswith`/`|endswith`/`|re`, value lists
(OR), and a `condition` string combining block names with `and`/`or`/`not`/
parentheses plus the `1 of x*` / `any of x*` / `all of x*` quantifier forms.

Not supported: aggregation functions (`count()`, `near`, timeframes),
field-to-field comparisons, or the full Sigma correlation-rule spec. A Sigma
rule using those constructs will simply never match here -- this is a real,
useful subset, not the complete language.

Rules are stored in db.models.SigmaRule and managed from the Management
page. Compiled/parsed rule set is cached in memory (same pattern as
core/exclusion_engine.py and core/yara_engine.py) and invalidated on any
rule CRUD.
"""
import ast
import fnmatch
import re
import threading
from typing import Any, Dict, List, Optional

_lock = threading.Lock()
_cache: Optional[List["CompiledSigmaRule"]] = None

_MODIFIER_RE = re.compile(r"^(.*?)\|(contains|startswith|endswith|re)$")


def invalidate():
    global _cache
    with _lock:
        _cache = None


def _value_matches(event_value: Any, rule_value: Any, modifier: Optional[str]) -> bool:
    if event_value is None:
        return False
    ev = str(event_value)
    values = rule_value if isinstance(rule_value, list) else [rule_value]
    for v in values:
        v = str(v)
        if modifier == "contains":
            if v.lower() in ev.lower():
                return True
        elif modifier == "startswith":
            if ev.lower().startswith(v.lower()):
                return True
        elif modifier == "endswith":
            if ev.lower().endswith(v.lower()):
                return True
        elif modifier == "re":
            try:
                if re.search(v, ev):
                    return True
            except re.error:
                continue
        else:
            if ev.lower() == v.lower():
                return True
    return False


def _block_matches(block: Any, event_fields: Dict[str, Any]) -> bool:
    """A detection block is either a dict (AND across its fields) or a list
    of dicts (OR across the list -- Sigma's shorthand for multiple selection
    variants under one name)."""
    if isinstance(block, list):
        return any(_block_matches(b, event_fields) for b in block)
    if not isinstance(block, dict):
        return False
    for field, rule_value in block.items():
        m = _MODIFIER_RE.match(field)
        base_field, modifier = (m.group(1), m.group(2)) if m else (field, None)
        if not _value_matches(event_fields.get(base_field), rule_value, modifier):
            return False
    return True


def _is_safe_bool_expr(node) -> bool:
    """Restricts the compiled condition AST to boolean logic only (BoolOp,
    Not, bare Name, bare bool Constant) -- rejects anything else so a
    malicious/malformed rule's condition string can never execute arbitrary
    Python, even though we do run it through ast/eval."""
    if isinstance(node, ast.BoolOp):
        return all(_is_safe_bool_expr(v) for v in node.values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _is_safe_bool_expr(node.operand)
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return True
    return False


class CompiledSigmaRule:
    def __init__(self, rule_id: str, name: str, detection: Dict[str, Any]):
        self.rule_id = rule_id
        self.name = name
        self.detection = detection
        self.condition = str(detection.get("condition") or "").strip()
        self.block_names = [k for k in detection.keys() if k != "condition"]

    def _resolve_quantifiers(self, expr: str) -> str:
        def repl(pattern: str, all_of: bool) -> str:
            matched = [b for b in self.block_names if fnmatch.fnmatch(b, pattern)]
            if not matched:
                return "False"
            joiner = " and " if all_of else " or "
            return "(" + joiner.join(f"__{b}__" for b in matched) + ")"

        expr = re.sub(r"\b(?:1|any)\s+of\s+([A-Za-z0-9_*]+)", lambda m: repl(m.group(1), False), expr)
        expr = re.sub(r"\ball\s+of\s+([A-Za-z0-9_*]+)", lambda m: repl(m.group(1), True), expr)
        return expr

    def evaluate(self, event_fields: Dict[str, Any]) -> bool:
        if not self.block_names:
            return False
        block_results = {name: _block_matches(self.detection[name], event_fields) for name in self.block_names}

        if not self.condition:
            # Sigma default with no explicit condition: match if the single
            # block present matches.
            if len(self.block_names) == 1:
                return block_results[self.block_names[0]]
            return False

        expr = self._resolve_quantifiers(self.condition)
        for name in sorted(self.block_names, key=len, reverse=True):
            expr = re.sub(rf"\b{re.escape(name)}\b", f"__{name}__", expr)

        try:
            tree = ast.parse(expr, mode="eval")
        except SyntaxError:
            return False
        if not _is_safe_bool_expr(tree.body):
            return False

        local_vars = {f"__{n}__": v for n, v in block_results.items()}
        try:
            return bool(eval(compile(tree, "<sigma-condition>", "eval"), {"__builtins__": {}}, local_vars))
        except Exception:
            return False


def _load_active_rules() -> List[CompiledSigmaRule]:
    import yaml
    from db.database import get_session
    from db.models import SigmaRule

    compiled: List[CompiledSigmaRule] = []
    with get_session() as session:
        rows = session.query(SigmaRule).filter(SigmaRule.is_active == True).all()  # noqa: E712
        for row in rows:
            try:
                parsed = yaml.safe_load(row.rule_yaml)
                detection = parsed.get("detection") if isinstance(parsed, dict) else None
                if not isinstance(detection, dict):
                    continue
                compiled.append(CompiledSigmaRule(row.rule_id, row.name, detection))
            except Exception:
                continue
    return compiled


def get_compiled_rules() -> List[CompiledSigmaRule]:
    global _cache
    with _lock:
        if _cache is None:
            _cache = _load_active_rules()
        return _cache


def evaluate_event(event_fields: Dict[str, Any]) -> List[Dict[str, str]]:
    matches = []
    for rule in get_compiled_rules():
        try:
            if rule.evaluate(event_fields):
                matches.append({"rule_id": rule.rule_id, "rule_name": rule.name})
        except Exception:
            continue
    return matches


def test_rule(rule_yaml: str, sample_fields: Dict[str, Any]) -> Dict[str, Any]:
    """Dry-run for the Management page's 'test before saving' action."""
    import yaml
    parsed = yaml.safe_load(rule_yaml)
    detection = parsed.get("detection") if isinstance(parsed, dict) else None
    if not isinstance(detection, dict):
        return {"matches": False, "error": "No 'detection' block found in rule YAML."}
    rule = CompiledSigmaRule("test", "test", detection)
    return {"matches": rule.evaluate(sample_fields)}
