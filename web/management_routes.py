import os
from datetime import datetime, timezone
from flask import render_template, jsonify, request
from werkzeug.security import generate_password_hash

from bridge.hitl_bridge import bridge
from core import exclusion_engine, yara_engine, retention, sigma_engine
from web.auth import current_user
from db.database import get_session
from db.models import (
    ExclusionRule, User, LlmProviderConfig, YaraRule, SigmaRule, RetentionPolicy, AuditLogEntry,
)

MANAGEMENT_TABS = ["exclusions", "yara-sigma", "baselines", "llm", "retention", "access"]


def register_management_routes(app):
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # ==========================================================================
    # PAGE ROUTES
    # ==========================================================================

    @app.route("/management")
    def management_default():
        from flask import redirect
        return redirect("/management/exclusions")

    @app.route("/management/<tab>")
    def management_page(tab):
        if tab not in MANAGEMENT_TABS:
            tab = "exclusions"
        return render_template("management.html", active_tab=tab)

    # ==========================================================================
    # EXCLUSION RULES
    # ==========================================================================

    @app.route("/api/management/exclusions", methods=["GET"])
    def list_exclusion_rules():
        with get_session() as session:
            rows = session.query(ExclusionRule).order_by(ExclusionRule.created_at.desc()).all()
            return jsonify({"rules": [_exclusion_rule_dict(r) for r in rows]})

    @app.route("/api/management/exclusions", methods=["POST"])
    def create_exclusion_rule():
        data = request.json or {}
        rule_type = data.get("rule_type")
        pattern_value = (data.get("pattern_value") or "").strip()
        description_reason = (data.get("description_reason") or "").strip()
        if not rule_type or not pattern_value or not description_reason:
            return jsonify({"success": False, "error": "rule_type, pattern_value, and description_reason are required"}), 400

        rule_id = exclusion_engine.new_rule_id()
        with get_session() as session:
            session.add(ExclusionRule(
                rule_id=rule_id,
                rule_type=rule_type,
                pattern_value=pattern_value,
                pattern_mode=data.get("pattern_mode", "exact"),
                matching_action=data.get("matching_action", "mark_excluded"),
                description_reason=description_reason,
                source_agent_filter=data.get("source_agent_filter") or None,
                min_severity_filter=data.get("min_severity_filter") or None,
                created_by=current_user()["username"],
                created_at=datetime.now(timezone.utc).isoformat(),
                expiration_date=data.get("expiration_date") or None,
                is_active=True,
            ))
        exclusion_engine.invalidate()
        bridge.log_event("MANAGEMENT", f"Exclusion rule created ({rule_type}: {pattern_value}) by {current_user()['username']}", level="WARN")
        return jsonify({"success": True, "rule_id": rule_id})

    @app.route("/api/management/exclusions/<rule_id>", methods=["PATCH"])
    def update_exclusion_rule(rule_id):
        data = request.json or {}
        with get_session() as session:
            row = session.get(ExclusionRule, rule_id)
            if not row:
                return jsonify({"success": False, "error": "Rule not found"}), 404
            for field in ("rule_type", "pattern_value", "pattern_mode", "matching_action",
                          "description_reason", "source_agent_filter", "min_severity_filter",
                          "expiration_date", "is_active"):
                if field in data:
                    setattr(row, field, data[field])
        exclusion_engine.invalidate()
        return jsonify({"success": True})

    @app.route("/api/management/exclusions/<rule_id>", methods=["DELETE"])
    def delete_exclusion_rule(rule_id):
        with get_session() as session:
            row = session.get(ExclusionRule, rule_id)
            if not row:
                return jsonify({"success": False, "error": "Rule not found"}), 404
            session.delete(row)
        exclusion_engine.invalidate()
        bridge.log_event("MANAGEMENT", f"Exclusion rule {rule_id} deleted by {current_user()['username']}", level="WARN")
        return jsonify({"success": True})

    @app.route("/api/management/exclusions/test", methods=["POST"])
    def test_exclusion_rule():
        data = request.json or {}
        try:
            result = exclusion_engine.test_rule(
                data.get("rule_type"), data.get("pattern_value", ""),
                data.get("pattern_mode", "exact"), data.get("sample_value", ""),
            )
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400
        return jsonify({"success": True, "matches": result})

    @app.route("/api/management/exclusions/impact", methods=["GET"])
    def exclusion_rules_impact():
        findings = bridge.get_all_findings(include_deleted=True, include_excluded=True)
        counts = {}
        for f in findings:
            if f.get("excluded") and f.get("excluded_by_rule_id"):
                counts[f["excluded_by_rule_id"]] = counts.get(f["excluded_by_rule_id"], 0) + 1
        return jsonify({"impact": counts, "total_suppressed": sum(counts.values())})

    @app.route("/api/management/exclusions/import-baseline", methods=["POST"])
    def import_baseline_hashes():
        """Bulk-create file_hash exclusion rules from a golden-image hash list
        (one hash per line, or a hash_manifest.csv-shaped list of hash strings)."""
        data = request.json or {}
        hashes = data.get("hashes") or []
        reason = (data.get("description_reason") or "Golden-image baseline import").strip()
        clean_hashes = sorted({h.strip() for h in hashes if h and h.strip()})
        if not clean_hashes:
            return jsonify({"success": False, "error": "No valid hashes provided"}), 400

        now = datetime.now(timezone.utc).isoformat()
        created = []
        with get_session() as session:
            for h in clean_hashes:
                rule_id = exclusion_engine.new_rule_id()
                session.add(ExclusionRule(
                    rule_id=rule_id, rule_type="file_hash", pattern_value=h, pattern_mode="exact",
                    matching_action="mark_excluded", description_reason=reason,
                    created_by=current_user()["username"], created_at=now, is_active=True,
                ))
                created.append(rule_id)
        exclusion_engine.invalidate()
        bridge.log_event("MANAGEMENT", f"Baseline import: {len(created)} hash exclusion rules created by {current_user()['username']}", level="WARN")
        return jsonify({"success": True, "created_count": len(created)})

    # ==========================================================================
    # LLM PROVIDER CONFIG
    # ==========================================================================

    @app.route("/api/management/llm-config", methods=["GET"])
    def get_llm_config():
        with get_session() as session:
            row = session.get(LlmProviderConfig, 1)
            return jsonify({
                "provider_label": row.provider_label, "base_url": row.base_url,
                "api_key_set": bool(row.api_key), "model_name": row.model_name,
                "context_limit": row.context_limit, "updated_at": row.updated_at,
            })

    @app.route("/api/management/llm-config", methods=["POST"])
    def update_llm_config():
        data = request.json or {}
        with get_session() as session:
            row = session.get(LlmProviderConfig, 1)
            row.provider_label = data.get("provider_label", row.provider_label)
            row.base_url = data.get("base_url", row.base_url)
            if data.get("api_key"):
                row.api_key = data["api_key"]
            row.model_name = data.get("model_name", row.model_name)
            row.context_limit = int(data.get("context_limit", row.context_limit))
            row.updated_at = datetime.now(timezone.utc).isoformat()
        bridge.log_event("MANAGEMENT", f"LLM provider config updated by {current_user()['username']}", level="WARN")
        return jsonify({"success": True})

    # ==========================================================================
    # YARA RULES
    # ==========================================================================

    @app.route("/api/management/yara-rules", methods=["GET"])
    def list_yara_rules():
        with get_session() as session:
            rows = session.query(YaraRule).order_by(YaraRule.created_at.desc()).all()
            return jsonify({"rules": [
                {"rule_id": r.rule_id, "name": r.name, "rule_text": r.rule_text, "is_active": r.is_active,
                 "created_by": r.created_by, "created_at": r.created_at,
                 "last_match_count": r.last_match_count, "last_error": r.last_error}
                for r in rows
            ]})

    @app.route("/api/management/yara-rules", methods=["POST"])
    def create_yara_rule():
        data = request.json or {}
        name = (data.get("name") or "").strip()
        rule_text = data.get("rule_text") or ""
        if not name or not rule_text.strip():
            return jsonify({"success": False, "error": "name and rule_text are required"}), 400
        error = yara_engine.validate_rule_text(rule_text)
        if error:
            return jsonify({"success": False, "error": f"YARA compile error: {error}"}), 400

        rule_id = "yara-" + os.urandom(8).hex()
        with get_session() as session:
            session.add(YaraRule(
                rule_id=rule_id, name=name, rule_text=rule_text, is_active=True,
                created_by=current_user()["username"], created_at=datetime.now(timezone.utc).isoformat(),
            ))
        yara_engine.invalidate()
        return jsonify({"success": True, "rule_id": rule_id})

    @app.route("/api/management/yara-rules/<rule_id>", methods=["PATCH"])
    def update_yara_rule(rule_id):
        data = request.json or {}
        with get_session() as session:
            row = session.get(YaraRule, rule_id)
            if not row:
                return jsonify({"success": False, "error": "Rule not found"}), 404
            if "rule_text" in data:
                error = yara_engine.validate_rule_text(data["rule_text"])
                if error:
                    return jsonify({"success": False, "error": f"YARA compile error: {error}"}), 400
                row.rule_text = data["rule_text"]
                row.last_error = None
            if "name" in data:
                row.name = data["name"]
            if "is_active" in data:
                row.is_active = data["is_active"]
        yara_engine.invalidate()
        return jsonify({"success": True})

    @app.route("/api/management/yara-rules/<rule_id>", methods=["DELETE"])
    def delete_yara_rule(rule_id):
        with get_session() as session:
            row = session.get(YaraRule, rule_id)
            if not row:
                return jsonify({"success": False, "error": "Rule not found"}), 404
            session.delete(row)
        yara_engine.invalidate()
        return jsonify({"success": True})

    # ==========================================================================
    # SIGMA RULES -- executed against EVTX_Sysmon_Correlator's pre-filtered
    # events on every run (core/sigma_engine.py). See that module's docstring
    # for exactly which subset of the Sigma spec is supported.
    # ==========================================================================

    @app.route("/api/management/sigma-rules", methods=["GET"])
    def list_sigma_rules():
        with get_session() as session:
            rows = session.query(SigmaRule).order_by(SigmaRule.created_at.desc()).all()
            return jsonify({"rules": [
                {"rule_id": r.rule_id, "name": r.name, "rule_yaml": r.rule_yaml,
                 "is_active": r.is_active, "created_by": r.created_by, "created_at": r.created_at}
                for r in rows
            ]})

    @app.route("/api/management/sigma-rules", methods=["POST"])
    def create_sigma_rule():
        data = request.json or {}
        name = (data.get("name") or "").strip()
        rule_yaml = data.get("rule_yaml") or ""
        if not name or not rule_yaml.strip():
            return jsonify({"success": False, "error": "name and rule_yaml are required"}), 400
        try:
            import yaml
            parsed = yaml.safe_load(rule_yaml)
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid YAML: {e}"}), 400
        if not isinstance(parsed, dict) or not isinstance(parsed.get("detection"), dict):
            return jsonify({"success": False, "error": "Rule YAML must have a top-level 'detection' block."}), 400

        rule_id = "sigma-" + os.urandom(8).hex()
        with get_session() as session:
            session.add(SigmaRule(
                rule_id=rule_id, name=name, rule_yaml=rule_yaml, is_active=True,
                created_by=current_user()["username"], created_at=datetime.now(timezone.utc).isoformat(),
            ))
        sigma_engine.invalidate()
        return jsonify({"success": True, "rule_id": rule_id})

    @app.route("/api/management/sigma-rules/<rule_id>", methods=["PATCH"])
    def update_sigma_rule(rule_id):
        data = request.json or {}
        with get_session() as session:
            row = session.get(SigmaRule, rule_id)
            if not row:
                return jsonify({"success": False, "error": "Rule not found"}), 404
            if "rule_yaml" in data:
                try:
                    import yaml
                    parsed = yaml.safe_load(data["rule_yaml"])
                except Exception as e:
                    return jsonify({"success": False, "error": f"Invalid YAML: {e}"}), 400
                if not isinstance(parsed, dict) or not isinstance(parsed.get("detection"), dict):
                    return jsonify({"success": False, "error": "Rule YAML must have a top-level 'detection' block."}), 400
                row.rule_yaml = data["rule_yaml"]
            if "is_active" in data:
                row.is_active = data["is_active"]
            if "name" in data:
                row.name = data["name"]
        sigma_engine.invalidate()
        return jsonify({"success": True})

    @app.route("/api/management/sigma-rules/<rule_id>", methods=["DELETE"])
    def delete_sigma_rule(rule_id):
        with get_session() as session:
            row = session.get(SigmaRule, rule_id)
            if not row:
                return jsonify({"success": False, "error": "Rule not found"}), 404
            session.delete(row)
        sigma_engine.invalidate()
        return jsonify({"success": True})

    @app.route("/api/management/sigma-rules/test", methods=["POST"])
    def test_sigma_rule():
        data = request.json or {}
        rule_yaml = data.get("rule_yaml") or ""
        sample_fields = data.get("sample_fields") or {}
        try:
            result = sigma_engine.test_rule(rule_yaml, sample_fields)
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400
        if result.get("error"):
            return jsonify({"success": False, "error": result["error"]}), 400
        return jsonify({"success": True, "matches": result["matches"]})

    # ==========================================================================
    # RETENTION
    # ==========================================================================

    @app.route("/api/management/retention/storage-summary", methods=["GET"])
    def retention_storage_summary():
        return jsonify(retention.scan_storage_summary(PROJECT_ROOT))

    @app.route("/api/management/retention/policies", methods=["GET"])
    def list_retention_policies():
        with get_session() as session:
            rows = {r.category: r for r in session.query(RetentionPolicy).all()}
            return jsonify({"policies": [
                {
                    "category": cat,
                    "max_age_days": rows[cat].max_age_days if cat in rows else None,
                    "max_total_gb": rows[cat].max_total_gb if cat in rows else None,
                    "auto_archive_enabled": rows[cat].auto_archive_enabled if cat in rows else False,
                }
                for cat in retention.CATEGORIES
            ]})

    @app.route("/api/management/retention/policies", methods=["POST"])
    def set_retention_policy():
        data = request.json or {}
        category = data.get("category")
        if category not in retention.CATEGORIES:
            return jsonify({"success": False, "error": "Invalid category"}), 400
        with get_session() as session:
            row = session.get(RetentionPolicy, category) or RetentionPolicy(category=category)
            row.max_age_days = data.get("max_age_days")
            row.max_total_gb = data.get("max_total_gb")
            row.auto_archive_enabled = bool(data.get("auto_archive_enabled", False))
            row.updated_at = datetime.now(timezone.utc).isoformat()
            session.merge(row)
        return jsonify({"success": True})

    @app.route("/api/management/retention/sweep-preview", methods=["POST"])
    def retention_sweep_preview():
        data = request.json or {}
        category = data.get("category")
        if category not in retention.CATEGORIES:
            return jsonify({"success": False, "error": "Invalid category"}), 400
        with get_session() as session:
            policy = session.get(RetentionPolicy, category)
            max_age_days = policy.max_age_days if policy else None
            max_total_gb = policy.max_total_gb if policy else None
        candidates = retention.preview_sweep(PROJECT_ROOT, category, max_age_days, max_total_gb)
        return jsonify({"candidates": candidates, "total_bytes": sum(c["size_bytes"] for c in candidates)})

    @app.route("/api/management/retention/sweep-execute", methods=["POST"])
    def retention_sweep_execute():
        data = request.json or {}
        paths = data.get("paths") or []
        if not paths:
            return jsonify({"success": False, "error": "No paths provided"}), 400
        result = retention.execute_sweep(PROJECT_ROOT, paths)
        bridge.log_event("MANAGEMENT", f"Retention sweep by {current_user()['username']}: "
                          f"{len(result['deleted'])} file(s) deleted, {len(result['errors'])} error(s)", level="WARN")
        return jsonify({"success": True, **result})

    # ==========================================================================
    # AUDIT LOG + USER MANAGEMENT
    # ==========================================================================

    @app.route("/api/management/audit-log", methods=["GET"])
    def global_audit_log():
        limit = min(int(request.args.get("limit", 200)), 1000)
        with get_session() as session:
            finding_entries = [
                {"timestamp": r.timestamp, "actor": r.actor, "action": r.action, "reason": r.reason,
                 "source": "finding", "context": r.finding_id}
                for r in session.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(limit).all()
            ]
        pipeline_entries = [
            {"timestamp": e["timestamp"], "actor": e["source"], "action": e["level"], "reason": e["message"],
             "source": "pipeline", "context": None}
            for e in bridge.logs[-limit:]
        ]
        combined = sorted(finding_entries + pipeline_entries, key=lambda e: e["timestamp"], reverse=True)
        return jsonify({"entries": combined[:limit]})

    @app.route("/api/management/users", methods=["GET"])
    def list_users():
        with get_session() as session:
            rows = session.query(User).order_by(User.created_at.asc()).all()
            return jsonify({"users": [
                {"id": r.id, "username": r.username, "role": r.role, "created_at": r.created_at,
                 "must_change_password": r.must_change_password}
                for r in rows
            ]})

    @app.route("/api/management/users", methods=["POST"])
    def create_user():
        data = request.json or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = data.get("role", "analyst")
        if not username or len(password) < 8 or role not in ("admin", "analyst", "viewer"):
            return jsonify({"success": False, "error": "username, an 8+ char password, and a valid role are required"}), 400
        with get_session() as session:
            if session.query(User).filter(User.username == username).first():
                return jsonify({"success": False, "error": "Username already exists"}), 400
            session.add(User(
                username=username, password_hash=generate_password_hash(password), role=role,
                created_at=datetime.now(timezone.utc).isoformat(), must_change_password=True,
            ))
        return jsonify({"success": True})

    @app.route("/api/management/users/<int:user_id>", methods=["PATCH"])
    def update_user(user_id):
        data = request.json or {}
        with get_session() as session:
            row = session.get(User, user_id)
            if not row:
                return jsonify({"success": False, "error": "User not found"}), 404
            if "role" in data and data["role"] in ("admin", "analyst", "viewer"):
                row.role = data["role"]
            if data.get("reset_password"):
                row.password_hash = generate_password_hash(data["reset_password"])
                row.must_change_password = True
        return jsonify({"success": True})

    @app.route("/api/management/users/<int:user_id>", methods=["DELETE"])
    def delete_user(user_id):
        if user_id == current_user()["id"]:
            return jsonify({"success": False, "error": "Cannot delete your own account"}), 400
        with get_session() as session:
            row = session.get(User, user_id)
            if not row:
                return jsonify({"success": False, "error": "User not found"}), 404
            session.delete(row)
        return jsonify({"success": True})


def _exclusion_rule_dict(r):
    return {
        "rule_id": r.rule_id, "rule_type": r.rule_type, "pattern_value": r.pattern_value,
        "pattern_mode": r.pattern_mode, "matching_action": r.matching_action,
        "description_reason": r.description_reason, "source_agent_filter": r.source_agent_filter,
        "min_severity_filter": r.min_severity_filter, "created_by": r.created_by,
        "created_at": r.created_at, "expiration_date": r.expiration_date, "is_active": r.is_active,
    }
