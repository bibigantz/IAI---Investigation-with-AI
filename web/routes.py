import os
import sys
import json
import time
import uuid
import threading
import asyncio
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from flask import render_template, jsonify, request, send_from_directory, Response
from werkzeug.utils import secure_filename
from bridge.hitl_bridge import bridge
from core import finding_utils
from db.database import get_session
from db.models import (
    FindingOverlay, ManualFinding, LocalIOC, AuditLogEntry, EnrichmentJob,
    SavedView, FindingLock, FindingComment,
)

MASTER_REPORT_FILENAME = "Master_Executive_Intelligence_Report.json"
ALLOWED_REPORT_FILENAMES = {
    MASTER_REPORT_FILENAME,
    "Windows_Forensics_Master_Report.json",
    "File_Analysis_Master_Report.json",
    "Memory_Analysis_Master_Report.json",
    "Master_Forensic_Report.json",
    "Execution_Artifacts_Report.json",
}


def register_routes(app):
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, "uploads")
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    investigation_thread = [None]

    def resolve_staging_dir(folder_name):
        """Safely resolve a staging folder name to an absolute path guaranteed
        to be a direct child of PROJECT_ROOT. Rejects any path separator in
        folder_name outright (staging folder names are always flat, so this
        alone blocks traversal) and double-checks the resolved absolute path
        still lives under PROJECT_ROOT. Returns None if invalid/not found."""
        if not folder_name or os.sep in folder_name or (os.altsep and os.altsep in folder_name):
            return None
        root = os.path.abspath(PROJECT_ROOT)
        candidate = os.path.abspath(os.path.join(root, folder_name))
        if candidate != root and not candidate.startswith(root + os.sep):
            return None
        if not os.path.isdir(candidate):
            return None
        return candidate

    @app.route("/")
    def index_dashboard():
        return render_template("dashboard.html")

    @app.route("/topology")
    def topology_view():
        return render_template("topology.html")

    @app.route("/agents")
    def agents_control():
        return render_template("agents.html")

    @app.route("/findings")
    def findings_view():
        return render_template("findings.html")

    @app.route("/iocs")
    def iocs_view():
        return render_template("iocs.html")

    @app.route("/api/status", methods=["GET"])
    def get_status():
        has_master_report = False
        collection_progress = None
        if bridge.active_investigation_id:
            staging_path = resolve_staging_dir(bridge.active_investigation_id)
            if staging_path:
                has_master_report = os.path.isfile(os.path.join(staging_path, MASTER_REPORT_FILENAME))
                progress_path = os.path.join(staging_path, "collection_progress.json")
                if os.path.isfile(progress_path):
                    try:
                        with open(progress_path, "r", encoding="utf-8") as f:
                            p = json.load(f)
                        collection_progress = {
                            "completed_categories": len(p.get("completed_categories", [])),
                            "completed_steps": len(p.get("completed_steps", [])),
                            "stopped": bool(p.get("stopped")),
                        }
                    except Exception:
                        pass

        return jsonify({
            "execution_mode": bridge.execution_mode,
            "pipeline_status": bridge.pipeline_status,
            "active_investigation_id": bridge.active_investigation_id,
            "pending_count": len(bridge.pending_approvals),
            "total_nodes": len(bridge.nodes),
            "approved_count": sum(1 for n in bridge.nodes.values() if n["state"] == "BLUE"),
            "active_count": sum(1 for n in bridge.nodes.values() if n["state"] in ["GREEN", "YELLOW"]),
            "is_paused": bridge.is_paused,
            "has_master_report": has_master_report,
            "collection_progress": collection_progress,
        })

    @app.route("/api/mode", methods=["POST"])
    def set_mode():
        data = request.json or {}
        new_mode = data.get("mode", "SUPERVISED").upper()
        if new_mode in ["SUPERVISED", "AUTOMATIC"]:
            bridge.execution_mode = new_mode
            bridge.log_event("SYSTEM", f"Global execution mode switched to: {new_mode}", level="WARN")
            return jsonify({"success": True, "execution_mode": bridge.execution_mode})
        return jsonify({"success": False, "error": "Invalid mode"}), 400

    @app.route("/api/drives", methods=["GET"])
    def list_drives():
        return jsonify({"drives": bridge.get_available_drives()})

    @app.route("/api/investigations/existing", methods=["GET"])
    def list_existing_investigations():
        return jsonify({"investigations": bridge.get_existing_investigations(search_root=PROJECT_ROOT)})

    @app.route("/api/investigations/delete", methods=["POST"])
    def delete_investigation():
        data = request.json or {}
        folder_name = data.get("folder_name", "").strip()
        target = resolve_staging_dir(folder_name)
        if not target:
            return jsonify({"success": False, "error": "Investigation not found"}), 404
        try:
            import shutil
            shutil.rmtree(target)
            bridge.log_event("SYSTEM", f"Deleted investigation session: {folder_name}", level="WARN")
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    def _audit(finding_id, action, actor, reason=None, details=None):
        with get_session() as session:
            session.add(AuditLogEntry(
                finding_id=finding_id, action=action, actor=actor or "Analyst", reason=reason,
                timestamp=datetime.now(timezone.utc).isoformat(), details=details,
            ))
        bridge.log_event("FINDINGS", f"[{finding_id}] {action} by {actor or 'Analyst'}"
                          + (f" -- {reason}" if reason else ""), level="HITL")

    @app.route("/api/findings", methods=["GET"])
    def get_findings():
        include_dismissed = request.args.get("include_dismissed", "false").lower() == "true"
        include_excluded = request.args.get("include_excluded", "false").lower() == "true"
        findings = bridge.get_all_findings(include_deleted=include_dismissed, include_excluded=include_excluded)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0}
        for f in findings:
            key = str(f.get("severity") or "").strip().upper()
            counts[key if key in counts else "OTHER"] += 1
        with get_session() as session:
            locks = {
                l.finding_id: l.locked_by for l in session.query(FindingLock).all() if not l.is_stale()
            }
        for f in findings:
            f["locked_by"] = locks.get(f["finding_id"])
        return jsonify({"findings": findings, "counts": counts, "total": len(findings)})

    # ==========================================================================
    # FINDINGS -- status / dismiss / restore / assign / tags / MITRE / confidence
    # ==========================================================================

    @app.route("/api/findings/dismiss", methods=["POST"])
    def dismiss_finding():
        data = request.json or {}
        finding_id = data.get("finding_id")
        status = data.get("status", "dismissed")
        reason = (data.get("reason") or "").strip()
        actor = data.get("actor", "Analyst")
        if not finding_id or status not in ("dismissed", "false_positive", "acknowledged", "escalated"):
            return jsonify({"success": False, "error": "Missing finding_id or invalid status"}), 400

        with get_session() as session:
            overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
            overlay.status = status
            overlay.dismissed_by = actor
            overlay.dismissed_reason = reason
            overlay.dismissed_at = datetime.now(timezone.utc).isoformat()
            overlay.updated_at = overlay.dismissed_at
            session.merge(overlay)

        _audit(finding_id, status, actor, reason)
        return jsonify({"success": True})

    @app.route("/api/findings/bulk-dismiss", methods=["POST"])
    def bulk_dismiss_findings():
        data = request.json or {}
        finding_ids = data.get("finding_ids") or []
        status = data.get("status", "dismissed")
        reason = (data.get("reason") or "").strip()
        actor = data.get("actor", "Analyst")
        if not finding_ids:
            return jsonify({"success": False, "error": "No findings selected"}), 400

        now = datetime.now(timezone.utc).isoformat()
        with get_session() as session:
            for finding_id in finding_ids:
                overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
                overlay.status = status
                overlay.dismissed_by = actor
                overlay.dismissed_reason = reason
                overlay.dismissed_at = now
                overlay.updated_at = now
                session.merge(overlay)
        for finding_id in finding_ids:
            _audit(finding_id, status, actor, reason)
        return jsonify({"success": True, "count": len(finding_ids)})

    @app.route("/api/findings/restore", methods=["POST"])
    def restore_finding():
        data = request.json or {}
        finding_id = data.get("finding_id")
        actor = data.get("actor", "Analyst")
        if not finding_id:
            return jsonify({"success": False, "error": "Missing finding_id"}), 400
        with get_session() as session:
            overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
            overlay.status = "new"
            overlay.dismissed_by = None
            overlay.dismissed_reason = None
            overlay.dismissed_at = None
            overlay.updated_at = datetime.now(timezone.utc).isoformat()
            session.merge(overlay)
        _audit(finding_id, "restored", actor)
        return jsonify({"success": True})

    @app.route("/api/findings/delete", methods=["POST"])
    def delete_finding_permanently():
        """Hard delete, distinct from dismiss/false_positive: the finding is
        excluded from every view unconditionally (bridge.get_all_findings()),
        with no restore path. For a manual finding this also drops its actual
        ManualFinding row -- for an agent-derived finding there is no row to
        drop, so the overlay's status='deleted' is the only mechanism, and it
        stays deleted only as long as the same anomaly keeps hashing to the
        same finding_id (see core/finding_utils.compute_finding_id)."""
        data = request.json or {}
        finding_id = data.get("finding_id")
        reason = (data.get("reason") or "").strip()
        actor = data.get("actor", "Analyst")
        if not finding_id:
            return jsonify({"success": False, "error": "Missing finding_id"}), 400

        finding = bridge.get_finding_by_id(finding_id)
        if not finding:
            return jsonify({"success": False, "error": "Finding not found"}), 404

        now = datetime.now(timezone.utc).isoformat()
        with get_session() as session:
            if finding.get("source") == "manual":
                manual_row = session.get(ManualFinding, finding_id)
                if manual_row:
                    session.delete(manual_row)
            overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
            overlay.status = "deleted"
            overlay.dismissed_by = actor
            overlay.dismissed_reason = reason or "Permanently deleted"
            overlay.dismissed_at = now
            overlay.updated_at = now
            session.merge(overlay)

        _audit(finding_id, "deleted_permanently", actor, reason)
        return jsonify({"success": True})

    @app.route("/api/findings/bulk-delete", methods=["POST"])
    def bulk_delete_findings_permanently():
        data = request.json or {}
        finding_ids = data.get("finding_ids") or []
        reason = (data.get("reason") or "").strip()
        actor = data.get("actor", "Analyst")
        if not finding_ids:
            return jsonify({"success": False, "error": "No findings selected"}), 400

        now = datetime.now(timezone.utc).isoformat()
        deleted_ids = []
        with get_session() as session:
            for finding_id in finding_ids:
                finding = bridge.get_finding_by_id(finding_id)
                if not finding:
                    continue
                if finding.get("source") == "manual":
                    manual_row = session.get(ManualFinding, finding_id)
                    if manual_row:
                        session.delete(manual_row)
                overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
                overlay.status = "deleted"
                overlay.dismissed_by = actor
                overlay.dismissed_reason = reason or "Permanently deleted"
                overlay.dismissed_at = now
                overlay.updated_at = now
                session.merge(overlay)
                deleted_ids.append(finding_id)
        for finding_id in deleted_ids:
            _audit(finding_id, "deleted_permanently", actor, reason)
        return jsonify({"success": True, "count": len(deleted_ids)})

    @app.route("/api/findings/assign", methods=["POST"])
    def assign_finding():
        data = request.json or {}
        finding_id = data.get("finding_id")
        assigned_to = (data.get("assigned_to") or "").strip() or None
        actor = data.get("actor", "Analyst")
        if not finding_id:
            return jsonify({"success": False, "error": "Missing finding_id"}), 400
        with get_session() as session:
            overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
            overlay.assigned_to = assigned_to
            overlay.updated_at = datetime.now(timezone.utc).isoformat()
            session.merge(overlay)
        _audit(finding_id, "assigned", actor, reason=f"assigned_to={assigned_to}")
        return jsonify({"success": True})

    @app.route("/api/findings/tag", methods=["POST"])
    def tag_finding():
        data = request.json or {}
        finding_id = data.get("finding_id")
        tags = data.get("tags")
        if not finding_id or tags is None:
            return jsonify({"success": False, "error": "Missing finding_id or tags"}), 400
        with get_session() as session:
            overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
            overlay.tags = list(dict.fromkeys([str(t).strip() for t in tags if str(t).strip()]))
            overlay.updated_at = datetime.now(timezone.utc).isoformat()
            session.merge(overlay)
        return jsonify({"success": True})

    @app.route("/api/findings/bulk-tag", methods=["POST"])
    def bulk_tag_findings():
        data = request.json or {}
        finding_ids = data.get("finding_ids") or []
        add_tags = [str(t).strip() for t in (data.get("add_tags") or []) if str(t).strip()]
        if not finding_ids or not add_tags:
            return jsonify({"success": False, "error": "Missing finding_ids or add_tags"}), 400
        now = datetime.now(timezone.utc).isoformat()
        with get_session() as session:
            for finding_id in finding_ids:
                overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
                overlay.tags = list(dict.fromkeys((overlay.tags or []) + add_tags))
                overlay.updated_at = now
                session.merge(overlay)
        return jsonify({"success": True, "count": len(finding_ids)})

    @app.route("/api/findings/mitre", methods=["POST"])
    def set_finding_mitre():
        data = request.json or {}
        finding_id = data.get("finding_id")
        techniques = data.get("mitre_techniques")
        if not finding_id or techniques is None:
            return jsonify({"success": False, "error": "Missing finding_id or mitre_techniques"}), 400
        with get_session() as session:
            overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
            overlay.mitre_techniques = list(dict.fromkeys([str(t).strip() for t in techniques if str(t).strip()]))
            overlay.updated_at = datetime.now(timezone.utc).isoformat()
            session.merge(overlay)
        return jsonify({"success": True})

    @app.route("/api/findings/mitre-lookup", methods=["GET"])
    def mitre_lookup():
        return jsonify({"techniques": finding_utils.mitre_lookup()})

    @app.route("/api/findings/confidence", methods=["POST"])
    def set_finding_confidence():
        data = request.json or {}
        finding_id = data.get("finding_id")
        confidence = data.get("confidence")
        if not finding_id or confidence is None:
            return jsonify({"success": False, "error": "Missing finding_id or confidence"}), 400
        try:
            confidence = max(0, min(100, float(confidence)))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "confidence must be a number 0-100"}), 400
        with get_session() as session:
            overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
            overlay.confidence = confidence
            overlay.updated_at = datetime.now(timezone.utc).isoformat()
            session.merge(overlay)
        return jsonify({"success": True})

    @app.route("/api/findings/cluster", methods=["POST"])
    def cluster_findings():
        data = request.json or {}
        finding_ids = data.get("finding_ids") or []
        if len(finding_ids) < 2:
            return jsonify({"success": False, "error": "Select at least 2 findings to merge"}), 400
        cluster_id = "manual-" + uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        with get_session() as session:
            for finding_id in finding_ids:
                overlay = session.get(FindingOverlay, finding_id) or FindingOverlay(finding_id=finding_id)
                overlay.cluster_id = cluster_id
                overlay.updated_at = now
                session.merge(overlay)
        return jsonify({"success": True, "cluster_id": cluster_id})

    # ==========================================================================
    # FINDINGS -- manual entry
    # ==========================================================================

    @app.route("/api/findings/manual", methods=["POST"])
    def add_manual_finding():
        data = request.json or {}
        anomaly_type = (data.get("anomaly_type") or "").strip()
        severity = (data.get("severity") or "Medium").strip()
        justification = (data.get("justification") or "").strip()
        if not anomaly_type or not justification:
            return jsonify({"success": False, "error": "anomaly_type and justification are required"}), 400

        finding_id = "manual-" + uuid.uuid4().hex[:16]
        now = datetime.now(timezone.utc).isoformat()
        with get_session() as session:
            session.add(ManualFinding(
                finding_id=finding_id,
                case_staging_dir=bridge.active_investigation_id,
                agent_label=(data.get("agent_label") or "Manual Entry").strip(),
                filepath=(data.get("filepath") or "").strip() or None,
                anomaly_type=anomaly_type,
                severity=severity,
                justification=justification,
                recommended_action=(data.get("recommended_action") or "").strip(),
                artifact_note=(data.get("artifact_note") or "").strip() or None,
                created_by=data.get("created_by", "Analyst"),
                created_at=now,
            ))
        _audit(finding_id, "created_manual", data.get("created_by", "Analyst"))
        return jsonify({"success": True, "finding_id": finding_id})

    # ==========================================================================
    # FINDINGS -- comments, locks (poll-based presence), audit log
    # ==========================================================================

    @app.route("/api/findings/<finding_id>/comments", methods=["GET"])
    def get_finding_comments(finding_id):
        with get_session() as session:
            rows = session.query(FindingComment).filter(
                FindingComment.finding_id == finding_id
            ).order_by(FindingComment.id.asc()).all()
            return jsonify({"comments": [
                {"id": r.id, "author": r.author, "body": r.body, "created_at": r.created_at} for r in rows
            ]})

    @app.route("/api/findings/<finding_id>/comments", methods=["POST"])
    def add_finding_comment(finding_id):
        data = request.json or {}
        body = (data.get("body") or "").strip()
        author = data.get("author", "Analyst")
        if not body:
            return jsonify({"success": False, "error": "Comment body is required"}), 400
        with get_session() as session:
            session.add(FindingComment(
                finding_id=finding_id, author=author, body=body,
                created_at=datetime.now(timezone.utc).isoformat(),
            ))
        return jsonify({"success": True})

    @app.route("/api/findings/<finding_id>/audit-log", methods=["GET"])
    def get_finding_audit_log(finding_id):
        with get_session() as session:
            rows = session.query(AuditLogEntry).filter(
                AuditLogEntry.finding_id == finding_id
            ).order_by(AuditLogEntry.id.asc()).all()
            return jsonify({"entries": [
                {"action": r.action, "actor": r.actor, "reason": r.reason, "timestamp": r.timestamp,
                 "details": r.details} for r in rows
            ]})

    @app.route("/api/findings/<finding_id>/lock", methods=["POST"])
    def heartbeat_finding_lock(finding_id):
        data = request.json or {}
        actor = data.get("actor", "Analyst")
        now = time.time()
        with get_session() as session:
            lock = session.get(FindingLock, finding_id)
            if lock and not lock.is_stale() and lock.locked_by != actor:
                return jsonify({"success": False, "locked_by": lock.locked_by}), 409
            lock = lock or FindingLock(finding_id=finding_id, locked_by=actor, locked_at=now)
            lock.locked_by = actor
            lock.locked_at = now
            session.merge(lock)
        return jsonify({"success": True})

    @app.route("/api/findings/<finding_id>/lock", methods=["DELETE"])
    def release_finding_lock(finding_id):
        with get_session() as session:
            lock = session.get(FindingLock, finding_id)
            if lock:
                session.delete(lock)
        return jsonify({"success": True})

    # ==========================================================================
    # FINDINGS -- pivot / hunt links, timeline correlation
    # ==========================================================================

    @app.route("/api/findings/pivot", methods=["GET"])
    def get_pivot_links():
        value = (request.args.get("value") or "").strip()
        if not value:
            return jsonify({"success": False, "error": "Missing value"}), 400
        return jsonify({"value": value, "links": finding_utils.build_pivot_links(value)})

    @app.route("/api/findings/<finding_id>/timeline-context", methods=["GET"])
    def get_finding_timeline_context(finding_id):
        """Best-effort temporal context for a finding: if its artifact path
        still exists on disk, surrounding-time context is its own filesystem
        timestamps -- this codebase has no persisted, queryable super-timeline
        store to correlate against, so this is intentionally best-effort
        rather than a full timeline join."""
        finding = bridge.get_finding_by_id(finding_id)
        if not finding:
            return jsonify({"success": False, "error": "Finding not found"}), 404
        filepath = finding.get("filepath")
        if not filepath or not os.path.isfile(filepath):
            return jsonify({
                "success": True, "available": False,
                "note": "No on-disk artifact path available for this finding to derive timestamps from.",
            })
        try:
            stats = os.stat(filepath)
            return jsonify({
                "success": True, "available": True,
                "created_utc": datetime.fromtimestamp(stats.st_ctime, tz=timezone.utc).isoformat(),
                "modified_utc": datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc).isoformat(),
                "accessed_utc": datetime.fromtimestamp(stats.st_atime, tz=timezone.utc).isoformat(),
                "note": "Derived from filesystem metadata; no super-timeline store exists to cross-reference.",
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # ==========================================================================
    # IOCs -- save as IOC, local library, export
    # ==========================================================================

    @app.route("/api/findings/save-as-ioc", methods=["POST"])
    def save_findings_as_ioc():
        data = request.json or {}
        finding_ids = data.get("finding_ids") or []
        tlp = data.get("tlp", "amber")
        actor = data.get("actor", "Analyst")
        if not finding_ids:
            return jsonify({"success": False, "error": "No findings selected"}), 400

        created = []
        now = datetime.now(timezone.utc).isoformat()
        with get_session() as session:
            for finding_id in finding_ids:
                finding = bridge.get_finding_by_id(finding_id)
                if not finding:
                    continue
                value = finding.get("filepath") or finding.get("anomaly_type")
                if not value:
                    continue
                ioc_type = finding_utils.classify_ioc_type(value)
                ioc_id = "ioc-" + uuid.uuid4().hex[:16]
                session.add(LocalIOC(
                    ioc_id=ioc_id, ioc_type=ioc_type, value=value, source_finding_id=finding_id,
                    case_staging_dir=bridge.active_investigation_id, tlp=tlp, added_by=actor,
                    added_at=now, notes=finding.get("justification"),
                ))
                created.append(ioc_id)
                _audit(finding_id, "saved_as_ioc", actor, details={"ioc_id": ioc_id})
        return jsonify({"success": True, "created_ioc_ids": created})

    @app.route("/api/iocs", methods=["GET"])
    def list_iocs():
        with get_session() as session:
            rows = session.query(LocalIOC).order_by(LocalIOC.added_at.desc()).all()
            return jsonify({"iocs": [
                {"ioc_id": r.ioc_id, "ioc_type": r.ioc_type, "value": r.value,
                 "source_finding_id": r.source_finding_id, "tlp": r.tlp, "added_by": r.added_by,
                 "added_at": r.added_at, "notes": r.notes} for r in rows
            ]})

    @app.route("/api/iocs/<ioc_id>", methods=["DELETE"])
    def delete_ioc(ioc_id):
        with get_session() as session:
            row = session.get(LocalIOC, ioc_id)
            if not row:
                return jsonify({"success": False, "error": "IOC not found"}), 404
            session.delete(row)
        return jsonify({"success": True})

    @app.route("/api/iocs/export", methods=["GET"])
    def export_iocs():
        fmt = request.args.get("format", "csv").lower()
        with get_session() as session:
            iocs = [
                {"ioc_id": r.ioc_id, "ioc_type": r.ioc_type, "value": r.value,
                 "source_finding_id": r.source_finding_id, "tlp": r.tlp, "added_by": r.added_by,
                 "added_at": r.added_at, "notes": r.notes}
                for r in session.query(LocalIOC).all()
            ]
        if not iocs:
            return jsonify({"success": False, "error": "No IOCs saved yet"}), 404

        if fmt == "stix":
            body = finding_utils.build_stix_bundle(iocs)
            return Response(body, mimetype="application/json",
                             headers={"Content-Disposition": "attachment; filename=iocs_stix_bundle.json"})
        if fmt == "misp":
            body = json.dumps(finding_utils.build_misp_shaped_json(iocs, "IAI investigation IOC export"), indent=2)
            return Response(body, mimetype="application/json",
                             headers={"Content-Disposition": "attachment; filename=iocs_misp_event.json"})
        if fmt == "json":
            return Response(json.dumps(iocs, indent=2), mimetype="application/json",
                             headers={"Content-Disposition": "attachment; filename=iocs.json"})

        import csv, io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["ioc_id", "ioc_type", "value", "source_finding_id", "tlp",
                                                    "added_by", "added_at", "notes"])
        writer.writeheader()
        writer.writerows(iocs)
        return Response(buf.getvalue(), mimetype="text/csv",
                         headers={"Content-Disposition": "attachment; filename=iocs.csv"})

    # ==========================================================================
    # FINDINGS -- export to report
    # ==========================================================================

    @app.route("/api/findings/export", methods=["POST"])
    def export_findings_report():
        data = request.json or {}
        finding_ids = data.get("finding_ids") or []
        fmt = data.get("format", "markdown").lower()
        template = data.get("template", "technical_forensic")
        redact_pii = bool(data.get("redact_pii", False))
        include_chain_of_custody = bool(data.get("include_chain_of_custody", True))

        all_findings = {f["finding_id"]: f for f in bridge.get_all_findings(include_deleted=True)}
        selected = [all_findings[fid] for fid in finding_ids if fid in all_findings] if finding_ids \
            else list(all_findings.values())
        if not selected:
            return jsonify({"success": False, "error": "No matching findings to export"}), 404
        if redact_pii:
            selected = [finding_utils.redact_finding(f) for f in selected]

        case_label = bridge.active_investigation_id or "Unknown investigation"

        if fmt == "csv":
            body = finding_utils.render_report_csv(selected)
            return Response(body, mimetype="text/csv",
                             headers={"Content-Disposition": "attachment; filename=findings_report.csv"})
        if fmt == "json":
            return Response(json.dumps(selected, indent=2), mimetype="application/json",
                             headers={"Content-Disposition": "attachment; filename=findings_report.json"})

        body = finding_utils.render_report_markdown(selected, template, case_label, include_chain_of_custody)
        return Response(body, mimetype="text/markdown",
                         headers={"Content-Disposition": "attachment; filename=findings_report.md"})

    # ==========================================================================
    # FINDINGS -- agent enrichment ("Deep Analyze with Agent")
    # ==========================================================================

    @app.route("/api/findings/<finding_id>/enrich", methods=["POST"])
    def enrich_finding(finding_id):
        data = request.json or {}
        action = data.get("action", "deep_analyze")
        finding = bridge.get_finding_by_id(finding_id)
        if not finding:
            return jsonify({"success": False, "error": "Finding not found"}), 404
        if finding.get("source") != "agent":
            return jsonify({"success": False, "error": "Only agent-derived findings can be re-analyzed"}), 400

        agent_id = finding["agent_id"]
        job_id = "job-" + uuid.uuid4().hex[:16]
        now = datetime.now(timezone.utc).isoformat()
        with get_session() as session:
            session.add(EnrichmentJob(
                job_id=job_id, finding_id=finding_id, agent_id=agent_id, action=action,
                status="queued", submitted_at=now,
            ))

        def run_enrichment():
            with get_session() as session:
                job = session.get(EnrichmentJob, job_id)
                job.status = "running"
                session.merge(job)
            try:
                state = bridge.agent_states.get(agent_id, {})
                raw_data_parsed = state.get("raw_data_parsed")
                prior_ai_analysis = state.get("ai_analysis") or {}
                result = asyncio.run(finding_utils.run_deep_analysis(
                    finding.get("agent_label", agent_id), raw_data_parsed, prior_ai_analysis, action
                ))
                if result.get("error"):
                    raise RuntimeError(result.get("raw_exception", result["error"]))

                new_anomalies = result.get("anomalies_found") or []
                if isinstance(new_anomalies, list) and new_anomalies:
                    merged = list(prior_ai_analysis.get("anomalies_found") or []) + new_anomalies
                    state["ai_analysis"] = {**prior_ai_analysis, "anomalies_found": merged,
                                             "summary": result.get("summary", prior_ai_analysis.get("summary", ""))}
                    bridge.agent_states[agent_id] = state
                    bridge.save_snapshot(force=True)

                summary = result.get("summary") or "Deep analysis completed with no summary returned."
                with get_session() as session:
                    job = session.get(EnrichmentJob, job_id)
                    job.status = "succeeded"
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    job.result_summary = summary
                    session.merge(job)
                bridge.log_event(agent_id, f"Deep analysis ({action}) completed: {summary}", level="INFO")
            except Exception as e:
                with get_session() as session:
                    job = session.get(EnrichmentJob, job_id)
                    job.status = "failed"
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    job.error = str(e)
                    session.merge(job)
                bridge.log_event(agent_id, f"Deep analysis ({action}) failed: {e}", level="ERROR")

        threading.Thread(target=run_enrichment, daemon=True).start()
        return jsonify({"success": True, "job_id": job_id})

    @app.route("/api/enrichment-jobs/<job_id>", methods=["GET"])
    def get_enrichment_job(job_id):
        with get_session() as session:
            job = session.get(EnrichmentJob, job_id)
            if not job:
                return jsonify({"success": False, "error": "Job not found"}), 404
            return jsonify({
                "job_id": job.job_id, "finding_id": job.finding_id, "status": job.status,
                "submitted_at": job.submitted_at, "completed_at": job.completed_at,
                "result_summary": job.result_summary, "error": job.error,
            })

    @app.route("/api/findings/<finding_id>/enrichment-jobs", methods=["GET"])
    def list_finding_enrichment_jobs(finding_id):
        with get_session() as session:
            rows = session.query(EnrichmentJob).filter(
                EnrichmentJob.finding_id == finding_id
            ).order_by(EnrichmentJob.submitted_at.desc()).all()
            return jsonify({"jobs": [
                {"job_id": r.job_id, "action": r.action, "status": r.status, "submitted_at": r.submitted_at,
                 "completed_at": r.completed_at, "result_summary": r.result_summary, "error": r.error}
                for r in rows
            ]})

    # ==========================================================================
    # SAVED VIEWS
    # ==========================================================================

    @app.route("/api/saved-views", methods=["GET"])
    def list_saved_views():
        with get_session() as session:
            rows = session.query(SavedView).order_by(SavedView.created_at.desc()).all()
            return jsonify({"views": [
                {"id": r.id, "name": r.name, "filters": r.filters, "created_by": r.created_by,
                 "created_at": r.created_at} for r in rows
            ]})

    @app.route("/api/saved-views", methods=["POST"])
    def create_saved_view():
        data = request.json or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"success": False, "error": "Name is required"}), 400
        with get_session() as session:
            view = SavedView(name=name, filters=data.get("filters") or {},
                              created_by=data.get("created_by", "Analyst"),
                              created_at=datetime.now(timezone.utc).isoformat())
            session.add(view)
            session.flush()
            return jsonify({"success": True, "id": view.id})

    @app.route("/api/saved-views/<int:view_id>", methods=["DELETE"])
    def delete_saved_view(view_id):
        with get_session() as session:
            row = session.get(SavedView, view_id)
            if not row:
                return jsonify({"success": False, "error": "View not found"}), 404
            session.delete(row)
        return jsonify({"success": True})

    @app.route("/api/investigation/report", methods=["GET"])
    def download_investigation_report():
        folder_name = request.args.get("staging_dir", "").strip()
        filename = request.args.get("file", MASTER_REPORT_FILENAME).strip()

        staging_path = resolve_staging_dir(folder_name)
        if not staging_path:
            return jsonify({"success": False, "error": "Invalid or unknown staging directory"}), 404
        if filename not in ALLOWED_REPORT_FILENAMES:
            return jsonify({"success": False, "error": "Unknown report file"}), 400
        if not os.path.isfile(os.path.join(staging_path, filename)):
            return jsonify({"success": False, "error": f"{filename} does not exist yet for this investigation"}), 404

        return send_from_directory(staging_path, filename, as_attachment=True)

    @app.route("/api/topology", methods=["GET"])
    def get_topology():
        return jsonify(bridge.get_topology())

    @app.route("/api/logs", methods=["GET"])
    def get_logs():
        return jsonify({"logs": bridge.logs})

    @app.route("/api/hitl/pending", methods=["GET"])
    def get_pending_hitl():
        pending_list = []
        for agent_name, record in bridge.pending_approvals.items():
            pending_list.append({
                "agent_name": agent_name,
                "timestamp": record["timestamp"],
                "raw_data_parsed": record["raw_data_parsed"],
                "ai_analysis": record["ai_analysis"]
            })
        return jsonify({"pending": pending_list})

    @app.route("/api/hitl/approve", methods=["POST"])
    def approve_hitl():
        data = request.json or {}
        agent_name = data.get("agent_name")
        if not agent_name:
            return jsonify({"success": False, "error": "Missing agent_name"}), 400
        success = bridge.submit_hitl_decision(agent_name=agent_name, action="APPROVE")
        return jsonify({"success": success})

    @app.route("/api/hitl/revise", methods=["POST"])
    def revise_hitl():
        data = request.json or {}
        agent_name = data.get("agent_name")
        feedback = data.get("feedback", "").strip()
        if not agent_name or not feedback:
            return jsonify({"success": False, "error": "Missing agent_name or feedback"}), 400
        success = bridge.submit_hitl_decision(agent_name=agent_name, action="REVISE", feedback=feedback)
        return jsonify({"success": success})

    @app.route("/api/investigation/pause", methods=["POST"])
    def pause_investigation():
        bridge.set_pause_state(True)
        return jsonify({"success": True, "status": "PAUSED"})

    @app.route("/api/investigation/resume", methods=["POST"])
    def resume_investigation():
        bridge.set_pause_state(False)
        return jsonify({"success": True, "status": "RUNNING"})

    @app.route("/api/investigation/stop", methods=["POST"])
    def stop_investigation_endpoint():
        # If a collector subprocess is still running (this was hit during
        # COLLECTING, e.g. via the old Stop Swarm control rather than Stop
        # Collecting), drop the same stop flag so it halts and saves
        # progress instead of running on as an orphaned background process
        # with the UI now showing IDLE and no way to see or stop it.
        if bridge.pipeline_status == "COLLECTING" and bridge.active_investigation_id:
            try:
                with open(os.path.join(bridge.active_investigation_id, "STOP_REQUESTED.flag"), "w", encoding="utf-8") as f:
                    f.write(datetime.now(timezone.utc).isoformat())
            except Exception:
                pass

        # Persist this investigation's topology/findings/log state to its own
        # staging folder before clearing in-memory state, so choosing it again
        # later restores exactly where it was left off.
        bridge.save_snapshot(force=True)
        bridge.pipeline_status = "IDLE"
        bridge.active_investigation_id = None
        bridge.is_paused = False
        bridge.reset_state()
        bridge.log_event("SYSTEM", "Pipeline reset back to IDLE setup state by analyst.", level="WARN")
        return jsonify({"success": True})

    @app.route("/api/investigation/context", methods=["POST"])
    def save_case_context():
        data = request.json or {}
        context_text = data.get("context_text", "").strip()
        staging_dir = data.get("staging_dir")
        try:
            paths_to_write = ["event_context.txt"]
            if staging_dir:
                paths_to_write.append(os.path.join(staging_dir, "event_context.txt"))
            for path in paths_to_write:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(context_text)
            bridge.log_event("SYSTEM", "Case context context brief updated.", level="INFO")
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/upload/file", methods=["POST"])
    def upload_file_to_staging():
        category = request.form.get("category", "ProgramDataList")
        staging_dir = request.form.get("staging_dir")

        if 'file' not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        uploaded_files = request.files.getlist('file')
        results = []

        for file in uploaded_files:
            if file.filename == '':
                continue
            if not staging_dir:
                return jsonify({"success": False, "error": "Invalid staging directory"}), 400

            filename = secure_filename(file.filename)
            target_dir = os.path.join(staging_dir, category, "raw")
            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, filename)

            file.save(target_path)
            bridge.log_event("SYSTEM", f"Uploaded forensic file: {filename} into {category}/raw", level="INFO")

            if filename.lower().endswith('.zip'):
                try:
                    with zipfile.ZipFile(target_path, 'r') as zf:
                        zf.extractall(target_dir, pwd=b'infected')
                        extracted_names = zf.namelist()
                    bridge.log_event("SYSTEM", f"Auto-extracted ZIP '{filename}' ({len(extracted_names)} files) with password 'infected'", level="INFO")
                    results.append({"filename": filename, "extracted": extracted_names})
                except RuntimeError:
                    try:
                        with zipfile.ZipFile(target_path, 'r') as zf:
                            zf.extractall(target_dir)
                            extracted_names = zf.namelist()
                        bridge.log_event("SYSTEM", f"Auto-extracted ZIP '{filename}' ({len(extracted_names)} files) without password", level="INFO")
                        results.append({"filename": filename, "extracted": extracted_names})
                    except Exception as e2:
                        bridge.log_event("SYSTEM", f"ZIP extraction failed for '{filename}': {e2}", level="ERROR")
                        results.append({"filename": filename, "error": str(e2)})
                except Exception as e:
                    bridge.log_event("SYSTEM", f"ZIP extraction failed for '{filename}': {e}", level="ERROR")
                    results.append({"filename": filename, "error": str(e)})
            else:
                results.append({"filename": filename, "path": target_path})

        return jsonify({"success": True, "results": results})

    @app.route("/api/upload/extract", methods=["POST"])
    def upload_and_extract_files():
        staging_dir = request.form.get("staging_dir")

        if 'file' not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        uploaded_files = request.files.getlist('file')
        results = []

        extracted_dir = os.path.join(staging_dir or '.', "Extracted_Files")
        os.makedirs(extracted_dir, exist_ok=True)

        analysis_raw_dir = os.path.join(staging_dir or '.', "ProgramDataList", "raw")
        os.makedirs(analysis_raw_dir, exist_ok=True)

        for file in uploaded_files:
            if file.filename == '':
                continue
            filename = secure_filename(file.filename)
            dest_path = os.path.join(extracted_dir, filename)
            file.save(dest_path)

            if filename.lower().endswith('.zip'):
                try:
                    with zipfile.ZipFile(dest_path, 'r') as zf:
                        zf.extractall(extracted_dir, pwd=b'infected')
                        extracted_names = zf.namelist()
                    bridge.log_event("FILE_EXTRACTOR", f"Extracted malware ZIP '{filename}': {extracted_names}", level="WARN")
                    for name in extracted_names:
                        src = os.path.join(extracted_dir, name)
                        if os.path.isfile(src):
                            shutil.copy2(src, os.path.join(analysis_raw_dir, os.path.basename(name)))
                    results.append({"filename": filename, "extracted": extracted_names, "staged_for_analysis": True})
                except Exception:
                    try:
                        with zipfile.ZipFile(dest_path, 'r') as zf:
                            zf.extractall(extracted_dir)
                            extracted_names = zf.namelist()
                        for name in extracted_names:
                            src = os.path.join(extracted_dir, name)
                            if os.path.isfile(src):
                                shutil.copy2(src, os.path.join(analysis_raw_dir, os.path.basename(name)))
                        bridge.log_event("FILE_EXTRACTOR", f"Extracted ZIP '{filename}' (no password): {extracted_names}", level="WARN")
                        results.append({"filename": filename, "extracted": extracted_names, "staged_for_analysis": True})
                    except Exception as e2:
                        bridge.log_event("FILE_EXTRACTOR", f"Failed to extract '{filename}': {e2}", level="ERROR")
                        results.append({"filename": filename, "error": str(e2)})
            else:
                shutil.copy2(dest_path, os.path.join(analysis_raw_dir, filename))
                bridge.log_event("FILE_EXTRACTOR", f"Staged '{filename}' for File Analysis pipeline", level="INFO")
                results.append({"filename": filename, "path": dest_path, "staged_for_analysis": True})

        return jsonify({"success": True, "results": results})

    @app.route("/api/agents", methods=["GET"])
    def list_agents():
        agents_data = []
        for agent_id, node in bridge.nodes.items():
            state_record = bridge.agent_states.get(agent_id, {})
            hitl_record = bridge.pending_approvals.get(agent_id, {})
            prompt = bridge.prompt_overrides.get(agent_id, f"Baseline System Prompt for {node['label']}")
            agents_data.append({
                "id": agent_id,
                "label": node["label"],
                "type": node["type"],
                "state": node["state"],
                "parent": node["parent"],
                "role": node["role"],
                "system_prompt": prompt,
                "raw_data_parsed": hitl_record.get("raw_data_parsed") or state_record.get("raw_data_parsed"),
                "ai_analysis": hitl_record.get("ai_analysis") or state_record.get("ai_analysis")
            })
        return jsonify({"agents": agents_data})

    @app.route("/api/agents/<agent_name>/prompt", methods=["POST"])
    def update_agent_prompt(agent_name):
        data = request.json or {}
        new_prompt = data.get("system_prompt", "").strip()
        if not new_prompt:
            return jsonify({"success": False, "error": "Prompt cannot be empty"}), 400
        bridge.prompt_overrides[agent_name] = new_prompt
        bridge.log_event(agent_name, "System prompt overridden by analyst.", level="INFO")
        return jsonify({"success": True, "agent_name": agent_name, "system_prompt": new_prompt})

    def _run_collector_subprocess(staging_dir, drive_letter, scope):
        """Spawns the collector subprocess, streams its stdout into the live
        log, and returns 'completed' / 'stopped' / 'failed'. 'stopped'
        specifically means the analyst clicked Stop Collecting: the flag
        file it left behind made the collector save collection_progress.json
        and exit cleanly (code 0), rather than being killed -- that's what
        lets Continue Collecting resume from exactly where it left off
        instead of redoing everything."""
        collector_cmd = [
            sys.executable, "-m", "collectors.collector",
            "--drive", drive_letter,
            "--staging", os.path.abspath(staging_dir),
            "--scope", scope,
        ]
        proc = subprocess.Popen(
            collector_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            errors='replace',
            cwd=PROJECT_ROOT,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        for line in iter(proc.stdout.readline, ''):
            bridge.log_event("COLLECTOR", line.strip(), level="INFO")
        proc.stdout.close()
        remaining_err = proc.stderr.read()
        proc.stderr.close()
        proc.wait(timeout=1800)
        if proc.returncode != 0:
            err_msg = remaining_err[-500:] if remaining_err else "Unknown error"
            bridge.log_event("COLLECTOR", f"Collection failed: {err_msg}", level="ERROR")
            return "failed"

        progress_path = os.path.join(staging_dir, "collection_progress.json")
        if os.path.isfile(progress_path):
            try:
                with open(progress_path, "r", encoding="utf-8") as f:
                    progress = json.load(f)
                if progress.get("stopped"):
                    return "stopped"
            except Exception:
                pass
        return "completed"

    def _run_agent_swarm(staging_dir, scope):
        from agents.orchestrators.master_analyst import MasterAnalystAgent
        master = MasterAnalystAgent()
        final_report = asyncio.run(master.execute_full_investigation(staging_dir=staging_dir, scope=scope))

        father_errors = final_report.get("father_agent_errors", {})
        father_reports = final_report.get("father_agent_reports", {})
        if father_errors and not father_reports:
            # Every father agent that was supposed to run failed -- there's
            # a written report, but it holds nothing but errors, so this
            # was not a completed investigation.
            bridge.pipeline_status = "ERROR"
            bridge.log_event("MASTER", f"Investigation failed: {father_errors}", level="ERROR")
        elif father_errors:
            bridge.pipeline_status = "COMPLETED"
            bridge.log_event(
                "MASTER",
                f"Investigation completed with partial results -- {list(father_errors.keys())} failed "
                f"and were skipped; see Master_Executive_Intelligence_Report.json for what did complete.",
                level="WARN",
            )
        else:
            bridge.pipeline_status = "COMPLETED"
            bridge.log_event("MASTER", "Investigation completed successfully!", level="INFO")

    @app.route("/api/investigation/start", methods=["POST"])
    def start_investigation():
        data = request.json or {}
        staging_dir = data.get("staging_dir")
        scope = data.get("scope", "ALL").upper()
        drive_letter = data.get("drive_letter", "SKIP").strip()
        context_text = data.get("context_text", "").strip()

        if bridge.pipeline_status in ("RUNNING", "COLLECTING"):
            return jsonify({"success": False, "error": "Investigation is already running"}), 400

        from datetime import datetime
        is_new_investigation = not staging_dir or staging_dir == "NEW"
        if is_new_investigation:
            staging_dir = f"investigation_staging_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        os.makedirs(staging_dir, exist_ok=True)

        if context_text:
            with open("event_context.txt", "w", encoding="utf-8") as f:
                f.write(context_text)
            with open(os.path.join(staging_dir, "event_context.txt"), "w", encoding="utf-8") as f:
                f.write(context_text)

        # A brand new investigation starts from a clean slate; resuming an
        # existing one restores whatever topology/findings/log state it was
        # last left with instead of wiping it.
        if is_new_investigation:
            bridge.reset_state()
        else:
            bridge.load_snapshot(staging_dir)
        bridge.is_paused = False
        bridge.pause_event.set()
        bridge.active_investigation_id = staging_dir
        bridge.log_event("MASTER", f"Starting investigation scope {scope} on staging: {staging_dir}", level="INFO")

        def run_wrapper():
            try:
                # Phase 1: Run collector if drive was specified
                if drive_letter != "SKIP":
                    bridge.log_event("COLLECTOR", f"Starting evidence collection on {drive_letter} into {staging_dir}", level="INFO")
                    bridge.update_node_state("Master_Analyst_Agent", "GREEN")
                    bridge.pipeline_status = "COLLECTING"
                    outcome = _run_collector_subprocess(staging_dir, drive_letter, scope)
                    if outcome == "failed":
                        bridge.pipeline_status = "ERROR"
                        return
                    if outcome == "stopped":
                        bridge.pipeline_status = "COLLECTION_STOPPED"
                        bridge.log_event(
                            "COLLECTOR",
                            "Evidence collection stopped -- click Continue Collecting to resume from where it left off.",
                            level="WARN",
                        )
                        return
                    bridge.log_event("COLLECTOR", "Evidence collection completed successfully", level="INFO")

                # Phase 2: AI Agent Swarm Analysis
                bridge.pipeline_status = "RUNNING"
                _run_agent_swarm(staging_dir, scope)
            except subprocess.TimeoutExpired:
                bridge.pipeline_status = "ERROR"
                bridge.log_event("COLLECTOR", "Collection timed out after 30 minutes", level="ERROR")
            except Exception as e:
                bridge.pipeline_status = "ERROR"
                bridge.log_event("MASTER", f"Investigation encountered error: {e}", level="ERROR")

        thread = threading.Thread(target=run_wrapper, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "status": "COLLECTING" if drive_letter != "SKIP" else "RUNNING",
            "staging_dir": staging_dir,
            "scope": scope
        })

    @app.route("/api/investigation/stop-collecting", methods=["POST"])
    def stop_collecting():
        """Graceful stop: drops a flag file the collector subprocess checks
        between categories/steps, so it finishes whatever single step it's
        mid-way through, saves collection_progress.json, and exits cleanly
        -- as opposed to killing the subprocess outright, which would risk
        a half-written file and would lose the "how far did we get" record
        Continue Collecting depends on."""
        if bridge.pipeline_status != "COLLECTING":
            return jsonify({"success": False, "error": "Not currently collecting evidence."}), 400
        staging_dir = bridge.active_investigation_id
        if not staging_dir:
            return jsonify({"success": False, "error": "No active investigation."}), 400
        try:
            os.makedirs(staging_dir, exist_ok=True)
            with open(os.path.join(staging_dir, "STOP_REQUESTED.flag"), "w", encoding="utf-8") as f:
                f.write(datetime.now(timezone.utc).isoformat())
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
        bridge.log_event(
            "COLLECTOR",
            "Stop requested by analyst -- will halt after the current collection step finishes and save progress.",
            level="WARN",
        )
        return jsonify({"success": True})

    @app.route("/api/investigation/continue-collecting", methods=["POST"])
    def continue_collecting():
        data = request.json or {}
        staging_dir = data.get("staging_dir") or bridge.active_investigation_id
        if not staging_dir or not resolve_staging_dir(staging_dir):
            return jsonify({"success": False, "error": "Invalid or unknown staging directory."}), 404
        if bridge.pipeline_status in ("RUNNING", "COLLECTING"):
            return jsonify({"success": False, "error": "An investigation is already active."}), 400

        progress_path = os.path.join(staging_dir, "collection_progress.json")
        if not os.path.isfile(progress_path):
            return jsonify({"success": False, "error": "No saved collection progress found for this investigation."}), 404
        try:
            with open(progress_path, "r", encoding="utf-8") as f:
                progress = json.load(f)
        except Exception as e:
            return jsonify({"success": False, "error": f"Could not read collection progress: {e}"}), 500

        drive_letter = progress.get("drive_letter")
        scope = progress.get("scope", "ALL")
        if not drive_letter:
            return jsonify({"success": False, "error": "No drive letter recorded for this collection -- cannot resume automatically."}), 400

        stop_flag = os.path.join(staging_dir, "STOP_REQUESTED.flag")
        if os.path.isfile(stop_flag):
            try:
                os.remove(stop_flag)
            except Exception:
                pass

        bridge.load_snapshot(staging_dir)
        bridge.is_paused = False
        bridge.pause_event.set()
        bridge.active_investigation_id = staging_dir
        bridge.update_node_state("Master_Analyst_Agent", "GREEN")
        bridge.pipeline_status = "COLLECTING"
        done = len(progress.get("completed_categories", []))
        bridge.log_event(
            "COLLECTOR",
            f"Resuming evidence collection into {staging_dir} ({done} categor{'y' if done == 1 else 'ies'} "
            f"already collected -- continuing from where it left off).",
            level="INFO",
        )

        def continue_wrapper():
            try:
                outcome = _run_collector_subprocess(staging_dir, drive_letter, scope)
                if outcome == "failed":
                    bridge.pipeline_status = "ERROR"
                    return
                if outcome == "stopped":
                    bridge.pipeline_status = "COLLECTION_STOPPED"
                    bridge.log_event("COLLECTOR", "Evidence collection stopped again -- click Continue Collecting to resume.", level="WARN")
                    return
                bridge.log_event("COLLECTOR", "Evidence collection completed successfully", level="INFO")
                bridge.pipeline_status = "RUNNING"
                _run_agent_swarm(staging_dir, scope)
            except subprocess.TimeoutExpired:
                bridge.pipeline_status = "ERROR"
                bridge.log_event("COLLECTOR", "Collection timed out after 30 minutes", level="ERROR")
            except Exception as e:
                bridge.pipeline_status = "ERROR"
                bridge.log_event("MASTER", f"Investigation encountered error: {e}", level="ERROR")

        thread = threading.Thread(target=continue_wrapper, daemon=True)
        thread.start()
        return jsonify({"success": True, "status": "COLLECTING", "staging_dir": staging_dir})
