import os
import sys
import json
import threading
import asyncio
import shutil
import subprocess
import zipfile
from flask import render_template, jsonify, request
from werkzeug.utils import secure_filename
from bridge.hitl_bridge import bridge


def register_routes(app):
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, "uploads")
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    investigation_thread = [None]

    @app.route("/")
    def index_dashboard():
        return render_template("dashboard.html")

    @app.route("/topology")
    def topology_view():
        return render_template("topology.html")

    @app.route("/agents")
    def agents_control():
        return render_template("agents.html")

    @app.route("/api/status", methods=["GET"])
    def get_status():
        return jsonify({
            "execution_mode": bridge.execution_mode,
            "pipeline_status": bridge.pipeline_status,
            "active_investigation_id": bridge.active_investigation_id,
            "pending_count": len(bridge.pending_approvals),
            "total_nodes": len(bridge.nodes),
            "approved_count": sum(1 for n in bridge.nodes.values() if n["state"] == "BLUE"),
            "active_count": sum(1 for n in bridge.nodes.values() if n["state"] in ["GREEN", "YELLOW"]),
            "is_paused": bridge.is_paused
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
        if not folder_name:
            return jsonify({"success": False, "error": "folder_name required"}), 400
        target = os.path.join(PROJECT_ROOT, folder_name)
        if not os.path.isdir(target):
            return jsonify({"success": False, "error": "Investigation not found"}), 404
        try:
            import shutil
            shutil.rmtree(target)
            bridge.log_event("SYSTEM", f"Deleted investigation session: {folder_name}", level="WARN")
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

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
        bridge.pipeline_status = "IDLE"
        bridge.active_investigation_id = None
        bridge.is_paused = False
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

    @app.route("/api/investigation/start", methods=["POST"])
    def start_investigation():
        data = request.json or {}
        staging_dir = data.get("staging_dir")
        scope = data.get("scope", "ALL").upper()
        drive_letter = data.get("drive_letter", "SKIP").strip()
        context_text = data.get("context_text", "").strip()

        if bridge.pipeline_status == "RUNNING":
            return jsonify({"success": False, "error": "Investigation is already running"}), 400

        from datetime import datetime
        if not staging_dir or staging_dir == "NEW":
            staging_dir = f"investigation_staging_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        os.makedirs(staging_dir, exist_ok=True)

        if context_text:
            with open("event_context.txt", "w", encoding="utf-8") as f:
                f.write(context_text)
            with open(os.path.join(staging_dir, "event_context.txt"), "w", encoding="utf-8") as f:
                f.write(context_text)

        bridge._init_topology_nodes()
        bridge.is_paused = False
        bridge.pause_event.set()
        bridge.pipeline_status = "RUNNING"
        bridge.active_investigation_id = staging_dir
        bridge.log_event("MASTER", f"Starting investigation scope {scope} on staging: {staging_dir}", level="INFO")

        def run_wrapper():
            try:
                # Phase 1: Run collector if drive was specified
                if drive_letter != "SKIP":
                    bridge.log_event("COLLECTOR", f"Starting evidence collection on {drive_letter} into {staging_dir}", level="INFO")
                    bridge.update_node_state("Master_Analyst_Agent", "GREEN")
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
                        bridge.pipeline_status = "ERROR"
                        return
                    bridge.log_event("COLLECTOR", "Evidence collection completed successfully", level="INFO")

                # Phase 2: AI Agent Swarm Analysis
                from agents.orchestrators.master_analyst import MasterAnalystAgent
                master = MasterAnalystAgent()
                asyncio.run(master.execute_full_investigation(staging_dir=staging_dir, scope=scope))
                bridge.pipeline_status = "COMPLETED"
                bridge.log_event("MASTER", "Investigation completed successfully!", level="INFO")
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
            "status": "RUNNING",
            "staging_dir": staging_dir,
            "scope": scope
        })
