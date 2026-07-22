import os
import sys
import json
import shutil
import threading
import asyncio
import zipfile
from flask import Flask, render_template, jsonify, request, redirect, url_for
from werkzeug.utils import secure_filename
from web_hitl_bridge import bridge

# Prevent cp1252 encoding errors on Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

investigation_thread = None

@app.route("/")
def index_dashboard():
    """📊 Global Control Dashboard View"""
    return render_template("dashboard.html")

@app.route("/topology")
def topology_view():
    """🗺️ Dynamic Topology DAG Canvas View"""
    return render_template("topology.html")

@app.route("/agents")
def agents_control():
    """⚙️ Agent Management Control Center View"""
    return render_template("agents.html")

# ==========================================
# REST API ENDPOINTS
# ==========================================

@app.route("/api/status", methods=["GET"])
def get_status():
    """System status and telemetry summary."""
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
    """Toggles global execution mode between SUPERVISED and AUTOMATIC."""
    data = request.json or {}
    new_mode = data.get("mode", "SUPERVISED").upper()
    if new_mode in ["SUPERVISED", "AUTOMATIC"]:
        bridge.execution_mode = new_mode
        bridge.log_event("SYSTEM", f"Global execution mode switched to: {new_mode}", level="WARN")
        return jsonify({"success": True, "execution_mode": bridge.execution_mode})
    return jsonify({"success": False, "error": "Invalid mode"}), 400

@app.route("/api/drives", methods=["GET"])
def list_drives():
    """Returns detected connected system drives."""
    return jsonify({"drives": bridge.get_available_drives()})

@app.route("/api/investigations/existing", methods=["GET"])
def list_existing_investigations():
    """Returns list of existing investigation folders in directory root."""
    return jsonify({"investigations": bridge.get_existing_investigations()})

@app.route("/api/topology", methods=["GET"])
def get_topology():
    """Returns nodes and links for DAG graph."""
    return jsonify(bridge.get_topology())

@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Returns buffered log entries."""
    return jsonify({"logs": bridge.logs})

@app.route("/api/hitl/pending", methods=["GET"])
def get_pending_hitl():
    """Returns list of sub-agents awaiting decision."""
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
    """Approve a pending agent node."""
    data = request.json or {}
    agent_name = data.get("agent_name")
    if not agent_name:
        return jsonify({"success": False, "error": "Missing agent_name"}), 400

    success = bridge.submit_hitl_decision(agent_name=agent_name, action="APPROVE")
    return jsonify({"success": success})

@app.route("/api/hitl/revise", methods=["POST"])
def revise_hitl():
    """Inject feedback revision for an agent."""
    data = request.json or {}
    agent_name = data.get("agent_name")
    feedback = data.get("feedback", "").strip()
    if not agent_name or not feedback:
        return jsonify({"success": False, "error": "Missing agent_name or feedback"}), 400

    success = bridge.submit_hitl_decision(agent_name=agent_name, action="REVISE", feedback=feedback)
    return jsonify({"success": success})

@app.route("/api/investigation/pause", methods=["POST"])
def pause_investigation():
    """Pauses pipeline execution non-destructively."""
    bridge.set_pause_state(True)
    return jsonify({"success": True, "status": "PAUSED"})

@app.route("/api/investigation/resume", methods=["POST"])
def resume_investigation():
    """Resumes pipeline execution."""
    bridge.set_pause_state(False)
    return jsonify({"success": True, "status": "RUNNING"})

@app.route("/api/investigation/stop", methods=["POST"])
def stop_investigation_endpoint():
    """Forces the pipeline status back to IDLE to return to the homepage setup hub."""
    bridge.pipeline_status = "IDLE"
    bridge.active_investigation_id = None
    bridge.is_paused = False
    bridge.log_event("SYSTEM", "Pipeline reset back to IDLE setup state by analyst.", level="WARN")
    return jsonify({"success": True})

@app.route("/api/investigation/context", methods=["POST"])
def save_case_context():
    """Saves case context brief text directly into event_context.txt."""
    data = request.json or {}
    context_text = data.get("context_text", "").strip()
    staging_dir = data.get("staging_dir")
    
    # Save both in root project folder and staging directory
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
    """Allows uploading target binaries or memory dumps directly to investigation staging folders.
    ZIP files with password 'infected' are automatically extracted."""
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
        
        # Auto-extract ZIP files with password "infected"
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
    """Uses File_Extractor logic to copy uploaded files into the Extracted_Files staging folder,
    then stages them into ProgramDataList/raw for File Analysis pipeline processing.
    ZIP files with password 'infected' are auto-extracted."""
    staging_dir = request.form.get("staging_dir")
    
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
        
    uploaded_files = request.files.getlist('file')
    results = []
    
    extracted_dir = os.path.join(staging_dir or '.', "Extracted_Files")
    os.makedirs(extracted_dir, exist_ok=True)
    
    # Also ensure ProgramDataList/raw exists for analysis pipeline
    analysis_raw_dir = os.path.join(staging_dir or '.', "ProgramDataList", "raw")
    os.makedirs(analysis_raw_dir, exist_ok=True)
    
    for file in uploaded_files:
        if file.filename == '':
            continue
        filename = secure_filename(file.filename)
        dest_path = os.path.join(extracted_dir, filename)
        file.save(dest_path)
        
        # Auto-extract ZIP malware archives
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
            # Non-ZIP: copy directly into ProgramDataList/raw for analysis
            shutil.copy2(dest_path, os.path.join(analysis_raw_dir, filename))
            bridge.log_event("FILE_EXTRACTOR", f"Staged '{filename}' for File Analysis pipeline", level="INFO")
            results.append({"filename": filename, "path": dest_path, "staged_for_analysis": True})
    
    return jsonify({"success": True, "results": results})

@app.route("/api/agents", methods=["GET"])
def list_agents():
    """List agent nodes, states, prompts, and analytical state results."""
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
    """Saves system prompt overrides."""
    data = request.json or {}
    new_prompt = data.get("system_prompt", "").strip()
    if not new_prompt:
        return jsonify({"success": False, "error": "Prompt cannot be empty"}), 400

    bridge.prompt_overrides[agent_name] = new_prompt
    bridge.log_event(agent_name, "System prompt overridden by analyst.", level="INFO")
    return jsonify({"success": True, "agent_name": agent_name, "system_prompt": new_prompt})

@app.route("/api/investigation/start", methods=["POST"])
def start_investigation():
    """Starts or simulates an investigation swarm run based on scope."""
    global investigation_thread
    data = request.json or {}
    staging_dir = data.get("staging_dir")
    scope = data.get("scope", "ALL").upper()
    drive_letter = data.get("drive_letter", "SKIP").strip()
    context_text = data.get("context_text", "").strip()

    if bridge.pipeline_status == "RUNNING":
        return jsonify({"success": False, "error": "Investigation is already running"}), 400

    # Auto-generate staging directory if none exists
    from datetime import datetime
    if not staging_dir or staging_dir == "NEW":
        staging_dir = f"investigation_staging_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    os.makedirs(staging_dir, exist_ok=True)
    
    # Save context brief
    if context_text:
        with open("event_context.txt", "w", encoding="utf-8") as f:
            f.write(context_text)
        with open(os.path.join(staging_dir, "event_context.txt"), "w", encoding="utf-8") as f:
            f.write(context_text)

    # 1. Trigger collector if drive_letter is not "SKIP"
    if drive_letter != "SKIP":
        bridge.log_event("COLLECTOR", f"Initiating drive collection on {drive_letter} into {staging_dir}", level="WARN")
        # Run collector script in staging folder
        try:
            # Construct command: python collector_agent.py drive_letter staging_dir
            # We'll simulate collection setup or launch subprocess
            pass
        except Exception as e:
            bridge.log_event("COLLECTOR", f"Collector execution failed: {e}", level="ERROR")

    # Reset node states before running
    bridge._init_topology_nodes()
    
    bridge.is_paused = False
    bridge.pause_event.set()
    bridge.pipeline_status = "RUNNING"
    bridge.active_investigation_id = staging_dir
    bridge.log_event("MASTER", f"Starting investigation scope {scope} on staging: {staging_dir}", level="INFO")
    
    # Launch runner thread
    def run_wrapper():
        try:
            from master_analyst_agent import MasterAnalystAgent
            master = MasterAnalystAgent()
            asyncio.run(master.execute_full_investigation(staging_dir=staging_dir, scope=scope))
            bridge.pipeline_status = "COMPLETED"
            bridge.log_event("MASTER", "Investigation completed successfully!", level="INFO")
        except Exception as e:
            bridge.pipeline_status = "ERROR"
            bridge.log_event("MASTER", f"Investigation encountered error: {e}", level="ERROR")

    investigation_thread = threading.Thread(target=run_wrapper, daemon=True)
    investigation_thread.start()

    return jsonify({
        "success": True, 
        "status": "RUNNING", 
        "staging_dir": staging_dir,
        "scope": scope
    })


if __name__ == "__main__":
    print("="*60)
    print("[SERVER] IAI (Investigate with AI) Platform Server Starting...")
    print("[SERVER] Dashboard URL: http://127.0.0.1:5000/")
    print("="*60)
    app.run(host="0.0.0.0", port=5000, debug=True)
