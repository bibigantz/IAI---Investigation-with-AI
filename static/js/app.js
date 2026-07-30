// Global Platform State
let currentState = {
    execution_mode: "SUPERVISED",
    pipeline_status: "IDLE",
    is_paused: false,
    pending_approvals: [],
    agents: [],
    topology: { nodes: [], links: [] },
    selectedAgentId: null,
    selectedStagingDir: null
};

// Canvas pan / zoom / maximize state
let viewportTransform = { x: 0, y: 0, scale: 1 };
let isPanning = false;
let panStart = { x: 0, y: 0 };
let isMaximized = false;

// Initialize App
document.addEventListener("DOMContentLoaded", () => {
    fetchStatus();
    fetchLogs();
    fetchTopology();
    fetchAgents();
    loadSetupData();
    initCanvasInteraction();
    onScopeChange();

    // Set up polling loop every 2 seconds
    setInterval(() => {
        fetchStatus();
        fetchLogs();
        fetchTopology();
        fetchAgents();
    }, 2000);
});

// ==========================================
// API FETCH & STATE UPDATE FUNCTIONS
// ==========================================

async function fetchStatus() {
    try {
        const res = await fetch("/api/status");
        const data = await res.json();
        
        currentState.execution_mode = data.execution_mode;
        currentState.pipeline_status = data.pipeline_status;
        currentState.is_paused = data.is_paused;
        currentState.active_investigation_id = data.active_investigation_id;

        // Toggle Setup Hub vs Active Dashboard visibility
        const setupHub = document.getElementById("setup-hub");
        const activeDashboard = document.getElementById("active-dashboard");
        
        if (setupHub && activeDashboard) {
            if (data.pipeline_status === "IDLE") {
                setupHub.style.display = "block";
                activeDashboard.style.display = "none";
            } else {
                setupHub.style.display = "none";
                activeDashboard.style.display = "block";
            }
        }
        
        // Update Navbar & KPI UI
        const modeText = document.getElementById("mode-text");
        const modeBtn = document.getElementById("btn-toggle-mode");
        if (modeText) modeText.textContent = data.execution_mode;
        if (modeBtn) {
            modeBtn.className = `mode-toggle-btn active ${data.execution_mode.toLowerCase()}`;
        }

        const navBadge = document.getElementById("nav-pending-badge");
        if (navBadge) navBadge.textContent = data.pending_count;

        // Update active dashboard play/pause button states
        const btnPause = document.getElementById("btn-pause-pipeline");
        const btnResume = document.getElementById("btn-resume-pipeline");
        if (btnPause && btnResume) {
            if (data.is_paused) {
                btnPause.style.display = "none";
                btnResume.style.display = "inline-flex";
            } else {
                btnPause.style.display = "inline-flex";
                btnResume.style.display = "none";
            }
        }

        const kpiPipeline = document.getElementById("kpi-pipeline");
        if (kpiPipeline) kpiPipeline.textContent = data.pipeline_status;

        const kpiMode = document.getElementById("kpi-mode");
        if (kpiMode) kpiMode.textContent = data.execution_mode;

        const kpiPending = document.getElementById("kpi-pending");
        if (kpiPending) kpiPending.textContent = data.pending_count;

        const kpiNodes = document.getElementById("kpi-nodes");
        if (kpiNodes) kpiNodes.textContent = data.total_nodes;

        const kpiInv = document.getElementById("kpi-investigation");
        if (kpiInv) kpiInv.textContent = data.active_investigation_id || "No Active Investigation";

    } catch (e) {
        console.error("Status fetch error:", e);
    }
}

async function loadSetupData() {
    try {
        // Load logical drives
        const driveRes = await fetch("/api/drives");
        const driveData = await driveRes.json();
        const selector = document.getElementById("drive-selector");
        if (selector) {
            selector.innerHTML = `<option value="SKIP">Skip Drive Collection (Use Uploaded/Pre-staged Files)</option>`;
            driveData.drives.forEach(drive => {
                selector.innerHTML += `<option value="${drive.letter}:">${drive.letter}: Drive (${drive.path})</option>`;
            });
        }

        // Load existing investigations
        const invRes = await fetch("/api/investigations/existing");
        const invData = await invRes.json();
        const listContainer = document.getElementById("existing-sessions-list");
        if (listContainer) {
            listContainer.innerHTML = "";
            if (invData.investigations.length === 0) {
                listContainer.innerHTML = `<div style="padding:1rem; color:var(--text-dim); text-align:center;">No previous investigations found.</div>`;
                return;
            }
            invData.investigations.forEach((inv, index) => {
                const checked = index === 0 ? "checked" : "";
                if (index === 0) currentState.selectedStagingDir = inv.folder_name;
                
                listContainer.innerHTML += `
                    <div style="display:flex; align-items:center; gap:0.75rem; padding:0.75rem; background:rgba(255,255,255,0.02); border:1px solid var(--card-border); border-radius:6px; margin-bottom:0.5rem; cursor:pointer;" onclick="selectStagingFolder('${inv.folder_name}')">
                        <input type="radio" name="existing-session" id="session-${inv.folder_name}" value="${inv.folder_name}" ${checked}>
                        <div style="flex:1;">
                            <div style="font-weight:600; font-size:0.85rem; color:var(--accent-cyan);">${inv.folder_name}</div>
                            <div style="font-size:0.75rem; color:var(--text-muted); display:flex; gap:1rem; margin-top:0.25rem;">
                                <span>Modified: ${inv.mtime}</span>
                                <span>Files: ${inv.raw_count + inv.meta_count}</span>
                                <span>Report: ${inv.has_master_report ? '✅ Yes' : '⚫ No'}</span>
                            </div>
                        </div>
                        <button class="btn btn-outline" style="padding:0.2rem 0.5rem; font-size:0.7rem; border-color:var(--accent-red); color:var(--accent-red); flex-shrink:0;" onclick="event.stopPropagation(); deleteInvestigation('${inv.folder_name}')">🗑</button>
                    </div>
                `;
            });
        }
    } catch (e) {
        console.error("Load setup data error:", e);
    }
}

function selectStagingFolder(folderName) {
    currentState.selectedStagingDir = folderName;
    const radio = document.getElementById(`session-${folderName}`);
    if (radio) radio.checked = true;
}

async function deleteInvestigation(folderName) {
    if (!confirm(`Delete investigation "${folderName}"? This cannot be undone.`)) return;
    try {
        const res = await fetch("/api/investigations/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ folder_name: folderName })
        });
        const data = await res.json();
        if (data.success) {
            loadSetupData();
        } else {
            alert("Delete failed: " + data.error);
        }
    } catch (e) {
        console.error("Delete error:", e);
    }
}

function onScopeChange() {
    const scope = document.getElementById("scope-selector").value;
    const fileArea = document.getElementById("file-upload-area");
    const memoryArea = document.getElementById("memory-upload-area");
    const extractorArea = document.getElementById("extractor-upload-area");

    if (fileArea) fileArea.style.display = (scope === "ALL" || scope === "FILE") ? "block" : "none";
    if (memoryArea) memoryArea.style.display = (scope === "ALL" || scope === "MEMORY") ? "block" : "none";
    if (extractorArea) extractorArea.style.display = (scope === "ALL" || scope === "FILE") ? "block" : "none";
}

async function launchNewSwarm() {
    const driveLetter = document.getElementById("drive-selector").value;
    const scope = document.getElementById("scope-selector").value;
    const contextText = document.getElementById("setup-case-context").value.trim();

    // Validate required arguments based on scope
    if (driveLetter === "SKIP" && scope !== "MEMORY") {
        const fileUploader = document.getElementById("file-uploader");
        const hasFiles = fileUploader && fileUploader.files.length > 0;
        if (scope === "FILE" && !hasFiles) {
            alert("File / Malware Analysis scope requires either a target drive or file uploads. Please select a drive or attach files.");
            return;
        }
        if (scope === "ALL" && !hasFiles) {
            alert("Full System Analysis scope requires a target drive for collection. Please select a drive or upload files.");
            return;
        }
        if (scope === "WINDOWS") {
            alert("Windows Forensics scope requires a target drive. Please select a connected drive.");
            return;
        }
    }
    if (scope === "MEMORY" && driveLetter === "SKIP") {
        const memoryUploader = document.getElementById("memory-uploader");
        const hasMemory = memoryUploader && memoryUploader.files.length > 0;
        if (!hasMemory) {
            alert("Memory Analysis scope requires a memory dump file. Please attach a .raw, .dmp, or .vmem file.");
            return;
        }
    }
    // Create new unique staging timestamp
    const stagingDir = "NEW";

    // 1. Submit Launch Configuration
    try {
        const res = await fetch("/api/investigation/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                staging_dir: stagingDir,
                scope: scope,
                drive_letter: driveLetter,
                context_text: contextText
            })
        });
        const data = await res.json();
        if (data.success) {
            const actualStagingDir = data.staging_dir;
            
            // 2. Upload files if selected
            await handleFileUploads(actualStagingDir);
            
            fetchStatus();
        } else {
            alert("Error launching pipeline: " + data.error);
        }
    } catch (e) {
        console.error("New investigation error:", e);
    }
}

async function handleFileUploads(stagingDir) {
    const fileUploader = document.getElementById("file-uploader");
    const memoryUploader = document.getElementById("memory-uploader");
    const extractorUploader = document.getElementById("extractor-uploader");

    if (fileUploader && fileUploader.files.length > 0) {
        for (let i = 0; i < fileUploader.files.length; i++) {
            const formData = new FormData();
            formData.append("category", "ProgramDataList");
            formData.append("staging_dir", stagingDir);
            formData.append("file", fileUploader.files[i]);
            await fetch("/api/upload/file", { method: "POST", body: formData });
        }
    }

    if (memoryUploader && memoryUploader.files.length > 0) {
        for (let i = 0; i < memoryUploader.files.length; i++) {
            const formData = new FormData();
            formData.append("category", "Logs");
            formData.append("staging_dir", stagingDir);
            formData.append("file", memoryUploader.files[i]);
            await fetch("/api/upload/file", { method: "POST", body: formData });
        }
    }

    if (extractorUploader && extractorUploader.files.length > 0) {
        for (let i = 0; i < extractorUploader.files.length; i++) {
            const formData = new FormData();
            formData.append("staging_dir", stagingDir);
            formData.append("file", extractorUploader.files[i]);
            await fetch("/api/upload/extract", { method: "POST", body: formData });
        }
    }
}

async function resumeExistingStaging() {
    if (!currentState.selectedStagingDir) {
        alert("Please select an existing staging folder.");
        return;
    }
    const contextText = document.getElementById("existing-case-context").value.trim();

    try {
        // First save event context if provided
        if (contextText) {
            await fetch("/api/investigation/context", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    context_text: contextText,
                    staging_dir: currentState.selectedStagingDir
                })
            });
        }

        const res = await fetch("/api/investigation/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                staging_dir: currentState.selectedStagingDir,
                scope: "ALL",
                drive_letter: "SKIP",
                context_text: contextText
            })
        });
        const data = await res.json();
        if (data.success) {
            fetchStatus();
        } else {
            alert("Error resuming: " + data.error);
        }
    } catch (e) {
        console.error("Resume staging error:", e);
    }
}

async function fetchLogs() {
    try {
        const res = await fetch("/api/logs");
        const data = await res.json();
        const terminalStream = document.getElementById("terminal-stream");
        if (!terminalStream) return;

        terminalStream.innerHTML = "";
        data.logs.forEach(log => {
            const div = document.createElement("div");
            div.className = `log-line ${log.level}`;
            div.innerHTML = `
                <span class="log-time">${log.timestamp}</span>
                <span class="log-source">[${log.source}]</span>
                <span class="log-msg">${escapeHtml(log.message)}</span>
            `;
            terminalStream.appendChild(div);
        });

        terminalStream.scrollTop = terminalStream.scrollHeight;
    } catch (e) {
        console.error("Fetch logs error:", e);
    }
}

function clearLogs() {
    const terminalStream = document.getElementById("terminal-stream");
    if (terminalStream) terminalStream.innerHTML = "";
}

// ==========================================
// STEERING / PAUSE CONTROLS
// ==========================================

async function pausePipeline() {
    await fetch("/api/investigation/pause", { method: "POST" });
    fetchStatus();
}

async function resumePipeline() {
    await fetch("/api/investigation/resume", { method: "POST" });
    fetchStatus();
}

async function stopPipeline() {
    if (confirm("Stop and return to Launch Hub? Active tasks will be terminated.")) {
        await fetch("/api/investigation/stop", { method: "POST" });
        location.reload();
    }
}

async function returnToHub() {
    if (confirm("Return to Launch Hub? This will stop the active pipeline.")) {
        await fetch("/api/investigation/stop", { method: "POST" });
        location.reload();
    }
}

async function injectQuickContext() {
    const input = document.getElementById("active-quick-context");
    const text = input ? input.value.trim() : "";
    if (!text) return;

    await fetch("/api/investigation/context", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            context_text: text,
            staging_dir: currentState.active_investigation_id
        })
    });
    input.value = "";
}

async function toggleMode() {
    const newMode = currentState.execution_mode === "SUPERVISED" ? "AUTOMATIC" : "SUPERVISED";
    try {
        await fetch("/api/mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode: newMode })
        });
        fetchStatus();
    } catch (e) {
        console.error("Toggle mode error:", e);
    }
}

// ==========================================
// TOPOLOGY DAG CANVAS RENDERING (HIGH SPACING)
// ==========================================

async function fetchTopology() {
    try {
        const res = await fetch("/api/topology");
        const data = await res.json();
        currentState.topology = data;
        renderTopologyCanvas(data);
    } catch (e) {
        console.error("Fetch topology error:", e);
    }
}

function renderTopologyCanvas(data) {
    const svg = document.getElementById("svg-dag");
    if (!svg) return;

    // Use viewport group for pan/zoom transforms
    let viewport = document.getElementById("viewport");
    if (!viewport) {
        viewport = document.createElementNS("http://www.w3.org/2000/svg", "g");
        viewport.id = "viewport";
        svg.appendChild(viewport);
    }
    viewport.innerHTML = "";

    // Set standard high-spacing viewBox (1700 width x 950 height) to prevent text label overlaps
    svg.setAttribute("viewBox", "0 0 1700 950");

    // Position coordinates mapping for structured tree columns
    const positions = {
        // Master Level
        "Master_Analyst_Agent": { x: 850, y: 70 },

        // Father Suite Levels
        "Windows_Forensics_Father_Agent": { x: 420, y: 190 },
        "File_Analysis_Father_Agent": { x: 1050, y: 190 },
        "Memory_Analysis_Father_Agent": { x: 1450, y: 190 },

        // Sub-Masters
        "Master_Execution_Artifacts_Analyzer": { x: 180, y: 310 },
        "Master_Execution_Paths_Analyzer": { x: 550, y: 310 },

        // Execution Artifacts sub-agents (x-spaced, staggered y)
        "Prefetch_Analyzer": { x: 80, y: 440 },
        "Amcache_Analyzer": { x: 180, y: 510 },
        "Shimcache_Analyzer": { x: 280, y: 440 },

        // Malware Paths sub-agents (x-spaced, staggered y)
        "Temp_Folder_Analyzer": { x: 400, y: 440 },
        "Downloads_Folder_Analyzer": { x: 450, y: 510 },
        "ProgramData_Analyzer": { x: 500, y: 440 },
        "Scheduled_Tasks_Analyzer": { x: 550, y: 510 },
        "Services_Analyzer": { x: 600, y: 440 },
        "Drivers_Analyzer": { x: 650, y: 510 },
        "Autoruns_Analyzer": { x: 700, y: 440 },

        // Windows Direct sub-agents (y-staggered below submasters)
        "EVTX_Sysmon_Correlator": { x: 350, y: 640 },
        "Registry_Hive_Miner": { x: 500, y: 710 },
        "Timeline_Anomaly_Detector": { x: 650, y: 640 },

        // File Analysis sub-agents (staggered)
        "PeStudio_Static_Triage_Analyzer": { x: 950, y: 340 },
        "Strings_Analyzer": { x: 1050, y: 410 },
        "Ghidra_Reverse_Engineering_Agent": { x: 1150, y: 340 },

        // Memory Analysis sub-agents (staggered)
        "PsTree_Process_Mapper": { x: 1350, y: 340 },
        "Network_Socket_Correlator": { x: 1450, y: 410 },
        "MalFind_Injected_Code_Analyzer": { x: 1550, y: 340 }
    };

    // Draw connecting edge lines
    data.links.forEach(link => {
        const src = positions[link.source];
        const tgt = positions[link.target];

        if (src && tgt) {
            const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", src.x);
            line.setAttribute("y1", src.y);
            line.setAttribute("x2", tgt.x);
            line.setAttribute("y2", tgt.y);
            line.setAttribute("stroke", "rgba(36, 47, 72, 0.75)");
            line.setAttribute("stroke-width", "2");
            viewport.appendChild(line);
        }
    });

    // Draw nodes
    data.nodes.forEach(node => {
        const pos = positions[node.id];
        if (!pos) return;

        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        g.setAttribute("transform", `translate(${pos.x}, ${pos.y})`);
        g.style.cursor = "pointer";
        g.onclick = () => openNodeModal(node.id);

        // Status coloring
        let color = "#5a6978"; // GRAY
        if (node.state === "GREEN") color = "#00ff88";
        else if (node.state === "YELLOW") color = "#ffb700";
        else if (node.state === "BLUE") color = "#00f3ff";

        const radius = node.type === "master" ? 22 : (node.type === "father" ? 18 : 14);

        // Glow circle
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("r", radius);
        circle.setAttribute("fill", "#0b0e17");
        circle.setAttribute("stroke", color);
        circle.setAttribute("stroke-width", node.state === "YELLOW" ? "4.5" : "2.5");
        if (node.state === "YELLOW") {
            circle.setAttribute("filter", "drop-shadow(0 0 10px #ffb700)");
        }

        g.appendChild(circle);

        // Inner status dot
        const innerDot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        innerDot.setAttribute("r", radius / 2.5);
        innerDot.setAttribute("fill", color);
        g.appendChild(innerDot);

        // Spaced out clean Text Label
        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("y", radius + 15);
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("fill", "#f0f4fd");
        text.setAttribute("font-size", "11px");
        text.setAttribute("font-family", "Inter, sans-serif");
        text.setAttribute("font-weight", "600");
        text.textContent = node.label;
        g.appendChild(text);

        viewport.appendChild(g);
    });

    applyViewportTransform();
}

// ==========================================
// TOPOLOGY CANVAS: PAN / ZOOM / MAXIMIZE
// ==========================================

function applyViewportTransform() {
    const vp = document.getElementById("viewport");
    if (vp) vp.setAttribute("transform", `translate(${viewportTransform.x},${viewportTransform.y}) scale(${viewportTransform.scale})`);
}

function zoomIn() {
    viewportTransform.scale = Math.min(viewportTransform.scale * 1.2, 5);
    applyViewportTransform();
}

function zoomOut() {
    viewportTransform.scale = Math.max(viewportTransform.scale / 1.2, 0.2);
    applyViewportTransform();
}

function resetZoom() {
    viewportTransform = { x: 0, y: 0, scale: 1 };
    applyViewportTransform();
}

function toggleMaximize() {
    const canvas = document.getElementById("topology-canvas");
    const btn = document.getElementById("btn-maximize");
    if (!canvas) return;
    isMaximized = !isMaximized;
    if (isMaximized) {
        canvas.style.position = "fixed";
        canvas.style.top = "0";
        canvas.style.left = "0";
        canvas.style.width = "100vw";
        canvas.style.height = "100vh";
        canvas.style.zIndex = "999";
        canvas.style.borderRadius = "0";
        canvas.style.margin = "0";
        if (btn) btn.textContent = "\u22A1";
    } else {
        canvas.style.position = "relative";
        canvas.style.top = "";
        canvas.style.left = "";
        canvas.style.width = "100%";
        canvas.style.height = "600px";
        canvas.style.zIndex = "";
        canvas.style.borderRadius = "8px";
        canvas.style.margin = "";
        if (btn) btn.textContent = "\u26F6";
    }
}

function initCanvasInteraction() {
    const svg = document.getElementById("svg-dag");
    if (!svg) return;

    svg.addEventListener("mousedown", (e) => {
        // Don't pan if clicking on a node group
        const clickedNode = e.target.closest("g[transform]");
        if (clickedNode && clickedNode.id !== "viewport") return;
        isPanning = true;
        panStart = { x: e.clientX - viewportTransform.x, y: e.clientY - viewportTransform.y };
        svg.style.cursor = "grabbing";
    });

    svg.addEventListener("mousemove", (e) => {
        if (!isPanning) return;
        viewportTransform.x = e.clientX - panStart.x;
        viewportTransform.y = e.clientY - panStart.y;
        applyViewportTransform();
    });

    svg.addEventListener("mouseup", () => { isPanning = false; svg.style.cursor = "grab"; });
    svg.addEventListener("mouseleave", () => { isPanning = false; svg.style.cursor = "grab"; });

    svg.addEventListener("wheel", (e) => {
        e.preventDefault();
        const delta = e.deltaY > 0 ? 0.9 : 1.1;
        viewportTransform.scale = Math.max(0.2, Math.min(5, viewportTransform.scale * delta));
        applyViewportTransform();
    }, { passive: false });

    svg.style.cursor = "grab";
}

// Node Modal Inspector Drawer
async function openNodeModal(agentId) {
    const modal = document.getElementById("node-modal");
    if (!modal) return;

    currentState.selectedAgentId = agentId;
    const node = currentState.topology.nodes.find(n => n.id === agentId);

    document.getElementById("modal-agent-name").textContent = node ? node.label : agentId;
    document.getElementById("modal-agent-role").textContent = node ? node.role : "Agent Node";

    // Fetch details
    const res = await fetch("/api/agents");
    const data = await res.json();
    const agentDetail = data.agents.find(a => a.id === agentId);

    const aiViewer = document.getElementById("modal-ai-report");
    const rawViewer = document.getElementById("modal-raw-data");
    const hitlBanner = document.getElementById("modal-hitl-banner");
    const hitlControls = document.getElementById("modal-hitl-controls");

    if (agentDetail) {
        aiViewer.textContent = agentDetail.ai_analysis ? JSON.stringify(agentDetail.ai_analysis, null, 2) : "No AI report available yet.";
        rawViewer.textContent = agentDetail.raw_data_parsed ? (typeof agentDetail.raw_data_parsed === 'string' ? agentDetail.raw_data_parsed : JSON.stringify(agentDetail.raw_data_parsed, null, 2)) : "No raw data available yet.";

        if (agentDetail.state === "YELLOW") {
            hitlBanner.style.display = "block";
            hitlControls.style.display = "flex";
        } else {
            hitlBanner.style.display = "none";
            hitlControls.style.display = "none";
        }
    }

    modal.style.display = "block";
}

function closeModal() {
    const modal = document.getElementById("node-modal");
    if (modal) modal.style.display = "none";
}

async function submitApproveFromModal() {
    if (!currentState.selectedAgentId) return;
    await fetch("/api/hitl/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: currentState.selectedAgentId })
    });
    closeModal();
    fetchStatus();
    fetchTopology();
}

async function submitReviseFromModal() {
    if (!currentState.selectedAgentId) return;
    const input = document.getElementById("modal-feedback-input");
    const feedback = input ? input.value.trim() : "";
    if (!feedback) {
        alert("Please enter feedback instructions for the agent.");
        return;
    }

    await fetch("/api/hitl/revise", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: currentState.selectedAgentId, feedback: feedback })
    });
    input.value = "";
    closeModal();
    fetchStatus();
    fetchTopology();
}

// ==========================================
// AGENT CONTROL CENTER: GROUPS & TAB VIEW
// ==========================================

async function fetchAgents() {
    const sidebar = document.getElementById("agent-sidebar-list");
    if (!sidebar) return;

    try {
        const res = await fetch("/api/agents");
        const data = await res.json();
        currentState.agents = data.agents;

        sidebar.innerHTML = "";

        // Define groupings by Father Agent/Suite
        const groupings = {
            "Orchestrator Node": [],
            "Windows Forensics Suite": [],
            "File Analysis Suite": [],
            "Memory Analysis Suite": []
        };

        data.agents.forEach(agent => {
            if (agent.type === "master" || agent.type === "father" || agent.type === "submaster") {
                groupings["Orchestrator Node"].push(agent);
            } else if (agent.parent === "Master_Execution_Artifacts_Analyzer" || 
                       agent.parent === "Master_Execution_Paths_Analyzer" || 
                       agent.parent === "Windows_Forensics_Father_Agent") {
                groupings["Windows Forensics Suite"].push(agent);
            } else if (agent.parent === "File_Analysis_Father_Agent") {
                groupings["File Analysis Suite"].push(agent);
            } else if (agent.parent === "Memory_Analysis_Father_Agent") {
                groupings["Memory Analysis Suite"].push(agent);
            }
        });

        // Render grouped sidebar listing
        Object.keys(groupings).forEach(groupName => {
            const list = groupings[groupName];
            if (list.length === 0) return;

            // Render Header
            const header = document.createElement("div");
            header.style.cssText = "font-size:0.75rem; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; letter-spacing:0.5px; padding:0.5rem 0; border-bottom:1px solid rgba(0, 243, 255, 0.15); margin-top:0.75rem; margin-bottom:0.4rem;";
            header.textContent = groupName;
            sidebar.appendChild(header);

            list.forEach(agent => {
                const div = document.createElement("div");
                div.className = `agent-item ${currentState.selectedAgentId === agent.id ? 'selected' : ''}`;
                div.onclick = () => selectAgentInControlCenter(agent.id);

                let dotColor = agent.state || "GRAY";
                div.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div style="font-weight:600; font-size:0.85rem;">${agent.label}</div>
                        <span class="state-dot ${dotColor}"></span>
                    </div>
                    <div style="font-size:0.72rem; color:var(--text-dim); margin-top:0.25rem;">${agent.role}</div>
                `;
                sidebar.appendChild(div);
            });
        });

        if (!currentState.selectedAgentId && data.agents.length > 0) {
            selectAgentInControlCenter(data.agents[0].id);
        } else if (currentState.selectedAgentId) {
            selectAgentInControlCenter(currentState.selectedAgentId);
        }
    } catch (e) {
        console.error("Fetch agents error:", e);
    }
}

function selectAgentInControlCenter(agentId) {
    currentState.selectedAgentId = agentId;
    const agent = currentState.agents.find(a => a.id === agentId);
    if (!agent) return;

    // Highlight item in sidebar
    const items = document.querySelectorAll(".agent-item");
    items.forEach(el => el.classList.remove("selected"));

    const title = document.getElementById("selected-agent-title");
    const role = document.getElementById("selected-agent-role");
    const stateBadge = document.getElementById("selected-agent-state-badge");
    const promptInput = document.getElementById("agent-system-prompt");
    const rawViewer = document.getElementById("agent-raw-viewer");
    const aiViewer = document.getElementById("agent-ai-viewer");
    const hitlArea = document.getElementById("agent-hitl-form-area");

    if (title) title.textContent = agent.label;
    if (role) role.textContent = agent.role;
    if (stateBadge) {
        let dotColor = agent.state || "GRAY";
        stateBadge.innerHTML = `<span class="state-dot ${dotColor}"></span> ${agent.state || 'IDLE'}`;
    }

    if (promptInput) promptInput.value = agent.system_prompt || "";
    if (rawViewer) rawViewer.textContent = agent.raw_data_parsed ? (typeof agent.raw_data_parsed === 'string' ? agent.raw_data_parsed : JSON.stringify(agent.raw_data_parsed, null, 2)) : "No raw tool data parsed yet.";
    if (aiViewer) aiViewer.textContent = agent.ai_analysis ? JSON.stringify(agent.ai_analysis, null, 2) : "No proposed AI analysis report yet.";

    if (hitlArea) {
        hitlArea.style.display = agent.state === "YELLOW" ? "block" : "none";
    }
}

async function savePromptOverride() {
    if (!currentState.selectedAgentId) return;
    const promptInput = document.getElementById("agent-system-prompt");
    const newPrompt = promptInput ? promptInput.value.trim() : "";
    if (!newPrompt) return;

    try {
        await fetch(`/api/agents/${currentState.selectedAgentId}/prompt`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ system_prompt: newPrompt })
        });
    } catch (e) {
        console.error("Save prompt error:", e);
    }
}

async function submitApproveFromPage() {
    if (!currentState.selectedAgentId) return;
    await fetch("/api/hitl/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: currentState.selectedAgentId })
    });
    fetchStatus();
    fetchAgents();
}

async function submitReviseFromPage() {
    if (!currentState.selectedAgentId) return;
    const input = document.getElementById("agent-user-feedback");
    const feedback = input ? input.value.trim() : "";
    if (!feedback) {
        alert("Please enter feedback instructions for the agent.");
        return;
    }

    await fetch("/api/hitl/revise", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: currentState.selectedAgentId, feedback: feedback })
    });
    input.value = "";
    fetchStatus();
    fetchAgents();
}

// Utility: HTML Escaping
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
