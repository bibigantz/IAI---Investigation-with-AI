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

// Tracks whether the Setup Hub was visible on the previous fetchStatus() tick,
// so we know when it just became visible again and should refresh its
// existing-investigations list rather than only on initial page load.
let setupHubVisible = null;

// Canvas pan / zoom / maximize state
let viewportTransform = { x: 0, y: 0, scale: 1 };
let isPanning = false;
let panStart = { x: 0, y: 0 };
let isMaximized = false;

// Trusted, hand-authored inline icon fragments (never built from request/user data —
// safe to inject via innerHTML). Kept tiny and dependency-free.
const ICONS = {
    trash: '<svg class="icon" viewBox="0 0 24 24"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13"/></svg>',
    check: '<svg class="icon" viewBox="0 0 24 24"><polyline points="4 12 9 18 20 6"/></svg>',
    circle: '<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/></svg>',
    warning: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3 22 20H2L12 3z"/><line x1="12" y1="9" x2="12" y2="13.5"/><circle cx="12" cy="16.5" r="0.9" fill="currentColor" stroke="none"/></svg>',
    info: '<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="8" r="0.9" fill="currentColor" stroke="none"/><line x1="12" y1="11" x2="12" y2="16"/></svg>',
    error: '<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>',
    maximize: '<svg class="icon" viewBox="0 0 24 24"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/></svg>',
    minimize: '<svg class="icon" viewBox="0 0 24 24"><path d="M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5"/></svg>',
    download: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3v12"/><polyline points="7 10 12 15 17 10"/><path d="M5 19h14"/></svg>'
};

// Initialize App
document.addEventListener("DOMContentLoaded", () => {
    // Deep-link support: /agents#<agent_id> (e.g. navigated from a Findings card)
    // pre-selects that agent before fetchAgents()'s own auto-select logic runs.
    if (window.location.hash) {
        const hashId = decodeURIComponent(window.location.hash.slice(1));
        if (hashId) currentState.selectedAgentId = hashId;
    }

    fetchStatus();
    fetchLogs();
    fetchTopology();
    fetchAgents();
    fetchFindings();
    loadSetupData();
    initCanvasInteraction();
    initFileHints();
    onScopeChange();

    // Set up polling loop every 2 seconds
    setInterval(() => {
        fetchStatus();
        fetchLogs();
        fetchTopology();
        fetchAgents();
        fetchFindings();
    }, 2000);
});

// ==========================================
// TOASTS + CONFIRM DIALOG (replace native alert()/confirm())
// ==========================================

function showToast(message, type = "info", duration = 4200) {
    const stack = document.getElementById("toast-stack");
    if (!stack) { console.log(`[${type}] ${message}`); return; }

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;

    const icon = document.createElement("span");
    icon.innerHTML = ICONS[type] || ICONS.info;
    toast.appendChild(icon);

    const msg = document.createElement("span");
    msg.className = "toast-msg";
    msg.textContent = message; // textContent only -- never render server/user text as HTML
    toast.appendChild(msg);

    const close = document.createElement("button");
    close.className = "toast-close";
    close.setAttribute("aria-label", "Dismiss");
    close.innerHTML = ICONS.error;
    close.addEventListener("click", () => dismissToast(toast));
    toast.appendChild(close);

    stack.appendChild(toast);
    if (duration > 0) setTimeout(() => dismissToast(toast), duration);
}

function dismissToast(toast) {
    if (!toast || !toast.parentNode) return;
    toast.classList.add("leaving");
    setTimeout(() => toast.remove(), 200);
}

function showConfirm(message, { title = "Please confirm", confirmLabel = "Confirm", tone = "warning" } = {}) {
    const overlay = document.getElementById("confirm-overlay");
    if (!overlay) return Promise.resolve(window.confirm(message));

    return new Promise((resolve) => {
        overlay.innerHTML = "";
        const box = document.createElement("div");
        box.className = "confirm-box";

        const titleEl = document.createElement("div");
        titleEl.className = "confirm-title";
        const icon = document.createElement("span");
        icon.innerHTML = tone === "danger" ? ICONS.error : ICONS.warning;
        titleEl.appendChild(icon);
        const titleText = document.createElement("span");
        titleText.textContent = title;
        titleEl.appendChild(titleText);
        box.appendChild(titleEl);

        const copy = document.createElement("div");
        copy.className = "confirm-copy";
        copy.textContent = message;
        box.appendChild(copy);

        const actions = document.createElement("div");
        actions.className = "confirm-actions";

        const cancelBtn = document.createElement("button");
        cancelBtn.className = "btn btn-outline";
        cancelBtn.textContent = "Cancel";

        const okBtn = document.createElement("button");
        okBtn.className = tone === "danger" ? "btn btn-danger" : "btn btn-warning";
        okBtn.textContent = confirmLabel;

        const finish = (result) => {
            overlay.classList.remove("open");
            setTimeout(() => { overlay.innerHTML = ""; }, 180);
            resolve(result);
        };

        cancelBtn.addEventListener("click", () => finish(false));
        okBtn.addEventListener("click", () => finish(true));
        overlay.addEventListener("click", (e) => { if (e.target === overlay) finish(false); }, { once: true });

        actions.appendChild(cancelBtn);
        actions.appendChild(okBtn);
        box.appendChild(actions);
        overlay.appendChild(box);

        requestAnimationFrame(() => overlay.classList.add("open"));
    });
}

// ==========================================
// NAVBAR USER MENU (Help / Management / Sign out dropdown)
// ==========================================

document.addEventListener("DOMContentLoaded", () => {
    document.addEventListener("click", (e) => {
        const trigger = document.getElementById("nav-user-trigger");
        const dropdown = document.getElementById("nav-user-dropdown");
        if (!trigger || !dropdown) return;
        if (!trigger.contains(e.target) && !dropdown.contains(e.target)) {
            closeUserMenu();
        }
    });
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeUserMenu();
    });
});

function toggleUserMenu(event) {
    event.stopPropagation();
    const trigger = document.getElementById("nav-user-trigger");
    const dropdown = document.getElementById("nav-user-dropdown");
    if (!trigger || !dropdown) return;
    const isOpen = dropdown.classList.toggle("open");
    trigger.setAttribute("aria-expanded", isOpen ? "true" : "false");
}

function closeUserMenu() {
    const trigger = document.getElementById("nav-user-trigger");
    const dropdown = document.getElementById("nav-user-dropdown");
    if (!dropdown || !dropdown.classList.contains("open")) return;
    dropdown.classList.remove("open");
    if (trigger) trigger.setAttribute("aria-expanded", "false");
}

// ==========================================
// THEME (light / dark)
// ==========================================
// The actual <html data-theme="..."> attribute is already set inline in
// <head>, before this file even loads, to avoid a flash of the wrong theme
// on page load (see the inline script in base.html/login.html/
// change_password.html). This section only handles switching it afterward
// and keeping the dropdown's toggle buttons in sync.

function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try { localStorage.setItem("iai_theme", theme); } catch (e) { /* localStorage unavailable -- theme just won't persist */ }
    syncThemeToggleUI(theme);
}

function syncThemeToggleUI(theme) {
    document.querySelectorAll(".theme-toggle-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.value === theme);
    });
}

document.addEventListener("DOMContentLoaded", () => {
    syncThemeToggleUI(document.documentElement.getAttribute("data-theme") || "dark");
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
            const isIdle = data.pipeline_status === "IDLE";
            if (isIdle) {
                setupHub.style.display = "block";
                activeDashboard.style.display = "none";
            } else {
                setupHub.style.display = "none";
                activeDashboard.style.display = "block";
            }
            // Refresh the existing-investigations list whenever the hub
            // transitions from hidden to visible, so a just-finished
            // investigation shows up without requiring a manual page reload.
            if (isIdle && setupHubVisible === false) loadExistingInvestigations();
            setupHubVisible = isIdle;
        }

        // On the Topology / Agent Control Center / Findings pages, hide the
        // page body and show a "no investigation selected" banner instead of
        // an ambiguous empty/idle view when nothing has been chosen yet.
        const noInvBanner = document.getElementById("no-investigation-banner");
        const pageBody = document.getElementById("page-body");
        if (noInvBanner && pageBody) {
            const hasActive = !!data.active_investigation_id;
            noInvBanner.style.display = hasActive ? "none" : "block";
            pageBody.style.display = hasActive ? "" : "none";
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
        if (kpiInv) kpiInv.textContent = data.active_investigation_id || "No active investigation";

        const btnDownload = document.getElementById("btn-download-report");
        if (btnDownload) btnDownload.style.display = data.has_master_report ? "inline-flex" : "none";

        updateCollectionPhaseUI(data);

    } catch (e) {
        console.error("Status fetch error:", e);
    }
}

// Switches which control group shows in the Active Dashboard's steering
// panel based on pipeline_status: collecting evidence, stopped mid-
// collection, or the normal agent-phase controls (Pause/Resume/Stop Swarm) --
// these are mutually exclusive views of the same panel, not stacked.
function updateCollectionPhaseUI(data) {
    const collectingControls = document.getElementById("collecting-controls");
    const stoppedControls = document.getElementById("collection-stopped-controls");
    const agentControls = document.getElementById("agent-phase-controls");
    const banner = document.getElementById("collection-status-banner");
    if (!collectingControls || !stoppedControls || !agentControls || !banner) return; // not on the dashboard

    const status = data.pipeline_status;
    collectingControls.style.display = status === "COLLECTING" ? "flex" : "none";
    stoppedControls.style.display = status === "COLLECTION_STOPPED" ? "flex" : "none";
    agentControls.style.display = (status === "COLLECTING" || status === "COLLECTION_STOPPED") ? "none" : "flex";

    if (status === "COLLECTING" || status === "COLLECTION_STOPPED") {
        banner.style.display = "block";
        const title = document.getElementById("collection-status-title");
        const detail = document.getElementById("collection-status-detail");
        const cp = data.collection_progress;
        if (status === "COLLECTING") {
            title.textContent = "Collecting evidence...";
            detail.textContent = cp
                ? `${cp.completed_categories} categor${cp.completed_categories === 1 ? "y" : "ies"} and ${cp.completed_steps} collection step(s) completed so far.`
                : "Starting up...";
        } else {
            title.textContent = "Evidence collection stopped";
            detail.textContent = cp
                ? `${cp.completed_categories} categor${cp.completed_categories === 1 ? "y" : "ies"} already collected and saved. Click Continue Collecting to pick up where it left off -- nothing will be re-collected.`
                : "Click Continue Collecting to resume.";
        }
    } else {
        banner.style.display = "none";
    }
}

async function stopCollecting() {
    const ok = await showConfirm(
        "Stops evidence collection after the current step finishes. Everything collected so far is saved -- " +
        "you can pick up exactly where this left off with Continue Collecting.",
        { title: "Stop collecting evidence?", confirmLabel: "Stop Collecting", tone: "warning" }
    );
    if (!ok) return;
    try {
        const res = await fetch("/api/investigation/stop-collecting", { method: "POST" });
        const data = await res.json();
        if (data.success) {
            showToast("Stop requested -- will halt after the current step finishes.", "warning");
            fetchStatus();
        } else {
            showToast("Could not stop collecting: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Stop request failed.", "error");
    }
}

async function continueCollecting() {
    try {
        const res = await fetch("/api/investigation/continue-collecting", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ staging_dir: currentState.active_investigation_id }),
        });
        const data = await res.json();
        if (data.success) {
            showToast("Resuming evidence collection.", "success");
            fetchStatus();
        } else {
            showToast("Could not resume collecting: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Resume request failed.", "error");
    }
}

function fileWord(n) { return n === 1 ? "file" : "files"; }

function initFileHints() {
    [["file-uploader", "file-uploader-hint"],
     ["memory-uploader", "memory-uploader-hint"],
     ["extractor-uploader", "extractor-uploader-hint"]].forEach(([inputId, hintId]) => {
        const input = document.getElementById(inputId);
        const hint = document.getElementById(hintId);
        if (!input || !hint) return;
        input.addEventListener("change", () => {
            const n = input.files.length;
            hint.textContent = n > 0 ? `${n} ${fileWord(n)} selected` : "";
            hint.classList.toggle("has-files", n > 0);
        });
    });
}

async function loadSetupData() {
    // Load logical drives and existing investigations independently -- a
    // failure in one (e.g. drive enumeration) must not prevent the other
    // from rendering.
    try {
        const driveRes = await fetch("/api/drives");
        const driveData = await driveRes.json();
        const selector = document.getElementById("drive-selector");
        if (selector) {
            selector.innerHTML = "";
            const skipOpt = document.createElement("option");
            skipOpt.value = "SKIP";
            skipOpt.textContent = "Skip drive collection (use uploaded / pre-staged files)";
            selector.appendChild(skipOpt);

            (driveData.drives || []).forEach(drive => {
                const opt = document.createElement("option");
                opt.value = `${drive.letter}:`;
                opt.textContent = `${drive.letter}: drive (${drive.path})`;
                selector.appendChild(opt);
            });
        }
    } catch (e) {
        console.error("Load drives error:", e);
        showToast("Could not load available drives.", "error");
    }

    await loadExistingInvestigations();
}

async function loadExistingInvestigations(showFeedback = false) {
    const listContainer = document.getElementById("existing-sessions-list");
    if (!listContainer) return;

    try {
        listContainer.innerHTML = "";
        if (showFeedback) {
            const loading = document.createElement("div");
            loading.className = "empty-state";
            loading.textContent = "Searching for investigation folders...";
            listContainer.appendChild(loading);
        }

        const invRes = await fetch("/api/investigations/existing");
        const invData = await invRes.json();
        listContainer.innerHTML = "";

        if (!invData.investigations || invData.investigations.length === 0) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            empty.textContent = "No previous investigations found.";
            listContainer.appendChild(empty);
            if (showFeedback) showToast("No investigation folders found.", "info");
            return;
        }

        invData.investigations.forEach((inv, index) => {
            if (index === 0) currentState.selectedStagingDir = inv.folder_name;
            listContainer.appendChild(buildSessionRow(inv, index === 0));
        });

        if (showFeedback) {
            const n = invData.investigations.length;
            showToast(`Found ${n} investigation ${n === 1 ? "session" : "sessions"}.`, "success");
        }
    } catch (e) {
        console.error("Load existing investigations error:", e);
        showToast("Could not load existing investigation sessions.", "error");
    }
}

function buildSessionRow(inv, checked) {
    const row = document.createElement("div");
    row.className = "session-row" + (checked ? " selected" : "");
    row.dataset.folder = inv.folder_name;

    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "existing-session";
    radio.id = `session-${inv.folder_name}`;
    radio.value = inv.folder_name;
    radio.checked = checked;

    const info = document.createElement("div");
    info.className = "session-info";

    const name = document.createElement("div");
    name.className = "session-name";
    name.textContent = inv.folder_name;

    const meta = document.createElement("div");
    meta.className = "session-meta";

    const modified = document.createElement("span");
    modified.textContent = `Modified ${inv.mtime}`;
    const files = document.createElement("span");
    files.textContent = `${inv.raw_count + inv.meta_count} files`;
    const report = document.createElement("span");
    report.className = inv.has_master_report ? "report-yes" : "report-no";
    report.textContent = inv.has_master_report ? "Report ready" : "No report yet";

    meta.appendChild(modified);
    meta.appendChild(files);
    meta.appendChild(report);
    info.appendChild(name);
    info.appendChild(meta);

    if (inv.has_master_report) {
        const downloadBtn = document.createElement("button");
        downloadBtn.className = "btn btn-ghost btn-icon";
        downloadBtn.title = "Download report";
        downloadBtn.innerHTML = ICONS.download;
        downloadBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            window.location.href = `/api/investigation/report?staging_dir=${encodeURIComponent(inv.folder_name)}`;
        });
        row.appendChild(radio);
        row.appendChild(info);
        row.appendChild(downloadBtn);
    } else {
        row.appendChild(radio);
        row.appendChild(info);
    }

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "btn btn-ghost btn-icon";
    deleteBtn.title = "Delete investigation";
    deleteBtn.innerHTML = ICONS.trash;
    deleteBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        deleteInvestigation(inv.folder_name);
    });

    row.appendChild(deleteBtn);
    row.addEventListener("click", () => selectStagingFolder(inv.folder_name));

    return row;
}

function selectStagingFolder(folderName) {
    currentState.selectedStagingDir = folderName;
    const radio = document.getElementById(`session-${folderName}`);
    if (radio) radio.checked = true;
    document.querySelectorAll(".session-row").forEach(el => {
        el.classList.toggle("selected", el.dataset.folder === folderName);
    });
}

async function deleteInvestigation(folderName) {
    const ok = await showConfirm(
        `Delete investigation "${folderName}"? This cannot be undone.`,
        { title: "Delete investigation", confirmLabel: "Delete", tone: "danger" }
    );
    if (!ok) return;

    try {
        const res = await fetch("/api/investigations/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ folder_name: folderName })
        });
        const data = await res.json();
        if (data.success) {
            showToast("Investigation deleted.", "success");
            loadExistingInvestigations();
        } else {
            showToast("Delete failed: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        console.error("Delete error:", e);
        showToast("Delete request failed.", "error");
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
            showToast("File / Malware Analysis scope requires either a target drive or file uploads.", "warning");
            return;
        }
        if (scope === "ALL" && !hasFiles) {
            showToast("Full System Analysis scope requires a target drive for collection.", "warning");
            return;
        }
        if (scope === "WINDOWS") {
            showToast("Windows Forensics scope requires a connected target drive.", "warning");
            return;
        }
    }
    if (scope === "MEMORY" && driveLetter === "SKIP") {
        const memoryUploader = document.getElementById("memory-uploader");
        const hasMemory = memoryUploader && memoryUploader.files.length > 0;
        if (!hasMemory) {
            showToast("Memory Analysis scope requires a memory dump file (.raw, .dmp, .vmem).", "warning");
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

            showToast("Swarm pipeline launched.", "success");
            fetchStatus();
        } else {
            showToast("Error launching pipeline: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        console.error("New investigation error:", e);
        showToast("Could not reach the server to launch the pipeline.", "error");
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
            formData.append("category", "MemoryDumps");
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
        showToast("Please select an existing staging folder first.", "warning");
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
            showToast("Resuming staged investigation.", "success");
            fetchStatus();
        } else {
            showToast("Error resuming: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        console.error("Resume staging error:", e);
        showToast("Could not reach the server to resume the session.", "error");
    }
}

async function fetchLogs() {
    try {
        const res = await fetch("/api/logs");
        const data = await res.json();
        const terminalStream = document.getElementById("terminal-stream");
        if (!terminalStream) return;

        terminalStream.innerHTML = "";

        if (!data.logs || data.logs.length === 0) {
            const empty = document.createElement("div");
            empty.className = "terminal-empty";
            empty.textContent = "No log activity yet.";
            terminalStream.appendChild(empty);
            return;
        }

        data.logs.forEach(log => {
            const div = document.createElement("div");
            div.className = `log-line ${log.level || ""}`;

            const time = document.createElement("span");
            time.className = "log-time";
            time.textContent = log.timestamp;

            const source = document.createElement("span");
            source.className = "log-source";
            source.textContent = `[${log.source}]`;

            const msg = document.createElement("span");
            msg.className = "log-msg";
            msg.textContent = log.message;

            div.appendChild(time);
            div.appendChild(source);
            div.appendChild(msg);
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
    showToast("Investigation paused.", "warning");
    fetchStatus();
}

async function resumePipeline() {
    await fetch("/api/investigation/resume", { method: "POST" });
    showToast("Investigation resumed.", "success");
    fetchStatus();
}

async function stopPipeline() {
    const ok = await showConfirm(
        "Stop and return to the Launch Hub? Active tasks will be terminated.",
        { title: "Stop swarm", confirmLabel: "Stop", tone: "danger" }
    );
    if (!ok) return;
    await fetch("/api/investigation/stop", { method: "POST" });
    location.reload();
}

async function returnToHub() {
    const ok = await showConfirm(
        "Return to the Launch Hub? This will stop the active pipeline.",
        { title: "Return to Launch Hub", confirmLabel: "Return", tone: "danger" }
    );
    if (!ok) return;
    await fetch("/api/investigation/stop", { method: "POST" });
    location.reload();
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
    showToast("Case context injected into active investigation.", "success");
}

async function toggleMode() {
    const newMode = currentState.execution_mode === "SUPERVISED" ? "AUTOMATIC" : "SUPERVISED";
    try {
        await fetch("/api/mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode: newMode })
        });
        showToast(`Execution mode set to ${newMode}.`, "info");
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

const STATE_COLORS = {
    GRAY: "#5c6773",
    GREEN: "#34d399",
    YELLOW: "#f2a93b",
    BLUE: "#38bdf8"
};

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
        "Temp_Folder_Analyzer": { x: 370, y: 440 },
        "Downloads_Folder_Analyzer": { x: 410, y: 510 },
        "AppData_Public_Paths_Analyzer": { x: 450, y: 440 },
        "ProgramData_Analyzer": { x: 500, y: 510 },
        "Scheduled_Tasks_Analyzer": { x: 550, y: 440 },
        "Services_Analyzer": { x: 600, y: 510 },
        "Drivers_Analyzer": { x: 650, y: 440 },
        "Autoruns_Analyzer": { x: 700, y: 510 },

        // Windows Direct sub-agents (y-staggered below submasters)
        "EVTX_Sysmon_Correlator": { x: 350, y: 640 },
        "Registry_Hive_Miner": { x: 500, y: 710 },
        "Timeline_Anomaly_Detector": { x: 650, y: 640 },

        // File Analysis sub-agents (staggered)
        "PeStudio_Static_Triage_Analyzer": { x: 950, y: 340 },
        "Ghidra_Reverse_Engineering_Agent": { x: 1050, y: 410 },
        "Dynamic_Sandbox_Correlator": { x: 1150, y: 340 },

        // Memory Analysis sub-agents (staggered)
        "PsTree_Process_Mapper": { x: 1350, y: 340 },
        "Network_Socket_Correlator": { x: 1450, y: 410 },
        "MalFind_Injected_Code_Analyzer": { x: 1550, y: 340 },
        "Malfind_Correlator": { x: 1650, y: 410 }
    };

    // Draw connecting edge lines
    (data.links || []).forEach(link => {
        const src = positions[link.source];
        const tgt = positions[link.target];

        if (src && tgt) {
            const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", src.x);
            line.setAttribute("y1", src.y);
            line.setAttribute("x2", tgt.x);
            line.setAttribute("y2", tgt.y);
            line.setAttribute("stroke", "rgba(255, 255, 255, 0.09)");
            line.setAttribute("stroke-width", "1.5");
            viewport.appendChild(line);
        }
    });

    // Draw nodes
    (data.nodes || []).forEach(node => {
        const pos = positions[node.id];
        if (!pos) return;

        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        g.setAttribute("transform", `translate(${pos.x}, ${pos.y})`);
        g.style.cursor = "pointer";
        g.addEventListener("click", () => openNodeModal(node.id));

        const color = STATE_COLORS[node.state] || STATE_COLORS.GRAY;
        const radius = node.type === "master" ? 22 : (node.type === "father" ? 18 : 14);

        // Glow circle
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("r", radius);
        circle.setAttribute("fill", "#0a0c11");
        circle.setAttribute("stroke", color);
        circle.setAttribute("stroke-width", node.state === "YELLOW" ? "4" : "2");
        if (node.state === "YELLOW") {
            circle.setAttribute("filter", "drop-shadow(0 0 9px rgba(242,169,59,0.75))");
        }
        g.appendChild(circle);

        // Inner status dot
        const innerDot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        innerDot.setAttribute("r", radius / 2.5);
        innerDot.setAttribute("fill", color);
        g.appendChild(innerDot);

        // Spaced out clean Text Label
        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("y", radius + 16);
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("fill", "#c7d0dc");
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
        if (btn) btn.innerHTML = ICONS.minimize;
    } else {
        canvas.style.position = "relative";
        canvas.style.top = "";
        canvas.style.left = "";
        canvas.style.width = "100%";
        canvas.style.height = "620px";
        canvas.style.zIndex = "";
        canvas.style.borderRadius = "10px";
        canvas.style.margin = "";
        if (btn) btn.innerHTML = ICONS.maximize;
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
    const overlay = document.getElementById("node-modal-overlay");
    const modal = document.getElementById("node-modal");
    if (!modal) return;

    currentState.selectedAgentId = agentId;
    const node = currentState.topology.nodes.find(n => n.id === agentId);

    document.getElementById("modal-agent-name").textContent = node ? node.label : agentId;
    document.getElementById("modal-agent-role").textContent = node ? node.role : "Agent node";

    // Fetch details
    const res = await fetch("/api/agents");
    const data = await res.json();
    const agentDetail = data.agents.find(a => a.id === agentId);

    const aiViewer = document.getElementById("modal-ai-report");
    const rawViewer = document.getElementById("modal-raw-data");
    const hitlBanner = document.getElementById("modal-hitl-banner");
    const hitlControls = document.getElementById("modal-hitl-controls");

    if (agentDetail) {
        setViewerContent(aiViewer, agentDetail.ai_analysis, "No AI report available yet.");
        setViewerContent(rawViewer, agentDetail.raw_data_parsed, "No raw data available yet.");

        if (agentDetail.state === "YELLOW") {
            hitlBanner.style.display = "flex";
            hitlControls.style.display = "flex";
        } else {
            hitlBanner.style.display = "none";
            hitlControls.style.display = "none";
        }
    }

    modal.classList.add("open");
    if (overlay) overlay.classList.add("open");
}

// Renders parsed/AI output safely via textContent -- this data can originate from
// analyzed malware artifacts, so it must never be interpreted as HTML.
function setViewerContent(el, value, placeholder) {
    if (!el) return;
    if (!value) {
        el.textContent = placeholder;
        el.classList.add("placeholder");
        return;
    }
    el.classList.remove("placeholder");
    el.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function closeModal() {
    const overlay = document.getElementById("node-modal-overlay");
    const modal = document.getElementById("node-modal");
    if (modal) modal.classList.remove("open");
    if (overlay) overlay.classList.remove("open");
}

async function submitApproveFromModal() {
    if (!currentState.selectedAgentId) return;
    await fetch("/api/hitl/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: currentState.selectedAgentId })
    });
    showToast("Findings approved. Swarm resuming.", "success");
    closeModal();
    fetchStatus();
    fetchTopology();
}

async function submitReviseFromModal() {
    if (!currentState.selectedAgentId) return;
    const input = document.getElementById("modal-feedback-input");
    const feedback = input ? input.value.trim() : "";
    if (!feedback) {
        showToast("Enter feedback instructions before requesting a revision.", "warning");
        return;
    }

    await fetch("/api/hitl/revise", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: currentState.selectedAgentId, feedback: feedback })
    });
    input.value = "";
    showToast("Revision feedback sent to the agent.", "info");
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

            const header = document.createElement("div");
            header.className = "agent-group-label";
            header.textContent = groupName;
            sidebar.appendChild(header);

            list.forEach(agent => {
                sidebar.appendChild(buildAgentItem(agent));
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

function buildAgentItem(agent) {
    const div = document.createElement("div");
    div.className = `agent-item ${currentState.selectedAgentId === agent.id ? "selected" : ""}`;
    div.addEventListener("click", () => selectAgentInControlCenter(agent.id));

    const top = document.createElement("div");
    top.className = "agent-item-top";
    const name = document.createElement("div");
    name.className = "agent-item-name";
    name.textContent = agent.label;
    const dot = document.createElement("span");
    dot.className = `state-dot ${agent.state || "GRAY"}`;
    top.appendChild(name);
    top.appendChild(dot);

    const role = document.createElement("div");
    role.className = "agent-item-role";
    role.textContent = agent.role;

    div.appendChild(top);
    div.appendChild(role);
    return div;
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
        stateBadge.innerHTML = "";
        const dot = document.createElement("span");
        dot.className = `state-dot ${agent.state || "GRAY"}`;
        stateBadge.appendChild(dot);
        stateBadge.appendChild(document.createTextNode(agent.state || "IDLE"));
    }

    if (promptInput) promptInput.value = agent.system_prompt || "";
    setViewerContent(rawViewer, agent.raw_data_parsed, "No raw tool data parsed yet.");
    setViewerContent(aiViewer, agent.ai_analysis, "No proposed AI analysis report yet.");

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
        showToast("System prompt override saved.", "success");
    } catch (e) {
        console.error("Save prompt error:", e);
        showToast("Could not save the prompt override.", "error");
    }
}

async function submitApproveFromPage() {
    if (!currentState.selectedAgentId) return;
    await fetch("/api/hitl/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: currentState.selectedAgentId })
    });
    showToast("Findings approved. Swarm resuming.", "success");
    fetchStatus();
    fetchAgents();
}

async function submitReviseFromPage() {
    if (!currentState.selectedAgentId) return;
    const input = document.getElementById("agent-user-feedback");
    const feedback = input ? input.value.trim() : "";
    if (!feedback) {
        showToast("Enter feedback instructions before requesting a revision.", "warning");
        return;
    }

    await fetch("/api/hitl/revise", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: currentState.selectedAgentId, feedback: feedback })
    });
    input.value = "";
    showToast("Revision feedback sent to the agent.", "info");
    fetchStatus();
    fetchAgents();
}

// ==========================================
// FINDINGS TRIAGE VIEW
// ==========================================

let findingsSeverityFilter = "ALL";
let findingsApprovedOnly = false;
let findingsShowDismissed = false;
let findingsShowFalsePositives = false;
let findingsShowExcluded = false;
let selectedFindingIds = new Set();
let expandedClusterKeys = new Set();
let keyboardModeOn = false;
let keyboardFocusIndex = -1;
let mitreLookupCache = null;
let currentDrawerFindingId = null;
let drawerLockInterval = null;
let enrichPollInterval = null;

function confidenceOf(f) {
    return (f.confidence !== undefined && f.confidence !== null) ? f.confidence : 50;
}

function getActorName() {
    return localStorage.getItem("iai_analyst_name") || "Analyst";
}

function setAnalystName(name) {
    localStorage.setItem("iai_analyst_name", (name || "").trim() || "Analyst");
}

document.addEventListener("DOMContentLoaded", () => {
    const nameInput = document.getElementById("analyst-name-input");
    if (nameInput) nameInput.value = getActorName();
    if (document.getElementById("saved-views-bar")) fetchSavedViews();
    document.addEventListener("keydown", handleTriageKeydown);
});

async function fetchFindings() {
    try {
        // Always fetch dismissed + false_positive findings too (the server's
        // include_dismissed flag bundles both statuses) -- "Show dismissed"
        // and "Show false positives" are independent client-side filters
        // over the same fetched set, same pattern as the severity chips.
        const res = await fetch(`/api/findings?include_dismissed=true&include_excluded=${findingsShowExcluded}`);
        const data = await res.json();
        currentState.findings = data.findings || [];
        currentState.findingsCounts = data.counts || {};

        const navBadge = document.getElementById("nav-findings-badge");
        if (navBadge) {
            const total = data.total || 0;
            navBadge.textContent = total;
            navBadge.style.display = total > 0 ? "inline-flex" : "none";
        }

        renderFindingsChips();
        renderFindingsList();
    } catch (e) {
        console.error("Fetch findings error:", e);
    }
}

function renderFindingsChips() {
    // Only present on the /findings page -- no-op elsewhere.
    if (!document.getElementById("findings-filter-bar")) return;

    const counts = currentState.findingsCounts || {};
    const total = (counts.CRITICAL || 0) + (counts.HIGH || 0) + (counts.MEDIUM || 0) + (counts.LOW || 0) + (counts.OTHER || 0);
    const setCount = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setCount("chip-count-ALL", total);
    setCount("chip-count-CRITICAL", counts.CRITICAL || 0);
    setCount("chip-count-HIGH", counts.HIGH || 0);
    setCount("chip-count-MEDIUM", counts.MEDIUM || 0);
    setCount("chip-count-LOW", counts.LOW || 0);

    document.querySelectorAll(".filter-chip[data-severity]").forEach(chip => {
        chip.classList.toggle("active", chip.dataset.severity === findingsSeverityFilter);
    });
}

function setFindingsSeverityFilter(severity) {
    findingsSeverityFilter = severity;
    renderFindingsChips();
    renderFindingsList();
}

function toggleFindingsApprovedOnly() {
    findingsApprovedOnly = !findingsApprovedOnly;
    const chip = document.getElementById("chip-approved-only");
    if (chip) chip.classList.toggle("active", findingsApprovedOnly);
    renderFindingsList();
}

function toggleFindingsShowDismissed() {
    findingsShowDismissed = !findingsShowDismissed;
    const chip = document.getElementById("chip-dismissed");
    if (chip) chip.classList.toggle("active", findingsShowDismissed);
    renderFindingsList();
}

function toggleFindingsShowFalsePositives() {
    findingsShowFalsePositives = !findingsShowFalsePositives;
    const chip = document.getElementById("chip-false-positive");
    if (chip) chip.classList.toggle("active", findingsShowFalsePositives);
    renderFindingsList();
}

function toggleFindingsShowExcluded() {
    findingsShowExcluded = !findingsShowExcluded;
    const chip = document.getElementById("chip-excluded");
    if (chip) chip.classList.toggle("active", findingsShowExcluded);
    fetchFindings();
}

function getFilteredFindings() {
    let findings = currentState.findings || [];
    if (findingsSeverityFilter !== "ALL") {
        findings = findings.filter(f => (f.severity || "").toUpperCase() === findingsSeverityFilter);
    }
    if (findingsApprovedOnly) {
        findings = findings.filter(f => f.approved);
    }
    if (!findingsShowDismissed) {
        findings = findings.filter(f => f.status !== "dismissed");
    }
    if (!findingsShowFalsePositives) {
        findings = findings.filter(f => f.status !== "false_positive");
    }
    return findings;
}

// Groups findings sharing a non-null cluster_key (either auto-detected -- same
// filepath+anomaly_type flagged by more than one agent -- or an analyst-forced
// merge) into a single collapsible row, so the same underlying artifact isn't
// shown as N unrelated cards.
function groupFindingsByCluster(findings) {
    const byCluster = new Map();
    const singles = [];
    findings.forEach(f => {
        if (f.cluster_key) {
            if (!byCluster.has(f.cluster_key)) byCluster.set(f.cluster_key, []);
            byCluster.get(f.cluster_key).push(f);
        } else {
            singles.push({ primary: f, extra: [] });
        }
    });
    const grouped = [];
    byCluster.forEach(group => {
        if (group.length < 2) { singles.push({ primary: group[0], extra: [] }); return; }
        grouped.push({ primary: group[0], extra: group.slice(1) });
    });
    return [...grouped, ...singles];
}

function renderFindingsList() {
    const container = document.getElementById("findings-list");
    if (!container) return; // not on the findings page

    const findings = getFilteredFindings();
    container.innerHTML = "";
    if (findings.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent = "No findings match this filter yet.";
        container.appendChild(empty);
        updateBulkBar();
        return;
    }

    const rows = groupFindingsByCluster(findings);
    rows.forEach((row, idx) => container.appendChild(buildFindingCard(row.primary, row.extra, idx)));
    updateBulkBar();
    updateKeyboardFocusHighlight();
}

// Every field on `f` (filepath, justification, recommended_action, ...) is LLM
// output describing a possibly-malicious artifact -- untrusted content, so
// every value below goes in via textContent, never innerHTML.
function buildFindingCard(f, extra, rowIndex) {
    const sevRaw = (f.severity || "").toUpperCase();
    const sevClass = sevRaw === "MEDIUM" ? "medium" : (sevRaw === "LOW" ? "low" : "");
    const cardSevClass = sevRaw === "MEDIUM" ? "severity-medium" : (sevRaw === "LOW" ? "severity-low" : "");

    const card = document.createElement("div");
    card.className = `finding-card ${cardSevClass}`;
    card.dataset.findingId = f.finding_id;
    card.dataset.rowIndex = rowIndex;

    const head = document.createElement("div");
    head.className = "finding-head";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "finding-checkbox";
    checkbox.checked = selectedFindingIds.has(f.finding_id);
    checkbox.addEventListener("click", (e) => e.stopPropagation());
    checkbox.addEventListener("change", () => toggleFindingSelection(f.finding_id, checkbox.checked));
    head.appendChild(checkbox);

    const title = document.createElement("div");
    title.className = "finding-title";
    title.textContent = f.anomaly_type || "Anomaly";
    head.appendChild(title);

    const badgeGroup = document.createElement("div");
    badgeGroup.className = "flex gap-2";

    const sevBadge = document.createElement("span");
    sevBadge.className = `severity-badge ${sevClass}`;
    sevBadge.textContent = f.severity || "Unknown";
    badgeGroup.appendChild(sevBadge);

    const approvalBadge = document.createElement("span");
    approvalBadge.className = `finding-approval ${f.approved ? "approved" : "pending"}`;
    approvalBadge.textContent = f.approved ? "Approved" : "Pending review";
    badgeGroup.appendChild(approvalBadge);

    if (f.status && f.status !== "new") {
        const statusBadge = document.createElement("span");
        statusBadge.className = `finding-approval status-${f.status}`;
        statusBadge.textContent = f.status.replace("_", " ");
        badgeGroup.appendChild(statusBadge);
    }

    if (f.excluded) {
        const excludedBadge = document.createElement("span");
        excludedBadge.className = "excluded-badge";
        excludedBadge.textContent = "Excluded by rule";
        excludedBadge.title = f.excluded_reason || "";
        badgeGroup.appendChild(excludedBadge);
    }

    if (extra && extra.length > 0) {
        const clusterBadge = document.createElement("button");
        clusterBadge.className = "cluster-badge";
        clusterBadge.textContent = `${extra.length + 1} sources`;
        clusterBadge.addEventListener("click", (e) => {
            e.stopPropagation();
            if (expandedClusterKeys.has(f.cluster_key)) expandedClusterKeys.delete(f.cluster_key);
            else expandedClusterKeys.add(f.cluster_key);
            renderFindingsList();
        });
        badgeGroup.appendChild(clusterBadge);
    }

    if (f.locked_by) {
        const lockBadge = document.createElement("span");
        lockBadge.className = "lock-badge";
        lockBadge.textContent = `👁 ${f.locked_by}`;
        lockBadge.title = `${f.locked_by} currently has this finding open`;
        badgeGroup.appendChild(lockBadge);
    }

    head.appendChild(badgeGroup);
    card.appendChild(head);

    const meta = document.createElement("div");
    meta.className = "finding-meta";
    const agentSpan = document.createElement("span");
    agentSpan.textContent = f.agent_label || f.agent_id;
    meta.appendChild(agentSpan);
    if (f.filepath) {
        const pathSpan = document.createElement("span");
        pathSpan.className = "path";
        pathSpan.textContent = f.filepath;
        meta.appendChild(pathSpan);
    }
    const confSpan = document.createElement("span");
    confSpan.className = "confidence-inline";
    confSpan.textContent = `Confidence: ${Math.round(confidenceOf(f))}%`;
    meta.appendChild(confSpan);
    if (f.assigned_to) {
        const assignSpan = document.createElement("span");
        assignSpan.textContent = `Assigned: ${f.assigned_to}`;
        meta.appendChild(assignSpan);
    }
    card.appendChild(meta);

    if ((f.tags && f.tags.length) || (f.mitre_techniques && f.mitre_techniques.length)) {
        const chipRow = document.createElement("div");
        chipRow.className = "finding-chip-row";
        (f.tags || []).forEach(t => {
            const chip = document.createElement("span");
            chip.className = "tag-chip";
            chip.textContent = t;
            chipRow.appendChild(chip);
        });
        (f.mitre_techniques || []).forEach(t => {
            const chip = document.createElement("span");
            chip.className = "mitre-chip";
            chip.textContent = t;
            chipRow.appendChild(chip);
        });
        card.appendChild(chipRow);
    }

    if (f.justification) {
        const desc = document.createElement("div");
        desc.className = "finding-desc";
        desc.textContent = f.justification;
        card.appendChild(desc);
    }

    if (f.recommended_action) {
        const action = document.createElement("div");
        action.className = "finding-action";
        const strong = document.createElement("strong");
        strong.textContent = "Recommended: ";
        action.appendChild(strong);
        action.appendChild(document.createTextNode(f.recommended_action));
        card.appendChild(action);
    }

    const footer = document.createElement("div");
    footer.className = "finding-footer";

    const detailBtn = document.createElement("button");
    detailBtn.className = "btn btn-outline";
    detailBtn.textContent = "Open detail";
    detailBtn.addEventListener("click", (e) => { e.stopPropagation(); openFindingDrawer(f.finding_id); });
    footer.appendChild(detailBtn);

    if (f.source === "agent") {
        const viewBtn = document.createElement("button");
        viewBtn.className = "btn btn-ghost";
        viewBtn.textContent = "View agent →";
        viewBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            window.location.href = `/agents#${encodeURIComponent(f.agent_id)}`;
        });
        footer.appendChild(viewBtn);
    }
    card.appendChild(footer);

    card.addEventListener("click", () => openFindingDrawer(f.finding_id));

    if (extra && extra.length && expandedClusterKeys.has(f.cluster_key)) {
        const extraWrap = document.createElement("div");
        extraWrap.className = "cluster-extra";
        extra.forEach(ef => {
            const line = document.createElement("div");
            line.className = "cluster-extra-line";
            line.textContent = `${ef.agent_label || ef.agent_id}: ${ef.justification || ""}`;
            line.addEventListener("click", (e) => { e.stopPropagation(); openFindingDrawer(ef.finding_id); });
            extraWrap.appendChild(line);
        });
        card.appendChild(extraWrap);
    }

    return card;
}

// ==========================================
// SELECTION + BULK ACTION BAR
// ==========================================

function toggleFindingSelection(findingId, checked) {
    if (checked) selectedFindingIds.add(findingId);
    else selectedFindingIds.delete(findingId);
    updateBulkBar();
}

function clearFindingsSelection() {
    selectedFindingIds.clear();
    renderFindingsList();
}

function updateBulkBar() {
    const bar = document.getElementById("bulk-action-bar");
    if (!bar) return;
    const n = selectedFindingIds.size;
    bar.style.display = n > 0 ? "flex" : "none";
    const countEl = document.getElementById("bulk-selected-count");
    if (countEl) countEl.textContent = `${n} selected`;
}

async function bulkDismissSelected(status) {
    if (selectedFindingIds.size === 0) return;
    const reason = window.prompt(`Reason for marking ${selectedFindingIds.size} finding(s) as "${status}":`, "");
    if (reason === null) return;
    try {
        const res = await fetch("/api/findings/bulk-dismiss", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_ids: [...selectedFindingIds], status, reason, actor: getActorName() })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`${data.count} finding(s) updated.`, "success");
            selectedFindingIds.clear();
            fetchFindings();
        } else {
            showToast("Bulk update failed: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Bulk update request failed.", "error");
    }
}

async function bulkDeletePermanently() {
    if (selectedFindingIds.size === 0) return;
    const n = selectedFindingIds.size;
    const reason = window.prompt(`Optional: why are you permanently deleting ${n} finding(s)? (kept in the audit log)`, "");
    if (reason === null) return; // cancelled the prompt
    const ok = await showConfirm(
        `${n} finding(s) will be PERMANENTLY deleted -- gone forever, not just hidden. They will not appear ` +
        `under "Show dismissed" or any other filter, and there is no restore option. This cannot be undone.`,
        { title: `Permanently delete ${n} finding(s)?`, confirmLabel: "Delete Forever", tone: "danger" }
    );
    if (!ok) return;
    try {
        const res = await fetch("/api/findings/bulk-delete", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_ids: [...selectedFindingIds], reason, actor: getActorName() })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`${data.count} finding(s) permanently deleted.`, "warning");
            selectedFindingIds.clear();
            fetchFindings();
        } else {
            showToast("Delete failed: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Delete request failed.", "error");
    }
}

async function clusterSelectedFindings() {
    if (selectedFindingIds.size < 2) {
        showToast("Select at least 2 findings to merge as duplicates.", "warning");
        return;
    }
    try {
        const res = await fetch("/api/findings/cluster", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_ids: [...selectedFindingIds] })
        });
        const data = await res.json();
        if (data.success) {
            showToast("Findings merged as duplicates.", "success");
            selectedFindingIds.clear();
            fetchFindings();
        } else {
            showToast("Merge failed: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Merge request failed.", "error");
    }
}

// ==========================================
// KEYBOARD TRIAGE MODE
// ==========================================

function toggleKeyboardMode() {
    keyboardModeOn = !keyboardModeOn;
    const stateEl = document.getElementById("keyboard-mode-state");
    if (stateEl) stateEl.textContent = keyboardModeOn ? "On" : "Off";
    const hintBar = document.getElementById("keyboard-hint-bar");
    if (hintBar) hintBar.style.display = keyboardModeOn ? "block" : "none";
    if (keyboardModeOn && keyboardFocusIndex < 0) keyboardFocusIndex = 0;
    updateKeyboardFocusHighlight();
}

function updateKeyboardFocusHighlight() {
    document.querySelectorAll(".finding-card").forEach(el => el.classList.remove("keyboard-focused"));
    if (!keyboardModeOn) return;
    const cards = document.querySelectorAll(".finding-card");
    if (cards.length === 0) return;
    keyboardFocusIndex = Math.max(0, Math.min(keyboardFocusIndex, cards.length - 1));
    const focused = cards[keyboardFocusIndex];
    if (focused) {
        focused.classList.add("keyboard-focused");
        focused.scrollIntoView({ block: "nearest" });
    }
}

function handleTriageKeydown(e) {
    if (!keyboardModeOn) return;
    if (!document.getElementById("findings-list")) return;
    if (["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) return;

    const cards = [...document.querySelectorAll(".finding-card")];
    if (cards.length === 0) return;

    if (e.key === "j") { keyboardFocusIndex = Math.min(keyboardFocusIndex + 1, cards.length - 1); updateKeyboardFocusHighlight(); }
    else if (e.key === "k") { keyboardFocusIndex = Math.max(keyboardFocusIndex - 1, 0); updateKeyboardFocusHighlight(); }
    else if (e.key === "x") {
        const card = cards[keyboardFocusIndex];
        if (card) {
            const cb = card.querySelector(".finding-checkbox");
            if (cb) { cb.checked = !cb.checked; toggleFindingSelection(card.dataset.findingId, cb.checked); }
        }
    } else if (e.key === "a" || e.key === "d") {
        const card = cards[keyboardFocusIndex];
        if (card) {
            selectedFindingIds = new Set([card.dataset.findingId]);
            bulkDismissSelected(e.key === "a" ? "acknowledged" : "dismissed");
        }
    } else if (e.key === "Enter") {
        const card = cards[keyboardFocusIndex];
        if (card) openFindingDrawer(card.dataset.findingId);
    } else if (e.key === "Escape") {
        closeFindingDrawer();
    }
}

// ==========================================
// SAVED VIEWS
// ==========================================

async function fetchSavedViews() {
    try {
        const res = await fetch("/api/saved-views");
        const data = await res.json();
        renderSavedViews(data.views || []);
    } catch (e) {
        console.error("Fetch saved views error:", e);
    }
}

function renderSavedViews(views) {
    const container = document.getElementById("saved-views-list");
    if (!container) return;
    container.innerHTML = "";
    views.forEach(v => {
        const chip = document.createElement("button");
        chip.className = "saved-view-chip";
        chip.textContent = v.name;
        chip.addEventListener("click", () => applySavedView(v));
        const del = document.createElement("span");
        del.className = "saved-view-delete";
        del.textContent = "✕";
        del.addEventListener("click", async (e) => {
            e.stopPropagation();
            await fetch(`/api/saved-views/${v.id}`, { method: "DELETE" });
            fetchSavedViews();
        });
        chip.appendChild(del);
        container.appendChild(chip);
    });
}

function applySavedView(view) {
    const f = view.filters || {};
    findingsSeverityFilter = f.severity || "ALL";
    findingsApprovedOnly = !!f.approved_only;
    const approvedChip = document.getElementById("chip-approved-only");
    if (approvedChip) approvedChip.classList.toggle("active", findingsApprovedOnly);
    renderFindingsChips();
    renderFindingsList();
}

async function saveCurrentView() {
    const name = window.prompt("Name this saved view:", "");
    if (!name) return;
    try {
        await fetch("/api/saved-views", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name, created_by: getActorName(),
                filters: { severity: findingsSeverityFilter, approved_only: findingsApprovedOnly }
            })
        });
        showToast("Saved view created.", "success");
        fetchSavedViews();
    } catch (e) {
        showToast("Could not save view.", "error");
    }
}

// ==========================================
// ADD MANUAL FINDING
// ==========================================

function openManualFindingModal() {
    document.getElementById("manual-finding-modal-overlay").classList.add("open");
}
function closeManualFindingModal() {
    document.getElementById("manual-finding-modal-overlay").classList.remove("open");
}
async function submitManualFinding() {
    const anomalyType = document.getElementById("mf-anomaly-type").value.trim();
    const justification = document.getElementById("mf-justification").value.trim();
    if (!anomalyType || !justification) {
        showToast("Anomaly type and justification are required.", "warning");
        return;
    }
    try {
        const res = await fetch("/api/findings/manual", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                anomaly_type: anomalyType,
                severity: document.getElementById("mf-severity").value,
                filepath: document.getElementById("mf-filepath").value.trim(),
                justification,
                recommended_action: document.getElementById("mf-recommended").value.trim(),
                artifact_note: document.getElementById("mf-artifact-note").value.trim(),
                created_by: getActorName(),
            })
        });
        const data = await res.json();
        if (data.success) {
            showToast("Manual finding added.", "success");
            closeManualFindingModal();
            ["mf-anomaly-type", "mf-filepath", "mf-justification", "mf-recommended", "mf-artifact-note"]
                .forEach(id => { document.getElementById(id).value = ""; });
            fetchFindings();
        } else {
            showToast("Could not add finding: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Request failed.", "error");
    }
}

// ==========================================
// SAVE AS IOC
// ==========================================

function openSaveAsIocModal() {
    document.getElementById("ioc-modal-count").textContent = `${selectedFindingIds.size} finding(s) selected.`;
    document.getElementById("ioc-modal-overlay").classList.add("open");
}
function closeSaveAsIocModal() {
    document.getElementById("ioc-modal-overlay").classList.remove("open");
}
async function submitSaveAsIoc() {
    try {
        const res = await fetch("/api/findings/save-as-ioc", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                finding_ids: [...selectedFindingIds],
                tlp: document.getElementById("ioc-tlp").value,
                actor: getActorName(),
            })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Saved ${data.created_ioc_ids.length} IOC(s). View them in the IOC Library.`, "success");
            closeSaveAsIocModal();
        } else {
            showToast("Save as IOC failed: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Request failed.", "error");
    }
}

// ==========================================
// EXPORT TO REPORT
// ==========================================

function openExportModal() {
    document.getElementById("export-modal-count").textContent =
        selectedFindingIds.size > 0 ? `${selectedFindingIds.size} finding(s) selected.` : "No selection -- exporting all visible findings.";
    document.getElementById("export-modal-overlay").classList.add("open");
}
function closeExportModal() {
    document.getElementById("export-modal-overlay").classList.remove("open");
}
async function submitExportReport() {
    const format = document.getElementById("export-format").value;
    try {
        const res = await fetch("/api/findings/export", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                finding_ids: [...selectedFindingIds],
                format,
                template: document.getElementById("export-template").value,
                redact_pii: document.getElementById("export-redact-pii").checked,
                include_chain_of_custody: document.getElementById("export-chain-of-custody").checked,
            })
        });
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            showToast("Export failed: " + (data.error || "unknown error"), "error");
            return;
        }
        const blob = await res.blob();
        const ext = format === "csv" ? "csv" : (format === "json" ? "json" : "md");
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `findings_report.${ext}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        closeExportModal();
    } catch (e) {
        showToast("Export request failed.", "error");
    }
}

// ==========================================
// BULK TAG
// ==========================================

function openBulkTagModal() {
    document.getElementById("bulk-tag-modal-overlay").classList.add("open");
}
function closeBulkTagModal() {
    document.getElementById("bulk-tag-modal-overlay").classList.remove("open");
}
async function submitBulkTag() {
    const raw = document.getElementById("bulk-tag-input").value;
    const tags = raw.split(",").map(t => t.trim()).filter(Boolean);
    if (tags.length === 0) { showToast("Enter at least one tag.", "warning"); return; }
    try {
        const res = await fetch("/api/findings/bulk-tag", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_ids: [...selectedFindingIds], add_tags: tags })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Tagged ${data.count} finding(s).`, "success");
            document.getElementById("bulk-tag-input").value = "";
            closeBulkTagModal();
            fetchFindings();
        } else {
            showToast("Tagging failed: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Request failed.", "error");
    }
}

// ==========================================
// FINDING DETAIL DRAWER
// ==========================================

function findFindingById(findingId) {
    return (currentState.findings || []).find(f => f.finding_id === findingId);
}

async function openFindingDrawer(findingId) {
    const f = findFindingById(findingId);
    if (!f) return;
    currentDrawerFindingId = findingId;

    document.getElementById("fd-title").textContent = f.anomaly_type || "Finding";
    document.getElementById("fd-subtitle").textContent = `${f.agent_label || f.agent_id} · ${f.finding_id}`;
    document.getElementById("fd-justification").textContent = f.justification || "";
    document.getElementById("fd-recommended").textContent = f.recommended_action || "(none provided)";
    document.getElementById("fd-confidence-slider").value = Math.round(confidenceOf(f));
    document.getElementById("fd-confidence-value").textContent = Math.round(confidenceOf(f));
    document.getElementById("fd-tags-input").value = (f.tags || []).join(", ");
    document.getElementById("fd-assignee-input").value = f.assigned_to || "";
    document.getElementById("fd-enrich-group").style.display = f.source === "agent" ? "block" : "none";

    const badges = document.getElementById("fd-badges");
    badges.innerHTML = "";
    [["Severity", f.severity], ["Status", f.status], ["Source", f.source]].forEach(([label, val]) => {
        const b = document.createElement("span");
        b.className = "fd-badge";
        b.textContent = `${label}: ${val || "n/a"}`;
        badges.appendChild(b);
    });

    await ensureMitreLookup();
    const mitreSelect = document.getElementById("fd-mitre-select");
    mitreSelect.innerHTML = "";
    (mitreLookupCache || []).forEach(t => {
        const opt = document.createElement("option");
        opt.value = t.id;
        opt.textContent = `${t.id} -- ${t.name}`;
        if ((f.mitre_techniques || []).includes(t.id)) opt.selected = true;
        mitreSelect.appendChild(opt);
    });

    const pivotGroup = document.getElementById("fd-pivot-group");
    const pivotValue = f.filepath;
    if (pivotValue) {
        pivotGroup.style.display = "block";
        loadPivotLinks(pivotValue);
    } else {
        pivotGroup.style.display = "none";
    }

    document.getElementById("fd-enrich-status").textContent = "";
    document.getElementById("fd-timeline-context").textContent = "";

    loadFindingComments(findingId);
    loadFindingAuditLog(findingId);
    loadEnrichmentHistory(findingId);
    acquireFindingLock(findingId);

    document.getElementById("finding-drawer-overlay").classList.add("open");
    document.getElementById("finding-drawer").classList.add("open");

    if (drawerLockInterval) clearInterval(drawerLockInterval);
    drawerLockInterval = setInterval(() => acquireFindingLock(findingId), 15000);
}

function closeFindingDrawer() {
    document.getElementById("finding-drawer-overlay").classList.remove("open");
    document.getElementById("finding-drawer").classList.remove("open");
    if (drawerLockInterval) { clearInterval(drawerLockInterval); drawerLockInterval = null; }
    if (enrichPollInterval) { clearInterval(enrichPollInterval); enrichPollInterval = null; }
    if (currentDrawerFindingId) {
        fetch(`/api/findings/${encodeURIComponent(currentDrawerFindingId)}/lock`, { method: "DELETE" }).catch(() => {});
    }
    currentDrawerFindingId = null;
}

async function acquireFindingLock(findingId) {
    try {
        const res = await fetch(`/api/findings/${encodeURIComponent(findingId)}/lock`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ actor: getActorName() })
        });
        const banner = document.getElementById("fd-lock-banner");
        if (res.status === 409) {
            const data = await res.json();
            banner.style.display = "block";
            banner.textContent = `${data.locked_by} is also viewing this finding right now.`;
        } else {
            banner.style.display = "none";
        }
    } catch (e) { /* best-effort presence indicator */ }
}

async function ensureMitreLookup() {
    if (mitreLookupCache) return;
    try {
        const res = await fetch("/api/findings/mitre-lookup");
        const data = await res.json();
        mitreLookupCache = data.techniques || [];
    } catch (e) {
        mitreLookupCache = [];
    }
}

async function loadPivotLinks(value) {
    const container = document.getElementById("fd-pivot-links");
    container.innerHTML = "Loading...";
    try {
        const res = await fetch(`/api/findings/pivot?value=${encodeURIComponent(value)}`);
        const data = await res.json();
        container.innerHTML = "";
        (data.links || []).forEach(link => {
            const a = document.createElement(link.url ? "a" : "span");
            a.className = "pivot-link" + (link.url ? "" : " pivot-link-disabled");
            a.textContent = link.label;
            if (link.url) { a.href = link.url; a.target = "_blank"; a.rel = "noopener"; }
            if (link.note) a.title = link.note;
            container.appendChild(a);
        });
    } catch (e) {
        container.textContent = "Could not load pivot links.";
    }
}

async function onConfidenceSlide(value) {
    document.getElementById("fd-confidence-value").textContent = value;
    if (!currentDrawerFindingId) return;
    clearTimeout(window._confidenceDebounce);
    window._confidenceDebounce = setTimeout(async () => {
        await fetch("/api/findings/confidence", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_id: currentDrawerFindingId, confidence: parseFloat(value) })
        });
        fetchFindings();
    }, 400);
}

async function applyTagsFromDrawer() {
    if (!currentDrawerFindingId) return;
    const tags = document.getElementById("fd-tags-input").value.split(",").map(t => t.trim()).filter(Boolean);
    await fetch("/api/findings/tag", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: currentDrawerFindingId, tags })
    });
    showToast("Tags updated.", "success");
    fetchFindings();
}

async function applyMitreFromDrawer() {
    if (!currentDrawerFindingId) return;
    const selected = [...document.getElementById("fd-mitre-select").selectedOptions].map(o => o.value);
    await fetch("/api/findings/mitre", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: currentDrawerFindingId, mitre_techniques: selected })
    });
    showToast("MITRE techniques updated.", "success");
    fetchFindings();
}

async function applyAssignmentFromDrawer() {
    if (!currentDrawerFindingId) return;
    const assignedTo = document.getElementById("fd-assignee-input").value.trim();
    await fetch("/api/findings/assign", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: currentDrawerFindingId, assigned_to: assignedTo, actor: getActorName() })
    });
    showToast(assignedTo ? `Assigned to ${assignedTo}.` : "Assignment cleared.", "success");
    fetchFindings();
}

async function dismissFromDrawer(status) {
    if (!currentDrawerFindingId) return;
    const reason = window.prompt(`Reason for marking this finding as "${status}":`, "");
    if (reason === null) return;
    await fetch("/api/findings/dismiss", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: currentDrawerFindingId, status, reason, actor: getActorName() })
    });
    showToast("Finding updated.", "success");
    closeFindingDrawer();
    fetchFindings();
}

async function deletePermanentlyFromDrawer() {
    if (!currentDrawerFindingId) return;
    const reason = window.prompt("Optional: why are you permanently deleting this finding? (kept in the audit log)", "");
    if (reason === null) return; // cancelled the prompt
    const ok = await showConfirm(
        "This finding will be PERMANENTLY deleted -- gone forever, not just hidden. It will not appear under " +
        '"Show dismissed" or any other filter, and there is no restore option. This cannot be undone.',
        { title: "Permanently delete this finding?", confirmLabel: "Delete Forever", tone: "danger" }
    );
    if (!ok) return;
    try {
        const res = await fetch("/api/findings/delete", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_id: currentDrawerFindingId, reason, actor: getActorName() })
        });
        const data = await res.json();
        if (data.success) {
            showToast("Finding permanently deleted.", "warning");
            closeFindingDrawer();
            fetchFindings();
        } else {
            showToast("Delete failed: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Delete request failed.", "error");
    }
}

async function loadTimelineContext() {
    if (!currentDrawerFindingId) return;
    const container = document.getElementById("fd-timeline-context");
    container.textContent = "Loading...";
    try {
        const res = await fetch(`/api/findings/${encodeURIComponent(currentDrawerFindingId)}/timeline-context`);
        const data = await res.json();
        if (!data.available) {
            container.textContent = data.note || "No timeline context available for this finding.";
            return;
        }
        container.textContent = `Created: ${data.created_utc} · Modified: ${data.modified_utc} · Accessed: ${data.accessed_utc}`;
        container.title = data.note || "";
    } catch (e) {
        container.textContent = "Could not load timeline context.";
    }
}

async function loadFindingComments(findingId) {
    const container = document.getElementById("fd-comments-list");
    container.textContent = "Loading...";
    try {
        const res = await fetch(`/api/findings/${encodeURIComponent(findingId)}/comments`);
        const data = await res.json();
        container.innerHTML = "";
        if (!data.comments || data.comments.length === 0) {
            container.textContent = "No comments yet.";
            return;
        }
        data.comments.forEach(c => {
            const row = document.createElement("div");
            row.className = "fd-comment";
            const meta = document.createElement("div");
            meta.className = "fd-comment-meta";
            meta.textContent = `${c.author} · ${c.created_at}`;
            const body = document.createElement("div");
            body.textContent = c.body;
            row.appendChild(meta);
            row.appendChild(body);
            container.appendChild(row);
        });
    } catch (e) {
        container.textContent = "Could not load comments.";
    }
}

async function submitFindingComment() {
    if (!currentDrawerFindingId) return;
    const input = document.getElementById("fd-comment-input");
    const body = input.value.trim();
    if (!body) return;
    await fetch(`/api/findings/${encodeURIComponent(currentDrawerFindingId)}/comments`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body, author: getActorName() })
    });
    input.value = "";
    loadFindingComments(currentDrawerFindingId);
}

async function loadFindingAuditLog(findingId) {
    const container = document.getElementById("fd-audit-log");
    container.textContent = "Loading...";
    try {
        const res = await fetch(`/api/findings/${encodeURIComponent(findingId)}/audit-log`);
        const data = await res.json();
        container.innerHTML = "";
        if (!data.entries || data.entries.length === 0) {
            container.textContent = "No audit history yet.";
            return;
        }
        data.entries.forEach(e => {
            const row = document.createElement("div");
            row.className = "fd-audit-entry";
            row.textContent = `${e.timestamp} — ${e.actor} ${e.action}${e.reason ? ": " + e.reason : ""}`;
            container.appendChild(row);
        });
    } catch (e) {
        container.textContent = "Could not load audit log.";
    }
}

async function enrichFinding(action) {
    if (!currentDrawerFindingId) return;
    const statusEl = document.getElementById("fd-enrich-status");
    try {
        const res = await fetch(`/api/findings/${encodeURIComponent(currentDrawerFindingId)}/enrich`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action })
        });
        const data = await res.json();
        if (!data.success) {
            statusEl.textContent = "Could not start enrichment: " + (data.error || "unknown error");
            return;
        }
        statusEl.textContent = "Deep analysis running...";
        showToast("Agent enrichment started.", "info");
        if (enrichPollInterval) clearInterval(enrichPollInterval);
        enrichPollInterval = setInterval(() => pollEnrichmentJob(data.job_id), 2000);
    } catch (e) {
        statusEl.textContent = "Enrichment request failed.";
    }
}

async function pollEnrichmentJob(jobId) {
    const statusEl = document.getElementById("fd-enrich-status");
    try {
        const res = await fetch(`/api/enrichment-jobs/${jobId}`);
        const data = await res.json();
        if (data.status === "queued" || data.status === "running") {
            statusEl.textContent = `Deep analysis ${data.status}...`;
            return;
        }
        clearInterval(enrichPollInterval);
        enrichPollInterval = null;
        if (data.status === "succeeded") {
            statusEl.textContent = `Completed: ${data.result_summary || "no summary"}`;
            showToast("Deep analysis completed.", "success");
            fetchFindings();
            if (currentDrawerFindingId) loadEnrichmentHistory(currentDrawerFindingId);
        } else {
            statusEl.textContent = `Failed: ${data.error || "unknown error"}`;
            showToast("Deep analysis failed.", "error");
        }
    } catch (e) {
        clearInterval(enrichPollInterval);
        enrichPollInterval = null;
        statusEl.textContent = "Lost track of enrichment job status.";
    }
}

async function loadEnrichmentHistory(findingId) {
    const container = document.getElementById("fd-enrich-history");
    try {
        const res = await fetch(`/api/findings/${encodeURIComponent(findingId)}/enrichment-jobs`);
        const data = await res.json();
        container.innerHTML = "";
        (data.jobs || []).forEach(j => {
            const row = document.createElement("div");
            row.className = "fd-enrich-job";
            row.textContent = `${j.submitted_at} · ${j.action} → ${j.status}${j.result_summary ? ": " + j.result_summary : ""}`;
            container.appendChild(row);
        });
    } catch (e) { /* non-critical */ }
}

// ==========================================
// IOC LIBRARY PAGE
// ==========================================

async function fetchIocs() {
    try {
        const res = await fetch("/api/iocs");
        const data = await res.json();
        renderIocs(data.iocs || []);
    } catch (e) {
        console.error("Fetch IOCs error:", e);
    }
}

function renderIocs(iocs) {
    const body = document.getElementById("ioc-table-body");
    const empty = document.getElementById("ioc-empty-state");
    if (!body) return;
    body.innerHTML = "";
    if (empty) empty.style.display = iocs.length === 0 ? "block" : "none";
    iocs.forEach(ioc => {
        const tr = document.createElement("tr");
        [ioc.ioc_type, ioc.value, ioc.tlp, ioc.source_finding_id || "-", ioc.added_by, ioc.added_at].forEach(val => {
            const td = document.createElement("td");
            td.textContent = val;
            tr.appendChild(td);
        });
        const actionsTd = document.createElement("td");
        const delBtn = document.createElement("button");
        delBtn.className = "btn btn-ghost btn-sm";
        delBtn.textContent = "Delete";
        delBtn.addEventListener("click", async () => {
            await fetch(`/api/iocs/${ioc.ioc_id}`, { method: "DELETE" });
            fetchIocs();
        });
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);
        body.appendChild(tr);
    });
}

// ==========================================
// REPORT EXPORT
// ==========================================

function downloadActiveReport() {
    if (!currentState.active_investigation_id) return;
    window.location.href = `/api/investigation/report?staging_dir=${encodeURIComponent(currentState.active_investigation_id)}`;
}

// ==========================================
// SYSTEM MANAGEMENT
// ==========================================

document.addEventListener("DOMContentLoaded", () => {
    if (document.getElementById("exclusions-table-body")) fetchExclusions();
    if (document.getElementById("yara-table-body")) fetchYaraRules();
    if (document.getElementById("sigma-table-body")) fetchSigmaRules();
    if (document.getElementById("baselines-table-body")) fetchBaselineHashes();
    if (document.getElementById("llm-provider-label")) fetchLlmConfig();
    if (document.getElementById("retention-summary-cards")) { fetchRetentionSummary(); fetchRetentionPolicies(); }
    if (document.getElementById("users-table-body")) { fetchUsers(); fetchGlobalAuditLog(); }
});

function humanBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    const units = ["KB", "MB", "GB", "TB"];
    let val = bytes, i = -1;
    do { val /= 1024; i++; } while (val >= 1024 && i < units.length - 1);
    return val.toFixed(1) + " " + units[i];
}

// ---- Exclusion Rules ----

let exclusionRulesCache = [];

async function fetchExclusions() {
    try {
        const [rulesRes, impactRes] = await Promise.all([
            fetch("/api/management/exclusions"), fetch("/api/management/exclusions/impact"),
        ]);
        const rulesData = await rulesRes.json();
        const impactData = await impactRes.json();
        exclusionRulesCache = rulesData.rules || [];
        renderExclusionsTable(exclusionRulesCache, impactData.impact || {});
    } catch (e) {
        console.error("Fetch exclusions error:", e);
    }
}

function renderExclusionsTable(rules, impact) {
    const body = document.getElementById("exclusions-table-body");
    const empty = document.getElementById("exclusions-empty");
    if (!body) return;
    body.innerHTML = "";
    empty.style.display = rules.length === 0 ? "block" : "none";
    rules.forEach(r => {
        const tr = document.createElement("tr");
        [r.rule_type, r.pattern_value, r.matching_action.replace("_", " "), r.description_reason, r.created_by].forEach(v => {
            const td = document.createElement("td");
            td.textContent = v;
            tr.appendChild(td);
        });
        const suppressTd = document.createElement("td");
        suppressTd.textContent = impact[r.rule_id] || 0;
        tr.appendChild(suppressTd);

        const activeTd = document.createElement("td");
        const activeCb = document.createElement("input");
        activeCb.type = "checkbox";
        activeCb.checked = r.is_active;
        activeCb.addEventListener("change", async () => {
            await fetch(`/api/management/exclusions/${r.rule_id}`, {
                method: "PATCH", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ is_active: activeCb.checked }),
            });
            fetchExclusions();
        });
        activeTd.appendChild(activeCb);
        tr.appendChild(activeTd);

        const actionsTd = document.createElement("td");
        const delBtn = document.createElement("button");
        delBtn.className = "btn btn-ghost btn-sm";
        delBtn.textContent = "Delete";
        delBtn.addEventListener("click", async () => {
            const ok = await showConfirm("Delete this exclusion rule? Matching findings will reappear.",
                { title: "Delete rule", confirmLabel: "Delete", tone: "danger" });
            if (!ok) return;
            await fetch(`/api/management/exclusions/${r.rule_id}`, { method: "DELETE" });
            fetchExclusions();
        });
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        body.appendChild(tr);
    });
}

function openExclusionDrawer() {
    document.getElementById("ex-rule-type").value = "file_hash";
    document.getElementById("ex-pattern-value").value = "";
    document.getElementById("ex-pattern-mode").value = "exact";
    document.getElementById("ex-source-agent").value = "";
    document.getElementById("ex-min-severity").value = "";
    document.getElementById("ex-matching-action").value = "mark_excluded";
    document.getElementById("ex-reason").value = "";
    document.getElementById("ex-expiration").value = "";
    document.getElementById("ex-test-sample").value = "";
    document.getElementById("ex-test-result").textContent = "";
    onExclusionRuleTypeChange();
    document.getElementById("exclusion-drawer-overlay").classList.add("open");
    document.getElementById("exclusion-drawer").classList.add("open");
}
function closeExclusionDrawer() {
    document.getElementById("exclusion-drawer-overlay").classList.remove("open");
    document.getElementById("exclusion-drawer").classList.remove("open");
}
function onExclusionRuleTypeChange() {
    const isCategory = document.getElementById("ex-rule-type").value === "finding_category";
    document.getElementById("ex-pattern-group").style.display = isCategory ? "none" : "block";
    document.getElementById("ex-mode-group").style.display = isCategory ? "none" : "block";
    document.getElementById("ex-agent-filter-group").style.display = isCategory ? "block" : "none";
    document.getElementById("ex-severity-filter-group").style.display = isCategory ? "block" : "none";
}

async function testExclusionRule() {
    try {
        const res = await fetch("/api/management/exclusions/test", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                rule_type: document.getElementById("ex-rule-type").value,
                pattern_value: document.getElementById("ex-pattern-value").value,
                pattern_mode: document.getElementById("ex-pattern-mode").value,
                sample_value: document.getElementById("ex-test-sample").value,
            }),
        });
        const data = await res.json();
        document.getElementById("ex-test-result").textContent = data.success
            ? (data.matches ? "✓ Matches" : "✗ Does not match") : ("Error: " + data.error);
    } catch (e) {
        document.getElementById("ex-test-result").textContent = "Test request failed.";
    }
}

async function submitExclusionRule() {
    const type = document.getElementById("ex-rule-type").value;
    const isCategory = type === "finding_category";
    const patternValue = isCategory ? "n/a" : document.getElementById("ex-pattern-value").value.trim();
    const reason = document.getElementById("ex-reason").value.trim();
    if (!isCategory && !patternValue) { showToast("Pattern value is required.", "warning"); return; }
    if (!reason) { showToast("Reason is required.", "warning"); return; }
    try {
        const res = await fetch("/api/management/exclusions", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                rule_type: type,
                pattern_value: patternValue,
                pattern_mode: document.getElementById("ex-pattern-mode").value,
                matching_action: document.getElementById("ex-matching-action").value,
                description_reason: reason,
                source_agent_filter: document.getElementById("ex-source-agent").value.trim() || null,
                min_severity_filter: document.getElementById("ex-min-severity").value || null,
                expiration_date: document.getElementById("ex-expiration").value || null,
            }),
        });
        const data = await res.json();
        if (data.success) {
            showToast("Exclusion rule created.", "success");
            closeExclusionDrawer();
            fetchExclusions();
        } else {
            showToast("Could not create rule: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Request failed.", "error");
    }
}

// ---- YARA Rules ----

async function fetchYaraRules() {
    try {
        const res = await fetch("/api/management/yara-rules");
        const data = await res.json();
        renderYaraTable(data.rules || []);
    } catch (e) {
        console.error("Fetch YARA rules error:", e);
    }
}

function renderYaraTable(rules) {
    const body = document.getElementById("yara-table-body");
    const empty = document.getElementById("yara-empty");
    if (!body) return;
    body.innerHTML = "";
    empty.style.display = rules.length === 0 ? "block" : "none";
    rules.forEach(r => {
        const tr = document.createElement("tr");
        const nameTd = document.createElement("td"); nameTd.textContent = r.name; tr.appendChild(nameTd);
        const byTd = document.createElement("td"); byTd.textContent = r.created_by; tr.appendChild(byTd);
        const statusTd = document.createElement("td");
        statusTd.textContent = r.last_error ? ("Error: " + r.last_error) : "OK";
        if (r.last_error) statusTd.classList.add("form-hint", "warn");
        tr.appendChild(statusTd);

        const activeTd = document.createElement("td");
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = r.is_active;
        cb.addEventListener("change", async () => {
            await fetch(`/api/management/yara-rules/${r.rule_id}`, {
                method: "PATCH", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ is_active: cb.checked }),
            });
            fetchYaraRules();
        });
        activeTd.appendChild(cb);
        tr.appendChild(activeTd);

        const actionsTd = document.createElement("td");
        const delBtn = document.createElement("button");
        delBtn.className = "btn btn-ghost btn-sm";
        delBtn.textContent = "Delete";
        delBtn.addEventListener("click", async () => {
            const ok = await showConfirm("Delete this YARA rule?", { title: "Delete rule", confirmLabel: "Delete", tone: "danger" });
            if (!ok) return;
            await fetch(`/api/management/yara-rules/${r.rule_id}`, { method: "DELETE" });
            fetchYaraRules();
        });
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        body.appendChild(tr);
    });
}

function openYaraDrawer() {
    document.getElementById("yara-name").value = "";
    document.getElementById("yara-rule-text").value = "";
    document.getElementById("yara-error").style.display = "none";
    document.getElementById("yara-drawer-overlay").classList.add("open");
    document.getElementById("yara-drawer").classList.add("open");
}
function closeYaraDrawer() {
    document.getElementById("yara-drawer-overlay").classList.remove("open");
    document.getElementById("yara-drawer").classList.remove("open");
}
async function submitYaraRule() {
    const name = document.getElementById("yara-name").value.trim();
    const ruleText = document.getElementById("yara-rule-text").value;
    const errEl = document.getElementById("yara-error");
    if (!name || !ruleText.trim()) { showToast("Name and rule text are required.", "warning"); return; }
    try {
        const res = await fetch("/api/management/yara-rules", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, rule_text: ruleText }),
        });
        const data = await res.json();
        if (data.success) {
            showToast("YARA rule saved.", "success");
            closeYaraDrawer();
            fetchYaraRules();
        } else {
            errEl.textContent = data.error;
            errEl.style.display = "block";
        }
    } catch (e) {
        errEl.textContent = "Request failed.";
        errEl.style.display = "block";
    }
}

// ---- Sigma Rules ----

async function fetchSigmaRules() {
    try {
        const res = await fetch("/api/management/sigma-rules");
        const data = await res.json();
        renderSigmaTable(data.rules || []);
    } catch (e) {
        console.error("Fetch Sigma rules error:", e);
    }
}

function renderSigmaTable(rules) {
    const body = document.getElementById("sigma-table-body");
    const empty = document.getElementById("sigma-empty");
    if (!body) return;
    body.innerHTML = "";
    empty.style.display = rules.length === 0 ? "block" : "none";
    rules.forEach(r => {
        const tr = document.createElement("tr");
        const nameTd = document.createElement("td"); nameTd.textContent = r.name; tr.appendChild(nameTd);
        const byTd = document.createElement("td"); byTd.textContent = r.created_by; tr.appendChild(byTd);

        const activeTd = document.createElement("td");
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = r.is_active;
        cb.addEventListener("change", async () => {
            await fetch(`/api/management/sigma-rules/${r.rule_id}`, {
                method: "PATCH", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ is_active: cb.checked }),
            });
            fetchSigmaRules();
        });
        activeTd.appendChild(cb);
        tr.appendChild(activeTd);

        const actionsTd = document.createElement("td");
        const delBtn = document.createElement("button");
        delBtn.className = "btn btn-ghost btn-sm";
        delBtn.textContent = "Delete";
        delBtn.addEventListener("click", async () => {
            const ok = await showConfirm("Delete this Sigma rule?", { title: "Delete rule", confirmLabel: "Delete", tone: "danger" });
            if (!ok) return;
            await fetch(`/api/management/sigma-rules/${r.rule_id}`, { method: "DELETE" });
            fetchSigmaRules();
        });
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        body.appendChild(tr);
    });
}

function openSigmaDrawer() {
    document.getElementById("sigma-name").value = "";
    document.getElementById("sigma-rule-yaml").value = "";
    document.getElementById("sigma-test-fields").value = "";
    document.getElementById("sigma-test-result").textContent = "";
    document.getElementById("sigma-error").style.display = "none";
    document.getElementById("sigma-drawer-overlay").classList.add("open");
    document.getElementById("sigma-drawer").classList.add("open");
}
async function testSigmaRule() {
    const resultEl = document.getElementById("sigma-test-result");
    let sampleFields;
    try {
        sampleFields = JSON.parse(document.getElementById("sigma-test-fields").value || "{}");
    } catch (e) {
        resultEl.textContent = "Sample fields must be valid JSON.";
        return;
    }
    try {
        const res = await fetch("/api/management/sigma-rules/test", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ rule_yaml: document.getElementById("sigma-rule-yaml").value, sample_fields: sampleFields }),
        });
        const data = await res.json();
        resultEl.textContent = data.success ? (data.matches ? "✓ Matches" : "✗ Does not match") : ("Error: " + data.error);
    } catch (e) {
        resultEl.textContent = "Test request failed.";
    }
}
function closeSigmaDrawer() {
    document.getElementById("sigma-drawer-overlay").classList.remove("open");
    document.getElementById("sigma-drawer").classList.remove("open");
}
async function submitSigmaRule() {
    const name = document.getElementById("sigma-name").value.trim();
    const ruleYaml = document.getElementById("sigma-rule-yaml").value;
    const errEl = document.getElementById("sigma-error");
    if (!name || !ruleYaml.trim()) { showToast("Name and rule YAML are required.", "warning"); return; }
    try {
        const res = await fetch("/api/management/sigma-rules", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, rule_yaml: ruleYaml }),
        });
        const data = await res.json();
        if (data.success) {
            showToast("Sigma rule saved.", "success");
            closeSigmaDrawer();
            fetchSigmaRules();
        } else {
            errEl.textContent = data.error;
            errEl.style.display = "block";
        }
    } catch (e) {
        errEl.textContent = "Request failed.";
        errEl.style.display = "block";
    }
}

// ---- Baseline / Golden-Image Whitelisting ----

async function fetchBaselineHashes() {
    try {
        const res = await fetch("/api/management/exclusions");
        const data = await res.json();
        renderBaselinesTable((data.rules || []).filter(r => r.rule_type === "file_hash"));
    } catch (e) {
        console.error("Fetch baseline hashes error:", e);
    }
}

function renderBaselinesTable(rules) {
    const body = document.getElementById("baselines-table-body");
    const empty = document.getElementById("baselines-empty");
    if (!body) return;
    body.innerHTML = "";
    empty.style.display = rules.length === 0 ? "block" : "none";
    rules.forEach(r => {
        const tr = document.createElement("tr");
        const hashTd = document.createElement("td");
        const code = document.createElement("code");
        code.textContent = r.pattern_value;
        hashTd.appendChild(code);
        tr.appendChild(hashTd);
        const reasonTd = document.createElement("td"); reasonTd.textContent = r.description_reason; tr.appendChild(reasonTd);
        const byTd = document.createElement("td"); byTd.textContent = r.created_by; tr.appendChild(byTd);

        const activeTd = document.createElement("td");
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = r.is_active;
        cb.addEventListener("change", async () => {
            await fetch(`/api/management/exclusions/${r.rule_id}`, {
                method: "PATCH", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ is_active: cb.checked }),
            });
            fetchBaselineHashes();
        });
        activeTd.appendChild(cb);
        tr.appendChild(activeTd);

        const actionsTd = document.createElement("td");
        const delBtn = document.createElement("button");
        delBtn.className = "btn btn-ghost btn-sm";
        delBtn.textContent = "Delete";
        delBtn.addEventListener("click", async () => {
            await fetch(`/api/management/exclusions/${r.rule_id}`, { method: "DELETE" });
            fetchBaselineHashes();
        });
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        body.appendChild(tr);
    });
}

function openBaselineImportModal() {
    document.getElementById("baseline-hashes-input").value = "";
    document.getElementById("baseline-import-modal-overlay").classList.add("open");
}
function closeBaselineImportModal() {
    document.getElementById("baseline-import-modal-overlay").classList.remove("open");
}
async function submitBaselineImport() {
    const hashes = document.getElementById("baseline-hashes-input").value.split("\n").map(h => h.trim()).filter(Boolean);
    if (hashes.length === 0) { showToast("Paste at least one hash.", "warning"); return; }
    try {
        const res = await fetch("/api/management/exclusions/import-baseline", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hashes, description_reason: document.getElementById("baseline-reason-input").value.trim() }),
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Imported ${data.created_count} baseline hash rule(s).`, "success");
            closeBaselineImportModal();
            fetchBaselineHashes();
        } else {
            showToast("Import failed: " + (data.error || "unknown error"), "error");
        }
    } catch (e) {
        showToast("Request failed.", "error");
    }
}

// ---- LLM Provider Configuration ----

// Base URLs that identify a known preset, purely for auto-selecting the
// dropdown on load -- saving/testing always uses whatever's actually in the
// text fields, never a value silently substituted in from this table.
const LLM_PRESETS = {
    openwebui: { label: "Open WebUI (offline)", base_url: "http://localhost:3000/api", model_name: "llama3.1" },
    gemini: { label: "Gemini (Google AI Studio -- testing)", base_url: "https://generativelanguage.googleapis.com/v1beta/openai/", model_name: "gemini-2.5-flash" },
};

function applyLlmPreset(preset) {
    document.getElementById("llm-preset-help-openwebui").style.display = preset === "openwebui" ? "block" : "none";
    document.getElementById("llm-preset-help-gemini").style.display = preset === "gemini" ? "block" : "none";
    if (preset === "custom") return; // leave whatever the admin already typed alone
    const p = LLM_PRESETS[preset];
    if (!p) return;
    document.getElementById("llm-provider-label").value = p.label;
    document.getElementById("llm-base-url").value = p.base_url;
    document.getElementById("llm-model-name").value = p.model_name;
    // API key is never auto-filled -- always the admin's own secret to paste.
}

function detectLlmPreset(baseUrl) {
    for (const [key, p] of Object.entries(LLM_PRESETS)) {
        if (baseUrl === p.base_url) return key;
    }
    return "custom";
}

async function fetchLlmConfig() {
    try {
        const res = await fetch("/api/management/llm-config");
        const data = await res.json();
        document.getElementById("llm-provider-label").value = data.provider_label || "";
        document.getElementById("llm-base-url").value = data.base_url || "";
        document.getElementById("llm-model-name").value = data.model_name || "";
        document.getElementById("llm-context-limit").value = data.context_limit || 30000;
        document.getElementById("llm-api-key").placeholder = data.api_key_set ? "Currently set (leave blank to keep)" : "Not set";
        document.getElementById("llm-updated-hint").textContent = data.updated_at ? `Last updated ${data.updated_at}` : "";

        const preset = detectLlmPreset(data.base_url || "");
        document.getElementById("llm-preset-select").value = preset;
        document.getElementById("llm-preset-help-openwebui").style.display = preset === "openwebui" ? "block" : "none";
        document.getElementById("llm-preset-help-gemini").style.display = preset === "gemini" ? "block" : "none";
    } catch (e) {
        console.error("Fetch LLM config error:", e);
    }
}

async function saveLlmConfig() {
    const body = {
        provider_label: document.getElementById("llm-provider-label").value.trim(),
        base_url: document.getElementById("llm-base-url").value.trim(),
        model_name: document.getElementById("llm-model-name").value.trim(),
        context_limit: parseInt(document.getElementById("llm-context-limit").value, 10) || 30000,
    };
    const apiKey = document.getElementById("llm-api-key").value.trim();
    if (apiKey) body.api_key = apiKey;
    try {
        const res = await fetch("/api/management/llm-config", {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.success) {
            showToast("LLM configuration saved.", "success");
            document.getElementById("llm-api-key").value = "";
            fetchLlmConfig();
        } else {
            showToast("Save failed.", "error");
        }
    } catch (e) {
        showToast("Request failed.", "error");
    }
}

async function testLlmConfig() {
    const resultEl = document.getElementById("llm-test-result");
    resultEl.textContent = "Testing connection...";
    const body = {
        base_url: document.getElementById("llm-base-url").value.trim(),
        model_name: document.getElementById("llm-model-name").value.trim(),
    };
    const apiKey = document.getElementById("llm-api-key").value.trim();
    if (apiKey) body.api_key = apiKey; // test the not-yet-saved key if one was just typed
    try {
        const res = await fetch("/api/management/llm-config/test", {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.success) {
            resultEl.textContent = `✓ Reachable -- responded in ${data.elapsed_seconds}s ("${data.reply}").`;
            showToast("LLM endpoint is reachable.", "success");
        } else {
            resultEl.textContent = "✗ " + data.error;
            showToast("LLM connection test failed.", "error");
        }
    } catch (e) {
        resultEl.textContent = "✗ Test request failed.";
    }
}

// ---- Retention ----

async function fetchRetentionSummary() {
    try {
        const res = await fetch("/api/management/retention/storage-summary");
        const data = await res.json();
        renderRetentionSummary(data);
    } catch (e) {
        console.error("Fetch retention summary error:", e);
    }
}

function renderRetentionSummary(data) {
    const cards = document.getElementById("retention-summary-cards");
    if (!cards) return;
    cards.innerHTML = "";
    const labels = { memory_dumps: "Memory Dumps", pcaps: "PCAPs", evidence_general: "General Evidence" };
    Object.keys(labels).forEach(cat => {
        const c = (data.categories && data.categories[cat]) || { total_bytes: 0, file_count: 0 };
        const card = document.createElement("div");
        card.className = "retention-card";
        const label = document.createElement("div"); label.className = "retention-card-label"; label.textContent = labels[cat];
        const value = document.createElement("div"); value.className = "retention-card-value"; value.textContent = humanBytes(c.total_bytes);
        const sub = document.createElement("div"); sub.className = "retention-card-sub"; sub.textContent = `${c.file_count} file(s)`;
        card.appendChild(label); card.appendChild(value); card.appendChild(sub);
        cards.appendChild(card);
    });

    const body = document.getElementById("retention-by-investigation-body");
    body.innerHTML = "";
    (data.by_investigation || []).forEach(inv => {
        const tr = document.createElement("tr");
        const nameTd = document.createElement("td"); nameTd.textContent = inv.folder_name; tr.appendChild(nameTd);
        const sizeTd = document.createElement("td"); sizeTd.textContent = humanBytes(inv.total_bytes); tr.appendChild(sizeTd);
        const mtimeTd = document.createElement("td"); mtimeTd.textContent = new Date(inv.mtime * 1000).toLocaleString(); tr.appendChild(mtimeTd);
        body.appendChild(tr);
    });
}

async function fetchRetentionPolicies() {
    try {
        const res = await fetch("/api/management/retention/policies");
        const data = await res.json();
        renderRetentionPolicyForms(data.policies || []);
    } catch (e) {
        console.error("Fetch retention policies error:", e);
    }
}

function renderRetentionPolicyForms(policies) {
    const container = document.getElementById("retention-policy-forms");
    if (!container) return;
    container.innerHTML = "";
    const labels = { memory_dumps: "Memory Dumps", pcaps: "PCAPs", evidence_general: "General Evidence" };
    policies.forEach(p => {
        const row = document.createElement("div");
        row.className = "retention-policy-row";

        const label = document.createElement("div"); label.className = "policy-label"; label.textContent = labels[p.category] || p.category;
        row.appendChild(label);

        const ageGroup = document.createElement("div"); ageGroup.className = "form-group";
        const ageLabel = document.createElement("label"); ageLabel.className = "form-label"; ageLabel.textContent = "Max age (days)";
        const ageInput = document.createElement("input"); ageInput.type = "number"; ageInput.className = "form-input";
        ageInput.value = (p.max_age_days !== null && p.max_age_days !== undefined) ? p.max_age_days : "";
        ageGroup.appendChild(ageLabel); ageGroup.appendChild(ageInput); row.appendChild(ageGroup);

        const gbGroup = document.createElement("div"); gbGroup.className = "form-group";
        const gbLabel = document.createElement("label"); gbLabel.className = "form-label"; gbLabel.textContent = "Max total (GB)";
        const gbInput = document.createElement("input"); gbInput.type = "number"; gbInput.className = "form-input";
        gbInput.value = (p.max_total_gb !== null && p.max_total_gb !== undefined) ? p.max_total_gb : "";
        gbGroup.appendChild(gbLabel); gbGroup.appendChild(gbInput); row.appendChild(gbGroup);

        const autoGroup = document.createElement("div"); autoGroup.className = "form-group form-checkbox-row";
        const autoLabel = document.createElement("label");
        const autoCb = document.createElement("input");
        autoCb.type = "checkbox";
        autoCb.checked = !!p.auto_archive_enabled;
        autoLabel.appendChild(autoCb);
        autoLabel.appendChild(document.createTextNode(" Auto-flag violations"));
        autoLabel.title = "Runs a background check every few minutes and logs a warning when this category " +
            "violates its policy. Never deletes anything automatically -- deletion always requires the " +
            "Sweep Preview + explicit confirmation below.";
        autoGroup.appendChild(autoLabel);
        row.appendChild(autoGroup);

        const saveBtn = document.createElement("button");
        saveBtn.className = "btn btn-outline btn-sm";
        saveBtn.textContent = "Save policy";
        saveBtn.addEventListener("click", async () => {
            await fetch("/api/management/retention/policies", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    category: p.category,
                    max_age_days: ageInput.value ? parseInt(ageInput.value, 10) : null,
                    max_total_gb: gbInput.value ? parseFloat(gbInput.value) : null,
                    auto_archive_enabled: autoCb.checked,
                }),
            });
            showToast("Policy saved.", "success");
        });
        row.appendChild(saveBtn);

        const previewBtn = document.createElement("button");
        previewBtn.className = "btn btn-warning btn-sm";
        previewBtn.textContent = "Run Sweep Preview";
        previewBtn.addEventListener("click", () => openSweepPreview(p.category, labels[p.category] || p.category));
        row.appendChild(previewBtn);

        container.appendChild(row);
    });
}

let sweepCandidatesCache = [];

async function openSweepPreview(category, label) {
    document.getElementById("sweep-category-label").textContent = label;
    try {
        const res = await fetch("/api/management/retention/sweep-preview", {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ category }),
        });
        const data = await res.json();
        sweepCandidatesCache = data.candidates || [];
        const list = document.getElementById("sweep-candidates-list");
        list.innerHTML = "";
        if (sweepCandidatesCache.length === 0) {
            list.textContent = "No files currently violate this category's policy.";
        } else {
            sweepCandidatesCache.forEach((c, idx) => {
                const row = document.createElement("div");
                row.className = "sweep-candidate-row";
                const cb = document.createElement("input");
                cb.type = "checkbox";
                cb.dataset.idx = idx;
                cb.checked = true;
                const info = document.createElement("div");
                const pathDiv = document.createElement("div"); pathDiv.className = "path"; pathDiv.textContent = c.path;
                const metaDiv = document.createElement("div");
                metaDiv.textContent = `${humanBytes(c.size_bytes)} · ${c.age_days} days old · ${c.reason}`;
                info.appendChild(pathDiv); info.appendChild(metaDiv);
                row.appendChild(cb); row.appendChild(info);
                list.appendChild(row);
            });
        }
        document.getElementById("sweep-preview-modal-overlay").classList.add("open");
    } catch (e) {
        showToast("Could not load sweep preview.", "error");
    }
}
function closeSweepPreviewModal() {
    document.getElementById("sweep-preview-modal-overlay").classList.remove("open");
}
async function executeSweepSelected() {
    const checkboxes = document.querySelectorAll("#sweep-candidates-list input[type=checkbox]:checked");
    const paths = [...checkboxes].map(cb => sweepCandidatesCache[parseInt(cb.dataset.idx, 10)].path);
    if (paths.length === 0) { showToast("Nothing selected.", "warning"); return; }
    const ok = await showConfirm(`Permanently delete ${paths.length} file(s)? This cannot be undone.`,
        { title: "Delete evidence files", confirmLabel: "Delete", tone: "danger" });
    if (!ok) return;
    try {
        const res = await fetch("/api/management/retention/sweep-execute", {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paths }),
        });
        const data = await res.json();
        showToast(`${data.deleted.length} file(s) deleted${data.errors.length ? ", " + data.errors.length + " error(s)" : ""}.`,
            data.errors.length ? "warning" : "success");
        closeSweepPreviewModal();
        fetchRetentionSummary();
    } catch (e) {
        showToast("Sweep request failed.", "error");
    }
}

// ---- Users + Global Audit Log ----

async function fetchUsers() {
    try {
        const res = await fetch("/api/management/users");
        const data = await res.json();
        renderUsersTable(data.users || []);
    } catch (e) {
        console.error("Fetch users error:", e);
    }
}

function renderUsersTable(users) {
    const body = document.getElementById("users-table-body");
    if (!body) return;
    body.innerHTML = "";
    users.forEach(u => {
        const tr = document.createElement("tr");
        const nameTd = document.createElement("td"); nameTd.textContent = u.username; tr.appendChild(nameTd);

        const roleTd = document.createElement("td");
        const roleSelect = document.createElement("select");
        roleSelect.className = "form-select";
        ["admin", "analyst", "viewer"].forEach(role => {
            const opt = document.createElement("option");
            opt.value = role;
            opt.textContent = role;
            if (role === u.role) opt.selected = true;
            roleSelect.appendChild(opt);
        });
        roleSelect.addEventListener("change", async () => {
            await fetch(`/api/management/users/${u.id}`, {
                method: "PATCH", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ role: roleSelect.value }),
            });
            showToast("Role updated.", "success");
        });
        roleTd.appendChild(roleSelect);
        tr.appendChild(roleTd);

        const statusTd = document.createElement("td");
        statusTd.textContent = u.must_change_password ? "Password reset pending" : "Active";
        tr.appendChild(statusTd);

        const actionsTd = document.createElement("td");
        const resetBtn = document.createElement("button");
        resetBtn.className = "btn btn-outline btn-sm";
        resetBtn.textContent = "Reset password";
        resetBtn.addEventListener("click", async () => {
            const newPw = window.prompt(`New temporary password for ${u.username} (8+ characters):`, "");
            if (!newPw || newPw.length < 8) return;
            await fetch(`/api/management/users/${u.id}`, {
                method: "PATCH", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ reset_password: newPw }),
            });
            showToast("Password reset.", "success");
            fetchUsers();
        });
        actionsTd.appendChild(resetBtn);

        const delBtn = document.createElement("button");
        delBtn.className = "btn btn-ghost btn-sm";
        delBtn.textContent = "Delete";
        delBtn.addEventListener("click", async () => {
            const ok = await showConfirm(`Delete user ${u.username}?`, { title: "Delete user", confirmLabel: "Delete", tone: "danger" });
            if (!ok) return;
            const res = await fetch(`/api/management/users/${u.id}`, { method: "DELETE" });
            const data = await res.json();
            if (!data.success) showToast(data.error, "error");
            fetchUsers();
        });
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        body.appendChild(tr);
    });
}

function openCreateUserModal() {
    document.getElementById("cu-username").value = "";
    document.getElementById("cu-password").value = "";
    document.getElementById("cu-role").value = "analyst";
    document.getElementById("create-user-modal-overlay").classList.add("open");
}
function closeCreateUserModal() {
    document.getElementById("create-user-modal-overlay").classList.remove("open");
}
async function submitCreateUser() {
    const username = document.getElementById("cu-username").value.trim();
    const password = document.getElementById("cu-password").value;
    const role = document.getElementById("cu-role").value;
    if (!username || password.length < 8) { showToast("Username and an 8+ character password are required.", "warning"); return; }
    try {
        const res = await fetch("/api/management/users", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password, role }),
        });
        const data = await res.json();
        if (data.success) {
            showToast("User created.", "success");
            closeCreateUserModal();
            fetchUsers();
        } else {
            showToast(data.error || "Could not create user.", "error");
        }
    } catch (e) {
        showToast("Request failed.", "error");
    }
}

async function fetchGlobalAuditLog() {
    try {
        const res = await fetch("/api/management/audit-log?limit=200");
        const data = await res.json();
        const body = document.getElementById("audit-log-table-body");
        if (!body) return;
        body.innerHTML = "";
        (data.entries || []).forEach(e => {
            const tr = document.createElement("tr");
            [e.timestamp, e.actor, e.action, e.reason || ""].forEach(v => {
                const td = document.createElement("td");
                td.textContent = v;
                tr.appendChild(td);
            });
            body.appendChild(tr);
        });
    } catch (e) {
        console.error("Fetch audit log error:", e);
    }
}

// ==========================================
// HELP CENTER
// ==========================================

let helpSearchIndexCache = null;
let helpActiveTagFilters = new Set();

function initHelpCenter() {
    if (!document.getElementById("help-content")) return; // not on the /help pages

    initHelpScrollSpy();

    document.addEventListener("click", (e) => {
        const results = document.getElementById("help-search-results");
        const input = document.getElementById("help-search-input");
        if (results && input && !results.contains(e.target) && e.target !== input) {
            results.classList.remove("open");
        }
    });
}

async function ensureHelpSearchIndex() {
    if (helpSearchIndexCache) return helpSearchIndexCache;
    try {
        const res = await fetch("/api/help/search-index");
        const data = await res.json();
        helpSearchIndexCache = data.entries || [];
    } catch (e) {
        helpSearchIndexCache = [];
    }
    return helpSearchIndexCache;
}

function _helpFuzzyScore(query, entry) {
    const q = query.toLowerCase();
    const title = (entry.title || "").toLowerCase();
    const excerpt = (entry.excerpt || "").toLowerCase();
    const tags = (entry.tags || []).join(" ").toLowerCase();
    if (title === q) return 100;
    if (title.startsWith(q)) return 90;
    if (title.includes(q)) return 70;
    if (tags.includes(q)) return 60;
    if (excerpt.includes(q)) return 40;
    return 0;
}

async function onHelpSearchInput(query) {
    const resultsEl = document.getElementById("help-search-results");
    if (!resultsEl) return;
    const index = await ensureHelpSearchIndex();

    let entries = index;
    if (helpActiveTagFilters.size > 0) {
        entries = entries.filter(e => (e.tags || []).some(t => helpActiveTagFilters.has(t)));
    }

    if (!query || !query.trim()) {
        resultsEl.classList.remove("open");
        resultsEl.innerHTML = "";
        return;
    }

    const scored = entries
        .map(e => ({ entry: e, score: _helpFuzzyScore(query, e) }))
        .filter(s => s.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, 15);

    resultsEl.innerHTML = "";
    if (scored.length === 0) {
        const empty = document.createElement("div");
        empty.className = "help-search-empty";
        empty.textContent = "No matching help topics.";
        resultsEl.appendChild(empty);
    } else {
        scored.forEach(({ entry }) => {
            const a = document.createElement("a");
            a.className = "help-search-result";
            a.href = `/help/${entry.slug}#${entry.anchor}`;

            const moduleDiv = document.createElement("div");
            moduleDiv.className = "help-search-result-module";
            moduleDiv.textContent = entry.module_title || "";
            a.appendChild(moduleDiv);

            const titleDiv = document.createElement("div");
            titleDiv.className = "help-search-result-title";
            titleDiv.textContent = entry.title;
            a.appendChild(titleDiv);

            if (entry.excerpt) {
                const excerptDiv = document.createElement("div");
                excerptDiv.className = "help-search-result-excerpt";
                excerptDiv.textContent = entry.excerpt;
                a.appendChild(excerptDiv);
            }
            resultsEl.appendChild(a);
        });
    }
    resultsEl.classList.add("open");
}

function toggleHelpTagFilter(tag) {
    const chip = document.querySelector(`.help-tag-chip[data-tag="${tag}"]`);
    if (helpActiveTagFilters.has(tag)) {
        helpActiveTagFilters.delete(tag);
        if (chip) chip.classList.remove("active");
    } else {
        helpActiveTagFilters.add(tag);
        if (chip) chip.classList.add("active");
    }

    document.querySelectorAll(".help-heading-link").forEach(link => {
        const linkTags = (link.dataset.tags || "").split(",").filter(Boolean);
        const visible = helpActiveTagFilters.size === 0 || linkTags.some(t => helpActiveTagFilters.has(t));
        link.classList.toggle("tag-hidden", !visible);
    });

    const searchInput = document.getElementById("help-search-input");
    if (searchInput && searchInput.value.trim()) onHelpSearchInput(searchInput.value);
}

function initHelpScrollSpy() {
    const tocLinks = document.querySelectorAll(".help-onpage-toc-link");
    if (tocLinks.length === 0) return;
    const headingEls = [...tocLinks].map(link => document.getElementById(link.dataset.anchor)).filter(Boolean);
    if (headingEls.length === 0 || !("IntersectionObserver" in window)) return;

    const setActive = (anchor) => {
        tocLinks.forEach(link => link.classList.toggle("active", link.dataset.anchor === anchor));
    };

    const observer = new IntersectionObserver((entries) => {
        const visible = entries.filter(e => e.isIntersecting);
        if (visible.length > 0) setActive(visible[0].target.id);
    }, { rootMargin: "-10% 0px -70% 0px" });

    headingEls.forEach(el => observer.observe(el));
}
