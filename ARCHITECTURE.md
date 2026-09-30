# IAI — Investigate with AI: System Architecture

A single-process Flask application that runs a two-phase Windows DFIR pipeline: **Phase 1 — Evidence Collection** (a script that copies and parses forensic artifacts from a target drive into a timestamped staging folder) and **Phase 2 — AI Agent Swarm Analysis** (a tree of ~25 agents — all but two are LLM-backed, see §6.4 — that read that staging folder and produce findings, gated by a Human-In-The-Loop approval step per agent). A vanilla-JS dashboard visualizes the agent tree as a live SVG DAG and lets an analyst approve/revise findings in real time.

There is no database and no message queue. All live state lives in one process-wide Python singleton (`bridge.hitl_bridge.bridge`); persistence is just files written under `investigation_staging_<timestamp>/`.

---

## 1. High-level flow

```
Browser (dashboard.html / topology.html / agents.html / findings.html / iocs.html /
         help.html / management.html, static/js/app.js — behind login/auth, §7.2)
        │  polls every 2s: /api/status /api/logs /api/topology /api/agents /api/findings
        │  actions:        /api/investigation/start|pause|resume|stop
        │                   /api/hitl/approve|revise  /api/upload/*  /api/browse-folder
        ▼
Flask app (app.py → web/routes.py + web/auth.py + web/management_routes.py +
           web/help_routes.py, single process, debug=True)
        │
        │  POST /api/investigation/start  { staging_dir, scope, drive_letter, target_folder }
        │  → creates/reuses investigation_staging_<YYYYMMDD_HHMMSS>/
        │  → NEW investigation: bridge.reset_state() (clean topology/logs/findings)
        │    RESUMED investigation: bridge.load_snapshot(dir) (restores that dir's
        │    own dashboard_state.json instead of wiping it — see §4)
        │  → spawns ONE daemon background thread
        ▼
Background thread (run_wrapper, in web/routes.py)
        │
        ├─ Phase 1 (skipped if drive_letter == "SKIP" and no target_folder):
        │     subprocess.Popen(python -m collectors.collector
        │                       --drive X | --folder <path>
        │                       --staging <dir> --scope <ALL|WINDOWS|FILE|MEMORY>)
        │     (--folder ingests just that one folder's files for File/Malware analysis,
        │      via run_folder_collection() — not a drive-root sweep — picked with the
        │      in-app folder browser, /api/browse-folder, instead of typing a path)
        │     stdout/stderr streamed line-by-line into bridge.log_event()
        │
        └─ Phase 2:
              MasterAnalystAgent()  →  asyncio.run(execute_full_investigation(...))
              (runs entirely inside this thread's own fresh asyncio event loop)
                    │
                    ▼
        MasterAnalystAgent  ── sequential await ──▶  3 "father" orchestrators
                                                        ── sequential await ──▶ sub-masters
                                                        ── sequential await ──▶ leaf agents
                                                              │
                                                              │ each leaf: parse artifacts →
                                                              │ call Gemini LLM → AgentResponse →
                                                              │ bridge.register_hitl_pause() →
                                                              │ await asyncio.Event (SUSPENDS)
                                                              ▼
                                          bridge.pending_approvals[agent_name]  (node turns YELLOW)
                                                              ▲
                                                              │ Flask thread calls
                                                              │ bridge.submit_hitl_decision()
                                                              │ loop.call_soon_threadsafe(event.set)
                                                              │ (cross-thread wake-up)
                                                              │
                                             Analyst clicks Approve/Revise in browser
```

Two threads matter: the Flask WSGI thread (handles HTTP synchronously) and the one background daemon thread per investigation run (owns its own asyncio event loop, runs the collector subprocess then the whole agent swarm). They only ever talk to each other through the `bridge` singleton, using `loop.call_soon_threadsafe()` to safely wake a suspended coroutine from the other thread.

---

## 2. Directory map

```
app.py                      Flask entry point: creates app, calls web.routes.register_routes()
requirements.txt            flask, werkzeug, openai (used as a Gemini-compatible client), pydantic,
                              volatility3 (Memory Analysis Father Agent, §6.4),
                              mcp (File / Malware Analysis Father Agent, §6.5)
collector_paths.json        17 categories of Windows artifact glob patterns (Phase 1 config)
event_context.txt           Analyst case-notes, auto-injected into every agent's system prompt
ioc_list.txt                 Optional, absent by default: one IP/domain per line, used by
                              Network_Socket_Correlator's deterministic IOC cross-reference (§6.4)
build_field_kit.py          Dev-only: PyInstaller-freezes collectors/collector.py into a
                              standalone run_kit.exe field kit (see §9)
field_kit/                  Templates copied into the built kit: run_kit.py, run_kit.bat,
                              rebuild_kit.bat (dev-only), README.txt

core/                        Foundation shared by every agent, plus platform-wide services (§7.2-§7.5)
├── models.py                  Pydantic schemas: the data contract
├── base_agent.py              BaseHITLAgent: LLM client, safe-file-reading, HITL loop
├── utils.py                    locate_staging_directory(), load_event_context(), load_ioc_list()
├── handoff.py                  Cross-agent file handoff -- see §6.6
├── llm_config.py               Reads the admin-editable LLM Provider Configuration DB row (§7.3)
│                                 that every agent's LLM client is now built from -- see §3.2
├── help_content.py             Renders docs/help-center/*.md server-side for /help (§7.5)
├── retention_scheduler.py      Background thread: logs (never deletes) retention-policy violations
├── sigma_engine.py             A real, partial-spec Sigma rule evaluator (see §7.3)
├── yara_engine.py               YARA rule text validation for the Management page's YARA tab
├── exclusion_engine.py         Findings suppression rule matching (Management page's Exclusion Rules tab)
├── retention.py                 Storage-usage scanning + preview/execute sweep logic (Management page)
└── finding_utils.py             Shared helpers for the Findings/IOCs pages (e.g. IOC type classification)

bridge/
└── hitl_bridge.py            WebHITLBridge — the single process-wide state hub ("bridge")

db/                          SQLite-backed persistence for everything that isn't per-investigation
├── database.py                SQLite engine at iai.db, init_db()/seed defaults, get_session() contextmanager
└── models.py                  13 tables: User, LlmProviderConfig, FindingOverlay, ManualFinding,
                                 LocalIOC, AuditLogEntry, EnrichmentJob, SavedView, FindingLock,
                                 FindingComment, ExclusionRule, YaraRule, SigmaRule, RetentionPolicy

collectors/                  Phase 1: evidence acquisition (runs as a subprocess)
├── collector.py               Drive walk, SHA-256 verified copy, external tool parsing
└── file_extractor.py          Standalone CLI hashing/copy utility (NOT wired into the app)

agents/                      Phase 2: the AI swarm
├── orchestrators/             Master + 3 "father" agents + 2 sub-masters (no LLM calls of their own)
├── windows_forensics/         6 leaf agents (Prefetch, Amcache, Shimcache, EVTX/Sysmon, Registry, Timeline)
├── malware_paths/             7 leaf agents (Temp, Downloads, ProgramData, Tasks, Services, Drivers, Autoruns)
├── file_analysis/             3 sub-modules: PeStudio_Static_Triage_Analyzer (pure automation),
                                   Ghidra_Reverse_Engineering_Agent (automation+LLM, incl. string
                                   extraction/decode -- absorbed the old separate Strings agent),
                                   Dynamic_Sandbox_Correlator (hybrid, Cuckoo v3 MCP);
                                   mcp_client.py (shared Ghidra/CAPA/Cuckoo MCP automation)
└── memory_analysis/            4 sub-modules: Malfind_Correlator (pure automation),
                                   MalFind_Injected_Code_Analyzer (hybrid + handoff),
                                   PsTree_Process_Mapper (automation+LLM),
                                   Network_Socket_Correlator (pure automation);
                                   volatility_runner.py (shared Volatility3 automation)

web/                         The HTTP layer -- 4 files, ~97 route declarations total (§7.1)
├── routes.py                  Investigation lifecycle, HITL, uploads, drives/folder-browse, Findings, IOCs
├── auth.py                     Session login, the global auth/role gate, change-password (§7.2)
├── management_routes.py        All /management + /api/management/* routes, admin-only (§7.3)
└── help_routes.py               /help/<slug> + /api/help/search-index (§7.5)

static/js/app.js             Dashboard client, ~3,700 lines: 2s polling, hand-rolled SVG DAG renderer,
                              HITL UI, folder browser, Findings triage + drawer, System Management UI,
                              IOC library, Help Center client-side search
templates/                   base.html (nav shell, 5 nav links + user dropdown) + dashboard.html +
                              topology.html + agents.html + findings.html + iocs.html + help.html +
                              management.html, plus standalone (no navbar) login.html +
                              change_password.html, and forbidden.html for 403s
docs/help-center/            Source markdown for the in-app Help Center (§7.5) -- 7 articles + README.md
tools/                       Third-party forensic CLIs (PECmd, AmcacheParser, EvtxECmd, RegRipper, autorunsc, …)
investigation_staging_*/     Per-run output: raw/ + metadata/ per category, hash_manifest.csv,
                              execution_report.json, dashboard_state.json (bridge UI snapshot,
                              see §4), and every orchestrator level's *_Report.json
instance/.secret_key         Flask session-cookie signing key, generated once on first run (§7.2)
iai.db                       SQLite database file (git-ignored), created by db.database.init_db()
dist/                         Build output only (git-ignored): dist/IAI_Collection_Kit/ + .zip
```

---

## 3. Foundation layer (`core/`)

### 3.1 `core/models.py` — the shared data contract

Every agent's LLM output is forced into this schema:

- **`ForensicAnomaly`** — `filepath, anomaly_type, severity (High/Medium/Low), justification, recommended_action`
- **`AgentAnalysisReport`** — `agent_name, status (Clean/Suspicious/Critical), anomalies_found: List[ForensicAnomaly], summary`
- **`AgentResponse`** — wraps `agent_name, raw_data_parsed, ai_analysis, status="PENDING_APPROVAL"`; this is what gets shown to the analyst
- **`HumanFeedback`** — `action (APPROVE/REVISE), feedback`; what a human decision resolves to

`AgentAnalysisReport.schema_json()` is injected verbatim into every agent's system prompt (`core/base_agent.py:38`), so the LLM is contractually forced to return that exact JSON shape — this is the only "structure enforcement" mechanism; there's no server-side re-validation of the LLM's JSON beyond `json.loads`.

### 3.2 `core/base_agent.py` — `BaseHITLAgent`

Every leaf agent subclasses this, including the two pure-automation Memory Analysis sub-modules (§6.4) that never actually call the LLM client it sets up — they still need the rest of this class (HITL submit/approve/revise plumbing, parsing helpers). It provides:

- **LLM client**: `AsyncOpenAI` configured from `core/llm_config.py:get_active_llm_config()`, which reads the singleton `LlmProviderConfig` row (`db/models.py`, id=1) — base URL, API key, model name, context-char limit — rather than an environment variable or a hardcoded default. This is editable from **System Management → AI & Agent Orchestration → LLM Provider Configuration** (§7.3), defaults to a local Open WebUI instance (offline-first), and that page's **Test Connection** button sends one real minimal request to verify reachability. `llm_config.py`'s own hardcoded dict is only ever used if the DB row is missing entirely (e.g. a hand-built DB not created via `init_db()`) — not a live-key fallback for normal operation.
- **Forensic safety gate**: files with executable extensions (`.exe .dll .sys .scr .com .msi .cpl .ocx .drv`) or known binary-artifact extensions (`.dat .hve .evtx .db .pf .lnk .zip .rar .7z .iso .img .bin`) are *never* opened as text — only their name/size/hash are given to the LLM. A third check, `_looks_like_binary()`, sniffs the first 4KB (PE `MZ` header, NUL bytes, non-printable ratio) to catch binaries with disguised extensions. This is centralized once here so no leaf agent can accidentally feed executable bytes to the LLM.
- **Parsing helpers**: `parse_category_artifacts(staging_root, category)` is the workhorse most leaf agents call — it walks `<staging_root>/<category>/raw/` (through the safety gate above) and `<staging_root>/<category>/metadata/` (parsing any `.csv` there — i.e. the output of the external forensic tools — via `csv.DictReader`), and returns one JSON string, hard-truncated at `MAX_PAYLOAD_CHARS = 30000` characters.
- **`execute_llm_analysis()`**: one call to `chat.completions.create(..., response_format={"type":"json_object"}, temperature=0.1)` against the running `conversation_history`.
- **`run_with_hitl(parsed_tool_data)`** — the loop every leaf agent's `process_task()` ends by calling:
  1. `await bridge.wait_if_paused()` — honors a global pause before starting.
  2. Appends parsed data to `conversation_history`, calls `execute_llm_analysis()`.
  3. Wraps the result as an `AgentResponse`, hands it to `send_to_dashboard_and_wait()`.
  4. **AUTOMATIC mode** → auto-approves immediately, node turns `BLUE`.
     **SUPERVISED mode** (default) → `bridge.register_hitl_pause()` creates an `asyncio.Event`, stores it under `bridge.pending_approvals[agent_name]`, sets the node `YELLOW`, and the coroutine genuinely suspends on `await event.wait()` until a human acts.
  5. On **APPROVE** → returns the final `AgentResponse` up the call chain.
     On **REVISE** → the prior AI JSON plus a synthesized message `"Human Analyst Override: {feedback}. Fix your analysis and return updated JSON."` are appended to `conversation_history`, and step 2 re-runs — i.e. revision replays the *entire* conversation with the analyst's correction now part of context, not a diff-patch.
  6. If the `bridge` import/call fails outright (e.g. running an agent standalone via `python -m agents...` with no Flask app), it falls back to a blocking terminal `input()` prompt.

### 3.3 `core/utils.py`

- `locate_staging_directory(search_root, explicit_path)` — if no explicit path given, globs `investigation_staging_*` under `search_root` and returns the one with the **latest mtime** (not lexical order).
- `load_event_context()` — reads `event_context.txt` from the **repo root** (not cwd, not staging dir), truncates at 4000 chars, and is folded into every agent's system prompt as shared case context.

---

## 4. State hub (`bridge/hitl_bridge.py`) — `WebHITLBridge` / the `bridge` singleton

This is the nervous system connecting the HTTP layer, the background thread, and the async agent swarm. Instantiated once at import time; every consumer does `from bridge.hitl_bridge import bridge`.

**State held (all in-memory, lost on process restart):**
- `execution_mode` (SUPERVISED default / AUTOMATIC), `pipeline_status` (IDLE/RUNNING/PAUSED/COMPLETED/ERROR), `is_paused` + `pause_event`
- `nodes` — a **hardcoded 27-node DAG** mirroring the fixed agent hierarchy (`_init_topology_nodes()`); each node has `{id, label, type, state, parent, role}`
- `pending_approvals: Dict[agent_name, {event, loop, raw_data, ai_analysis, decision, ...}]`
- `agent_states: Dict[agent_name, AgentResponse.dict()]` — latest result per agent, for dashboard display
- `prompt_overrides: Dict[agent_name, str]` — see §10, this is display-only
- `logs` — ring buffer capped at 2000 entries

**Node states**: `GRAY` (idle) → `YELLOW` (awaiting analyst HITL decision) → `BLUE` (approved) or `GREEN` (revision requested / activity underneath). `update_node_state()` also force-propagates `GREEN` one level up to the parent when a child turns `GREEN`/`YELLOW`, so a father node visually lights up while any of its children are active. (No `RED`/error state exists anywhere in the codebase — a failed pipeline just sets `pipeline_status="ERROR"`, no node is recolored.)

**The cross-thread handshake** (the trickiest part of the system):
1. A leaf agent's coroutine (running inside the background thread's own asyncio event loop) calls `bridge.register_hitl_pause()`, which grabs that loop via `asyncio.get_event_loop()`, stores it alongside a fresh `asyncio.Event` in `pending_approvals[agent_name]`, and returns the Event for the agent to `await`.
2. The analyst's approve/revise click hits a Flask route running on Flask's own (different) thread, which calls `bridge.submit_hitl_decision(agent_name, action, feedback)` synchronously.
3. That method stores the decision, recolors the node, and — critically — calls `loop.call_soon_threadsafe(event.set)` using the *stored* loop reference, not `event.set()` directly. This is what safely wakes the suspended coroutine living on a different thread's event loop.
4. The leaf agent's `await event.wait()` returns; it reads `pending_approvals.pop(agent_name)["decision"]` and continues.

No locks are used anywhere else — the design relies on the GIL plus this one thread-safe scheduling primitive for all cross-thread state mutation.

Other bridge responsibilities: `get_topology()` (nodes+links for the frontend graph), `get_available_drives()` (Windows `GetLogicalDrives()` bitmask via ctypes), `get_existing_investigations()` (scans for `investigation_staging_*` folders, independent of but parallel to `core.utils.locate_staging_directory`), `log_event()`, `set_pause_state()` (same `call_soon_threadsafe` pattern for global pause/resume).

**Per-investigation dashboard-state persistence** (`reset_state()` / `save_snapshot()` / `load_snapshot()`): because `bridge` is one process-wide singleton, switching investigations used to bleed state — Topology/Agent Control Center/Findings would keep showing whatever `nodes`/`agent_states`/`logs` the *previous* investigation left behind. This is now handled explicitly:
- `reset_state()` — reinitializes `nodes` (`_init_topology_nodes()`) and clears `agent_states`, `pending_approvals`, `logs`. Called for a genuinely **new** investigation (fresh slate) and by `/api/investigation/stop` (so the just-cleared bridge doesn't leak into whatever the analyst looks at next while idle).
- `save_snapshot(force=False)` — best-effort writes `{nodes, agent_states, logs}` as JSON to `<active_investigation_id>/dashboard_state.json`. Called from `update_node_state()` (`force=True`, i.e. every state transition) and from `log_event()` (throttled to at most once/second, since collector stdout can stream hundreds of lines/sec). Every write is wrapped in a bare `try/except: pass` — this is a view-state cache, not a source of truth, and is never allowed to raise into the agent/collector code paths that trigger it.
- `load_snapshot(staging_dir)` — called instead of `reset_state()` by `/api/investigation/start` when **resuming** an existing staging folder: reads that folder's `dashboard_state.json` back into `nodes`/`agent_states`/`logs` (falling back to `reset_state()` if the file is missing/corrupt), so re-selecting an investigation shows exactly the topology colors, findings, and log history it was left with.
- **This is view-state only, not pipeline resumability**: `pending_approvals` (live `asyncio.Event`/loop references) are deliberately never persisted or restored — there is no such thing as a resumed investigation with an agent still sitting mid-HITL-wait. Clicking "Resume Selected Session" restores what the dashboard *shows*, then still runs `MasterAnalystAgent().execute_full_investigation()` from scratch (§6.1) exactly as a new investigation would.
- `/api/investigation/stop` calls `save_snapshot(force=True)` *before* clearing `active_investigation_id`, so the outgoing investigation's final state is captured before the in-memory reset.

---

## 5. Evidence Collector (`collectors/collector.py`) — Phase 1

Runs as a **separate subprocess** (`python -m collectors.collector --drive X --staging <dir> --scope <ALL|WINDOWS|FILE|MEMORY>`), never imported in-process — this isolates any collector crash from the Flask app and lets its stdout be streamed live into the dashboard log.

There are two collection modes, dispatched by which CLI flag is present:

1. **Drive selection**: `--drive` letter, or interactive `input()`-driven picker over lettered drives detected via `os.path.exists("X:\\")`. This is the normal full/tiered sweep described below (steps 2-5).
   **Or `--folder <path>`**: `run_folder_collection()` ingests one arbitrary, possibly deeply-nested folder instead — no drive-root artifact categories apply (no registry hives, `$MFT`, VSS, Autoruns), it simply hashes and copies everything under that folder (via the same `copy_matched_path()` recursive-copy-with-hash-verify helper `collect_standard_artifacts()` uses) into `ProgramDataList/raw/` for File/Malware analysis. This backs the Launch Hub's "...or investigate a specific folder instead" picker (`/api/browse-folder`) — for when the analyst wants one specific folder analyzed, not a whole drive.
2. **Config**: reads `collector_paths.json` (17 categories → lists of glob patterns like `Users\*\NTUSER.DAT`, `Windows\Prefetch\*.pf`); unknown/malformed categories are skipped with a warning, never fatal.
3. **Staging layout**: creates `investigation_staging_<YYYYMMDD_HHMMSS>/<Category>/{raw,metadata}/` for every category (plus fixed extras: `ProgramDataList`, `AlternateDataStreams`, `VSS_Shadows`, `SysinternalsAutoruns`, or just `MemoryDumps` when `scope=MEMORY`).
4. **Copy + verify**: every matched file is SHA-256 hashed *before* copy, copied with `shutil.copy2`, then hashed *again* at the destination; a mismatch deletes the corrupted copy and logs it — nothing corrupted is left in the evidence set. Locked/in-use files raise `PermissionError`, which is caught and recorded as a failed manifest row (never aborts the run). Every result — matched/copied/failed per pattern, per-tool status, hash verification stats — is written to `hash_manifest.csv` (columns: `timestamp, category, source_path, dest_path, algorithm, source_hash, dest_hash, size_bytes, verified, error`) and `execution_report.json`, even on a fatal crash (`finally` block always saves both).
5. **External tool parsing** — after copying, `raw/` files are fed to Eric-Zimmerman-style CLI tools in `tools/`, writing CSV into `metadata/`:

   | Category | Tool | Notes |
   |---|---|---|
   | Prefetch | `PECmd.exe` | `-d {raw} --csv {meta}` |
   | Amcache | `AmcacheParser.exe` | parses `Amcache.hve` |
   | Shimcache | `AppCompatCacheParser.exe` | parses the copied `SYSTEM` hive |
   | Windows Event Logs | `EvtxECmd.exe` | batch `-d` over `raw/` |
   | Registry (NTUSER hives) | `rip.exe` (RegRipper) | run once per NTUSER file, `-p wordwheelquery` |
   | SysinternalsAutoruns | `autorunsc.exe` | run against the **live target drive**, once per user profile + once system-wide |

   Amcache/Shimcache/EVTX/Registry parsing is skipped for `scope=FILE`; Autoruns/VSS skipped for `FILE`/`MEMORY`; all parsing skipped for `scope=MEMORY`. Missing tool binaries or empty raw folders are skipped with a warning, not an error. Note: the `SRUM` category is collected raw but has no wired parser.
6. `collectors/file_extractor.py` is a small standalone hashing/copy CLI utility that is **not called anywhere** in the running app — the actual `/api/upload/extract` Flask route reimplements its own zip-extraction logic inline instead.

---

## 6. AI Agent Swarm (`agents/`) — Phase 2

### 6.1 Hierarchy

```
MasterAnalystAgent
├── WindowsForensicsMaster
│   ├── ArtifactsAnalyzerMaster       → Prefetch, Amcache, Shimcache
│   ├── CommonMalwarePathsMaster      → TempFolder, DownloadsFolder, ProgramData,
│   │                                    ScheduledTasks, Services, Drivers, Autoruns
│   └── (direct) EVTX/Sysmon, Registry Miner, Timeline Anomaly Detector
├── FileAnalysisMaster                → Static Triage & Capability Mapper, Reverse Engineering
│                                         & String Analyzer, Dynamic Sandbox Correlator
└── MemoryAnalysisMaster              → Malfind_Correlator, Injected Code Analyzer,
                                          Process & Thread Mapper, Network Socket Correlator
```

`MasterAnalystAgent` and every father/sub-master orchestrator except `MemoryAnalysisMaster` and `FileAnalysisMaster` is a thin, **non-LLM** coordinator: it builds a fixed list of sub-agents in `__init__`, and its `execute_investigation`/`process_task` method loops `for agent in self.sub_agents: result = await agent.process_task(staging_root)` — **strictly sequential, `asyncio.gather` is never used**, even though each leaf's work is independent. This is a deliberate/acknowledged limitation elsewhere in the tree: the HITL wait (a human clicking approve) blocks the entire chain one agent at a time. No orchestrator level presents anything to HITL itself — approval only ever happens inside a leaf agent's `run_with_hitl`/`run_automated_with_hitl` call, which the orchestrator chain transparently awaits. **`MemoryAnalysisMaster` (§6.4) and `FileAnalysisMaster` (§6.5) are the two exceptions.**

Dispatch is scope-gated: `MasterAnalystAgent.execute_full_investigation(scope=...)` only awaits a given father if `scope in ("ALL", <that father's scope tag>)`.

### 6.2 Leaf agent pattern

Each leaf agent implements one `async def process_task(self, staging_root)` that either calls `self.parse_category_artifacts(staging_root, "<Category>")` (the common path — maps 1:1 to a `collector_paths.json` category, e.g. `Prefetch`, `TempFolder`, `Logs`) or builds a **custom payload** across every collected category's `raw/` folder — the File Analysis (§6.5) and Memory Analysis (§6.4) sub-modules both do the latter, hand-parsing binaries/plugin output rather than reading a pre-existing metadata CSV.

Then every LLM-backed leaf ends with `return await self.run_with_hitl(parsed_tool_data)`; the pure-automation leaves in §6.4/§6.5 end with `run_automated_with_hitl()` instead (no LLM call at all).

### 6.3 Report aggregation

Every orchestration level writes its own JSON report into the staging root as it completes:
- Leaf → nothing separately written; its `AgentResponse` is returned up the chain.
- Sub-master → `Execution_Artifacts_Report.json`, `Master_Forensic_Report.json`
- Father → `Windows_Forensics_Master_Report.json`, `File_Analysis_Master_Report.json`, `Memory_Analysis_Master_Report.json`
- Master → `Master_Executive_Intelligence_Report.json` (top-level keys: `master_orchestrator, staging_root, scope, timestamp, father_agent_reports, father_agent_errors, cross_agent_handoffs, total_anomalies_flagged, critical_findings, overall_verdict` — see §6.6 for how the last four are derived, and why this file is now always written even if a father agent crashed)

### 6.4 Memory Analysis (`agents/memory_analysis/`, `agents/orchestrators/memory_analysis_master.py`) — the concurrent exception

Volatility3 automation lives behind one shared module, `agents/memory_analysis/volatility_runner.py`: `run_plugin(image_path, plugin, args=None, output_dir=None)` shells out to the `vol` CLI with `-r json` (falls back to `python -m volatility3.cli` if only the package, not its console script, is on PATH) and returns parsed rows, or `[]` with a `bridge.log_event(..., level="WARN")` if the plugin/binary/image fails — the same degrade-gracefully contract `collectors/collector.py` uses for every other external tool. The backend is swappable (`VolatilityBackend` / `set_backend()`) so an MCP transport can replace the subprocess call later without any sub-module changing. `locate_memory_image(staging_root)` resolves the analyst-uploaded dump from `MemoryDumps/raw/` (`.raw/.dmp/.vmem/.mem/.lime`, largest file wins if several are present).

Four sub-modules, not three:
- **`Malfind_Correlator`** (`malfind_correlator.py`, pure automation, **zero LLM tokens**) — runs `windows.malfind.Malfind --dump`, `windows.thrdscan.ThrdScan`, `windows.handles.Handles`, and `windows.dlllist.DllList` (per-process module ranges — `windows.modules.Modules` lists *kernel* drivers, not per-process VAs, so it can't answer this), then scores every malfind hit with a fixed point table (`correlate()`, a pure function, independently unit-testable with hand-built rows): unbacked VAD +30, thread start address inside the region +30, a remote process holding a `Process`-type handle +25 (+10 more if the granted-access string mentions VM write/thread-creation/all-access), PAGE_EXECUTE_READWRITE +15, VA falling inside a legitimately loaded module range −40. Score → severity is a fixed threshold (≥70 Critical / ≥50 High / ≥25 Medium / else Low). Submitted to the dashboard via `BaseHITLAgent.run_automated_with_hitl()` (see below) — a real `AgentAnalysisReport`-shaped result with no `execute_llm_analysis()` call anywhere in its path.
- **`MalFind_Injected_Code_Analyzer`** (`malfind.py`, hybrid) — does **not** re-run malfind. The Father Agent hands it the correlator's already-scored list; it only spends an LLM call reviewing candidates that scored ≥25 (Medium+), asking the LLM to rule out JIT/.NET/Mono/legitimate self-modifying code. The join between "candidate the correlator scored" and "candidate the LLM judged real" is a string key (`f"PID {pid} ({process}) @ {va}"`) that the system prompt instructs the LLM to echo back verbatim in `anomalies_found[].filepath` — omission from the LLM's response *is* its false-positive verdict, by prompt contract. Only after the analyst then **approves** (not merely LLM-flagged) does it build a `MalwareHandoffPayload` — locates the plugin's `--dump` output file (`find_malfind_dump()`), SHA-256/MD5-hashes it, sniffs an `MZ` header, and copies it into `ProgramDataList/raw/` — the exact folder `/api/upload/extract` already stages files into and `FileAnalysisMaster`'s Static Triage & Capability Mapper (§6.5) scans on the *next* run with zero additional wiring.
- **`PsTree_Process_Mapper`** (`pstree.py`, Automation → LLM) — runs `windows.pslist.PsList` + `windows.pstree.PsTree` + `windows.psxview.PsXView`; deterministically computes hidden/unlinked PIDs (seen by psxview, absent from pslist) and parent/child legitimacy against a small fixed table (`svchost.exe` should have `services.exe`/`wininit.exe` as parent, etc.) *before* the LLM call, so the LLM is pointed at pre-flagged candidates plus whatever the fixed table has no entry for (masquerading names, non-standard paths).
- **`Network_Socket_Correlator`** (`network.py`, pure automation, **zero LLM tokens**) — runs `windows.netscan.NetScan` (+ `windows.pslist.PsList` to detect orphaned sockets whose owner PID no longer exists), flags via a fixed rule set (known-non-networking process making an outbound connection, known C2-associated ports, high-port listeners, and an optional analyst-supplied IOC list at `<repo_root>/ioc_list.txt` via `core.utils.load_ioc_list()`). Also routed through `run_automated_with_hitl()`.

**`BaseHITLAgent.run_automated_with_hitl(parsed_tool_data, deterministic_analysis)`** (`core/base_agent.py`) is the one addition to the shared base class this required: identical HITL submit/approve/revise loop as `run_with_hitl()`, but `deterministic_analysis` — already `AgentAnalysisReport`-shaped — is submitted directly with no `execute_llm_analysis()` call. A REVISE decision on one of these has nothing to hand feedback to (there's no LLM call to re-run with the analyst's correction folded in), so it's logged as an analyst annotation via `bridge.log_event(level="HITL")` and the *same* deterministic result is re-submitted for another decision.

**`MemoryAnalysisMaster.execute_investigation()`** is genuinely two-stage, and the second stage runs concurrently:
```
Stage 1 (blocking):  Malfind_Correlator
Stage 2 (asyncio.gather, all three concurrent):
    MalFind_Injected_Code_Analyzer  <- consumes Stage 1's ranked candidates
    PsTree_Process_Mapper            <- independent
    Network_Socket_Correlator       <- independent
```
`return_exceptions=True` on the `gather()` — one sub-module crashing produces an `"status": "ERROR"` entry in the compiled report instead of taking the other two down with it, since they don't share mutable state. This is one of only two places in the whole agent tree that run independent leaves concurrently (the other is `FileAnalysisMaster`, §6.5; see §10's "no concurrency" gap, now scoped to "everywhere except these two") — safe specifically because none of these three ever mutate shared state outside their own `bridge.pending_approvals[agent_name]`/`bridge.agent_states[agent_name]` slot. The compiled `Memory_Analysis_Master_Report.json` is a real `MemoryAnalysisReport` pydantic model (`core/models.py`): `process_tree` (`ProcessTreeFinding`, automation anomalies + LLM anomalies re-parsed back out of `anomalies_found[].filepath` and merged), `malfind_correlations` (the full ranked list from Stage 1), `injected_regions` (`InjectedMemoryRegion`, confirmed vs. false-positive per candidate), `socket_correlation` (`SocketCorrelation`), and `handoffs_to_malware_analysis` (every `MalwareHandoffPayload` that was actually staged).

### 6.5 File / Malware Analysis (`agents/file_analysis/`, `agents/orchestrators/file_analysis_master.py`)

MCP (Model Context Protocol) automation lives behind one shared module, `agents/file_analysis/mcp_client.py`, mirroring `volatility_runner.py`'s shape exactly: `call_tool(server, tool_name, arguments)` talks the real MCP wire protocol (via the official `mcp` SDK, over stdio or SSE depending on `MCPServerSpec.transport`) and returns parsed data, or `{}` with a `bridge.log_event(..., level="WARN")` on any failure (server not installed/running, tool error, timeout, malformed response) — never raises into a sub-module. Three servers, each resolved from env vars at import time (`GHIDRA_MCP_*`, `CAPA_MCP_*`, `CUCKOO_MCP_*` — command/args for stdio, or `*_URL` for SSE): `mcp_client.GHIDRA_MCP`, `mcp_client.CAPA_MCP`, `mcp_client.CUCKOO_MCP` (defaults to SSE transport, since sandboxes are normally a standing network service rather than a per-call subprocess). The backend is swappable (`set_backend()`) for tests exactly like the Volatility layer.

Three sub-modules, matching the brief's count exactly (the old separate `Strings_Analyzer` node/agent no longer exists — its logic was absorbed into the Reverse Engineering module below):
- **`PeStudio_Static_Triage_Analyzer`** (`pestudio_analysis.py`, pure automation, **zero LLM tokens**, routed through `run_automated_with_hitl()`) — reuses this project's existing hand-rolled PE parser unchanged (header/section/import/export walk, per-section Shannon entropy, packer-section-name and RWX-section detection, suspicious-API-category table), adds a lightweight ELF header + `.dynsym`/`.dynstr` parser (`_parse_elf()`) for the `.elf`/`.so` case, computes `imphash` directly from the already-walked PE import table (no `pefile` dependency), an ELF-analog `typehash` (md5 of the sorted deduplicated imported-symbol-name list), and an `ssdeep` fuzzy hash that degrades to `None` if the `ssdeep` package/native `libfuzzy` isn't available. Calls `CAPA_MCP`'s `analyze_capabilities` tool per binary and maps its response into `MitreMapping` records. Every binary becomes one fully-typed `StaticAnalysisReport` (`core/models.py`); indicators and CAPA capabilities both feed `anomalies_found` directly — there is no LLM step anywhere in this module.
- **`Ghidra_Reverse_Engineering_Agent`** (`reverse_engineering.py`, automation → LLM) — calls `GHIDRA_MCP`'s `analyze_binary` tool for headless auto-analysis + per-function decompiled pseudocode, then filters to functions worth an LLM's attention (`_is_high_priority()`: cyclomatic complexity ≥ 8 **and** not a compiler-generated/CRT-init name via a regex allowlist) before spending any LLM call — the same cost-bounding philosophy as the memory module's Malfind_Correlator → Injected Code Analyzer hand-off. Also runs the (now-consolidated) string extraction/categorization pass, plus two automated decode routines the plain `strings`-style categorizer alone can't produce: `find_xor_encoded_strings()` brute-forces all 256 single-byte XOR keys over a bounded window of the raw binary and keeps only decodes that both look like clean text (padding-run trimming via `_trim_padding_runs()`, since XORing a run of repeated padding bytes with a printable-range key is itself printable and would otherwise bridge straight into a real string) and match a recognizable marker (URL / IP / command-path / **config-blob**, the last being a `KEY=VALUE`-shaped heuristic tuned specifically for decoded C2 configuration strings); `decode_base64_candidates()` does the equivalent for base64-shaped strings the categorizer already isolated. The LLM call's system prompt (`REVERSE_ENGINEERING_SYSTEM_PROMPT`) instructs it to echo back each function's `name@address` verbatim as `anomalies_found[].filepath` (same join-key pattern as the memory module), from which crypto-algorithm and suggested-rename are extracted via light regex on `justification` into typed `DecompiledFunctionFinding` records.
- **`Dynamic_Sandbox_Correlator`** (`dynamic_sandbox.py`, hybrid) — calls `CUCKOO_MCP`'s `submit_and_wait` tool (a single blocking-until-complete tool call, not a submit/poll pair — simplest contract for an MCP tool designed for automation), normalizes the behavioral report into `BehavioralIOC`/`NetworkArtifact` records, then — the module's actual "missing feature" — `correlate_static_and_dynamic()` deterministically cross-references the Static Triage module's CAPA capability list against what was actually observed: an injection capability is corroborated only if a process in the tree is flagged `injected`/`is_hollow` into a sensitive target name; a network capability only if any network artifact exists; a persistence capability only if a Run-key-shaped registry write exists. **An uncorroborated capability is reported, not dropped** — "CAPA claimed X but nothing at runtime did X" is itself a finding (sandbox evasion, unmet dependency, or a static false positive), never silently ignored. `detect_anti_analysis()` flags sandbox-evasion signature names and a near-zero-duration-with-no-network heuristic; `compute_risk_score()` is a fixed point table (corroborated capability +30, anti-analysis signal +20 ×min(2), unencrypted HTTP/TCP traffic +25, injection corroborated +25, persistence observed +15) → threshold severity, same auditable-score philosophy as `malfind_correlator.py`. The LLM call only runs on top of this table — explaining *why* an uncorroborated entry might not have fired, and flagging anomalies (sleep loops, cleartext C2, VM-artifact checks) the deterministic rules don't cover.

**`FileAnalysisMaster.execute_investigation()`**'s conditional gate is the literal brief example: Stage 1 (Static Triage, blocking, always runs) decides everything downstream. If every triaged binary comes back `Clean` (no indicators, no CAPA capabilities), Reverse Engineering **and** Dynamic Sandbox are both skipped outright (`reverse_engineering_skipped_reason`/`dynamic_skipped_reason` explain why) — there's nothing worth reverse engineering or, far more importantly, worth the expense/risk of detonating. Otherwise Stage 2 runs both remaining sub-modules **concurrently** via `asyncio.gather(..., return_exceptions=True)`: Reverse Engineering and Dynamic Sandbox Correlator are independent of each other by construction — the sandbox correlator takes its `static_capabilities` argument from Stage 1's CAPA list directly, not from Reverse Engineering's output — so there's no dependency forcing them to serialize. The sandboxed target is the single highest-severity triaged binary (`status` rank, tie-broken by CAPA capability count), not every file the collector staged — this pipeline detonates the primary suspicious artifact, matching the brief's "isolated suspicious artifacts" framing. The compiled `File_Analysis_Master_Report.json` is a typed `MalwareAnalysisReport`: `static` (`StaticAnalysisReport`), `reverse_engineering` (`ReverseEngineeringModel`, `None` when skipped), `dynamic` (`DynamicAnalysisReport`, `None` when skipped), plus the usual aggregated `total_anomalies_flagged`/`critical_findings`/`detailed_agent_reports`.

### 6.6 Cross-agent handoff & the top-level Master Analyst (`master_analyst.py`, `core/handoff.py`)

**The problem this solves**: most Windows Forensics agents only ever *describe* a suspicious file inside their `ForensicAnomaly.filepath` string — e.g. `Services_Analyzer`/`Drivers_Analyzer`/`Autoruns_Analyzer` reading a registry `ImagePath`, or `ProgramData_Analyzer` reading a directory-listing manifest (`ProgramDataList`'s collector step deliberately only lists top-level entries, never copies them — see §5). The referenced binary is very often never actually copied into the staging folder by `collectors/collector.py` at all, which means no amount of File Analysis running afterward would ever see it — the finding and the file it's about were disconnected the moment collection finished.

`core/handoff.py` closes that gap centrally, in exactly one place, rather than touching every leaf agent:
- `iter_anomalies(node)` recursively walks an arbitrarily-nested father-agent report (sub-master reports nest inside father reports nest inside the investigation summary, to unknown depth) and yields every `(agent_name, anomaly_dict)` pair at any level — it makes no assumption about whose report shape it's walking.
- `scan_and_handoff_suspicious_files(report_tree, staging_root)` filters those anomalies down to ones whose `filepath` is a real absolute Windows path (`^[A-Za-z]:\\` or a UNC prefix — this is exactly what excludes the non-filesystem identifier styles other agents already use as their own join-key, like memory analysis's `"PID 1337 @ 0x10000"` or a socket description string, with no per-agent special-casing needed), that actually exists on disk, and whose extension is one Static Triage's PE/ELF parser can actually do something with. Each survivor is SHA-256-hashed and skipped if that hash is already sitting under any category's `raw/` folder (already-collected files are already discoverable by Static Triage's own generic scan — no double-staging); otherwise it's copied into `ProgramDataList/raw/` — the same intake folder `/api/upload/extract` and the memory module's `MalwareHandoffPayload` handoff (§6.4) already use — as `handoff_<agent_name>_<filename>`, and a `HandoffRecord` (source agent, original path, staged path, hash, reason, severity, timestamp) is appended to `<staging_root>/handoffs.json`.
- Every step degrades silently on failure (unreadable file, hash error, copy failure) — a missed handoff must never abort the investigation, matching every other "external thing might fail" contract already established in this codebase (collector tool failures, MCP calls, Volatility plugin calls).

**Execution order changed to make the handoff useful within a single run**: `MasterAnalystAgent.execute_full_investigation()` now runs the three father agents **Memory → Windows → File**, not the structural Windows → File → Memory order the hierarchy diagram (§6.1) lists them in. `File_Analysis_Father_Agent` is the one destination every handoff feeds into, so it has to go last: `scan_and_handoff_suspicious_files()` is called immediately after Memory Analysis completes and again immediately after Windows Forensics completes (never after File Analysis itself — there's nothing downstream of it to hand off to), so anything either of those two flags is already sitting in `ProgramDataList/raw/` by the time File Analysis's Static Triage runs its generic per-category scan — no waiting for a second investigation run.

**Resilience**: each father agent now runs inside `MasterAnalystAgent._run_father()`'s own `try/except` instead of being awaited bare. One father crashing (a bad Volatility plugin, an MCP server that's down, an unhandled exception anywhere in that subtree) is recorded in `father_agent_errors[key]` and logged, but does **not** abort the other two phases, and — critically — does not prevent a final report from being produced at all. Previously, any single father raising took down the entire `execute_full_investigation()` call, and `_compile_executive_intelligence_report()` (the only place `Master_Executive_Intelligence_Report.json` gets written) was never reached; the analyst would see `pipeline_status="ERROR"` and find no report on disk whatsoever. Now `_compile_executive_intelligence_report()` always runs, with whatever subset of `father_agent_reports` did succeed. `web/routes.py`'s `run_wrapper()` reflects this three-way outcome: all fathers succeeded → `COMPLETED` + info log; some succeeded → `COMPLETED` + a `WARN` log naming which fathers failed; every father that was supposed to run failed → `ERROR` (a report with nothing but errors in it isn't a completed investigation).

**The final report is now a real aggregate, not just a nested dump**: `_compile_executive_intelligence_report()` calls `iter_anomalies()` over the *entire* `father_agent_reports` tree to compute `total_anomalies_flagged` and a flattened `critical_findings` list (HIGH/CRITICAL severity, from any agent, at any depth) independently of whatever each father's own `_compile_master_report()` already counted — so nothing is double-counted or missed if one father's internal aggregation differs slightly from another's. It also derives a single `overall_verdict` (`Critical` / `Suspicious` / `Clean`) and includes `cross_agent_handoffs` — the full list of every `HandoffRecord` made during the run — directly in the report, so "what got handed to whom, and why" is part of the durable, downloadable artifact (`/api/investigation/report`), not just something visible in the live log stream while the investigation is running.

**Known limitation**: the handoff mechanism assumes the referenced live-drive path is still reachable from *this* machine at scan time (a Windows Forensics agent flagging `ImagePath` on the box the whole app is running against). If the investigation is analyzing a disconnected/imaged drive, or a staging folder produced by the field collection kit (§9) on a different machine, `src.is_file()` simply returns `False` and the handoff is silently skipped — there is no attempt to reach back out to a remote/offline source. This mirrors how the collector itself already behaves (§5's `PermissionError`/missing-artifact handling) rather than introducing a new failure mode.

---

## 7. Web layer (`app.py` + `web/routes.py` + `web/auth.py` + `web/management_routes.py` + `web/help_routes.py`)

`app.py` is a thin bootstrap: creates the Flask app, ensures `instance/` exists and persists a random 32-byte session-signing key there on first run (so debug-mode auto-reloads don't invalidate logged-in sessions — see §7.2), calls `db.database.init_db()`, starts the retention background checker (`core.retention_scheduler.start_background_checker()`, §7.3), registers routes from all four files below, and runs `app.run(host="0.0.0.0", port=5000, debug=True)`. No blueprints — routes are registered directly.

### 7.1 Routing overview

**97 `@app.route` declarations** across four files — this supersedes any earlier "25 routes" figure, which predates authentication, Findings triage, IOCs, System Management, and the Help Center:

| File | Declarations | Covers |
|---|---|---|
| `web/routes.py` | 60 | Pages (`/`, `/topology`, `/agents`, `/findings`, `/iocs`), status/telemetry polling, investigation lifecycle, HITL, file/folder ingestion, drive+folder browsing, the entire Findings-triage API (dismiss/assign/tag/comment/lock/cluster/enrich/pivot/export — the single largest group), Saved Views, IOCs |
| `web/management_routes.py` | 31 | Everything under `/management` and `/api/management/*` — §7.3 |
| `web/auth.py` | 3 | `/login`, `/logout`, `/change-password` — §7.2 |
| `web/help_routes.py` | 3 | `/help`, `/help/<slug>`, `/api/help/search-index` — §7.5 |

Route groups worth naming individually (all in `web/routes.py` unless noted):

| Purpose | Routes |
|---|---|
| Pages | `GET /`, `/topology`, `/agents`, `/findings`, `/iocs` |
| Status/telemetry (polled every 2s) | `GET /api/status`, `/api/logs`, `/api/topology`, `/api/agents`, `/api/hitl/pending` |
| Investigation lifecycle | `POST /api/investigation/start\|pause\|resume\|stop\|context\|stop-collecting\|continue-collecting`, `GET /api/investigation/report` |
| Setup | `GET /api/drives`, `/api/browse-folder`, `/api/investigations/existing`, `POST /api/investigations/delete` |
| HITL | `POST /api/hitl/approve\|revise` |
| File ingestion | `POST /api/upload/file`, `/api/upload/extract` (two different intake paths — see below) |
| Runtime prompt editing | `POST /api/agents/<agent_name>/prompt` |
| Mode | `POST /api/mode` (SUPERVISED ↔ AUTOMATIC) |
| Findings triage | `GET /api/findings` + ~15 `POST` mutation routes (dismiss/bulk-dismiss/restore/delete/assign/tag/mitre/confidence/cluster/manual/save-as-ioc/export/enrich), comments, audit-log, lock, pivot, timeline-context |
| Saved Views | `GET/POST /api/saved-views`, `DELETE /api/saved-views/<id>` |
| IOCs | `GET /api/iocs`, `DELETE /api/iocs/<id>`, `GET /api/iocs/export?format=csv\|json\|stix\|misp` |

**`GET /api/browse-folder`** backs the in-app folder picker used to "investigate a specific folder instead" on the Launch Hub: an empty `path` returns the available drives as browse roots; otherwise it lists only that path's subdirectories (never files), sorted case-insensitively, plus a `parent` path for "up" navigation (empty string once you're already at a drive root). 400 if the path isn't a directory, 403 on a permission error.

**`POST /api/investigation/start`** is the pipeline launcher and the one route worth understanding in detail: it resolves/creates the staging directory, resets **or restores** the bridge's topology/findings/logs (`reset_state()` for a brand-new staging dir, `load_snapshot(staging_dir)` when resuming an existing one — see §4), and starts a **daemon background thread** (fire-and-forget — the HTTP response returns immediately with `{"success": true, "status": "RUNNING", ...}`). Inside that thread: Phase 1 is a `subprocess.Popen` of the collector (streamed into the log — either `--drive X` or, for a custom-folder investigation, `--folder <path>`), Phase 2 is an in-process `asyncio.run(MasterAnalystAgent().execute_full_investigation(...))` — i.e. collection is out-of-process, analysis is in-process-but-off-thread. **`POST /api/investigation/stop`** is the mirror image: it snapshots the current investigation's state (`bridge.save_snapshot(force=True)`) before clearing `active_investigation_id` and calling `reset_state()`.

**`GET /api/investigation/report`** streams a report JSON (`Master_Executive_Intelligence_Report.json` by default, or one of a fixed allow-list of the other per-tier `*_Report.json` files) out of a given `staging_dir` as a download — used by the "Download Report" button and by the report icon on each row in "Existing Staging Sessions".

**Two different upload routes, two different jobs**: `POST /api/upload/file` (form fields `category`, `staging_dir`, `file`) saves into `<staging_dir>/<category>/raw/`, auto-extracting a `.zip` in place (`infected` password first, then none) — this is the generic "stage evidence into a category" path, used by the Launch Hub's file/memory-dump uploaders and the Active Dashboard's **Add File** button. `POST /api/upload/extract` (form fields `staging_dir`, `file`) is File-Analysis-specific: it saves into `<staging_dir>/Extracted_Files/` and *also* copies every non-zip file (or every file extracted from a zip) into `<staging_dir>/ProgramDataList/raw/` so it's guaranteed to be picked up by `FileAnalysisMaster`'s next scan. Neither route checks `bridge.pipeline_status` — both can be called whether an investigation is idle, running, or paused.

### 7.2 Authentication (`web/auth.py`)

Session-based login using Flask's own signed-cookie session (`flask.session["user_id"]`) — no Flask-Login, no server-side session store. `current_user()` looks up that id against the `User` table (§7.6) on every request. The signing key persists at `instance/.secret_key` (32 random bytes, written once on first run, read on every subsequent start) specifically so `debug=True`'s auto-reload doesn't invalidate everyone's session on every code change.

`_global_auth_gate()`, a `before_request` hook, is where all of this is actually enforced, in order: static files and `/login`/`/logout` bypass everything; anything else with no valid session → 401 (`/api/*`) or a redirect to `/login`; `must_change_password=True` (set on the seeded default admin and on every admin-created/reset account) force-redirects everywhere except `/change-password` itself; any `/management*` or `/api/management/*` path requires `role == "admin"`, else 403; and — the fix noted in `docs/help-center/07-known-limitations.md` — a `viewer` role gets every non-GET request rejected ("Viewer accounts are read-only") except sign-out, changing their own password, and the Findings CSV/STIX/MISP export (a read-only download despite being a POST). There are three roles: `admin`, `analyst`, `viewer`. **Sessions never expire** — no idle timeout is implemented; sign out explicitly on a shared machine.

The default first-run account (`db/database.py`'s `_seed_defaults()`, only when the `users` table is empty) is `admin`/`changeme`, `must_change_password=True`.

### 7.3 System Management (`web/management_routes.py`, `templates/management.html`)

`/management` redirects to `/management/exclusions`; `/management/<tab>` renders one of six tabs, restricted to a fixed `MANAGEMENT_TABS` list. **The entire page and every `/api/management/*` route is admin-only**, enforced by §7.2's global gate, not per-route decorators:

- **Findings Exclusion Rules** — CRUD suppression rules (`core/exclusion_engine.py`) matched by file hash/path/IP/domain/port/process name/PID/PPID/finding category, exact/glob/regex/CIDR, either just hiding a finding behind "Show excluded" or suppressing it outright — with a "test before saving" sample-value tester and a per-rule suppression-count impact view.
- **YARA & Sigma Rules** — YARA: CRUD plus server-side rule-text validation (`core/yara_engine.py`) before save. Sigma: CRUD plus an inline dry-run tester, backed by `core/sigma_engine.py` — a real (partial-spec) evaluator supporting named detection blocks, `|contains`/`|startswith`/`|endswith`/`|re` modifiers, value-list ORs, and `and`/`or`/`not`/parens/`1 of x*`/`all of x*` conditions (safely evaluated via a restricted `ast` walk, not `eval` on untrusted YAML) — genuinely wired into `agents/windows_forensics/evtx_sysmon.py`'s live event evaluation, not just catalogued. Aggregation functions (`count()`, `near`, timeframes) and field-to-field comparisons are explicitly out of scope.
- **Baseline / Golden-Image Whitelisting** — bulk-imports a pasted list of file hashes as `file_hash` exclusion rules.
- **LLM Provider Configuration** — see §3.2; a preset selector switches between Open WebUI (offline default), Google AI Studio/Gemini (explicitly labeled online-only, for testing), and Custom, plus a Test Connection action.
- **Data Lifecycle & Retention** (`core/retention.py`, `core/retention_scheduler.py`) — a storage-usage summary, a per-category policy form (max age, max total size, an "auto-flag violations" checkbox), and a preview-then-explicit-delete sweep. The background checker (§2) only ever logs a warning when a flagged category's violation count changes — **deletion is never automatic**, by deliberate design.
- **Auditability & Access Control** — a Users table (create/patch-role/reset-password/delete; can't delete your own account; new/reset accounts get `must_change_password=True`) and a Global Audit Log merging per-finding `AuditLogEntry` rows with the live `bridge.logs` pipeline event stream.

### 7.4 IOCs (`GET/DELETE /api/iocs`, `templates/iocs.html`)

A locally-tracked IOC library (`LocalIOC` table, §7.6), populated from the Findings page's "Save as IOC" action (derives a value from the finding's filepath/anomaly type, classifies its type, tags it with a TLP marking and the source finding/case). The IOCs page itself is one table plus export buttons for **STIX 2.1**, **MISP**-shaped JSON, and **CSV** — all local-file exports for manual import; there is no live push to a running MISP/STIX/TAXII server, by deliberate offline-deployment design (same framing as §10's SIEM/MISP notes).

### 7.5 Help Center (`core/help_content.py`, `web/help_routes.py`, `docs/help-center/*.md`)

`/help/<slug>` renders one of 7 markdown articles under `docs/help-center/` server-side (`python-markdown` + a post-processing pass for `{#anchor-id}` headings, emoji-callout blockquotes, and figure placeholders), building that article's own on-page TOC and a sidebar where only the active article's headings are expanded. `GET /api/help/search-index` returns every heading across every article as `{title, anchor, tags, excerpt, slug}` for a client-side fuzzy search in `app.js` — no server-side search endpoint. All parsed content is cached in-process (`@lru_cache(maxsize=1)`) after the first request; editing a `.md` file needs a server restart or an explicit `help_content.reload_content()` call to show up.

### 7.6 Database (`db/database.py`, `db/models.py`)

SQLite at `<project_root>/iai.db` (`check_same_thread=False`, so background threads — investigation runs, enrichment jobs — can touch it too), accessed exclusively through `get_session()`, a `@contextmanager` that commits on clean exit and rolls back on exception. `init_db()` (called once from `app.py` at startup) creates every table and seeds the default admin account plus a default `LlmProviderConfig` row if either is missing. This is deliberately separate from the per-investigation state in §4's `bridge` singleton and the `investigation_staging_*/` folders on disk: `bridge`/staging-folders hold *this run's* live pipeline/topology/findings; the database holds everything that has to survive across and independent of any single investigation — accounts, the LLM endpoint config, exclusion/YARA/Sigma rules, retention policy, and every piece of *analyst-added* state layered onto findings (overlay status/tags/assignment, manual findings, comments, audit log, locks, saved views) plus the IOC library. 13 tables in total; see §7.1/§7.3/§7.4 for what most of them back.

---

## 8. Frontend (`static/js/app.js` + templates)

Plain JavaScript, no framework, no build step — `static/js/app.js` is now roughly 3,700 lines in one file. `templates/base.html` provides the nav shell: 5 nav links (Launch & Telemetry, Dynamic Topology, Agent Control Center, Findings, IOCs), the mode toggle, the pending-HITL badge (flickers when its count is nonzero, so an approval waiting on the analyst is hard to miss from any page), and — only for a logged-in user — a dropdown with Help, System Management (admin-only), a light/dark Theme switch, and Sign out. `dashboard.html` is the setup hub (drive/folder/scope pickers, file uploads, launch/resume controls) plus the live-run view (KPI tiles, pause/resume/stop, an **Add File** control, a scrolling log terminal); `topology.html` hosts a full-page hand-rolled **SVG** DAG (not canvas/WebGL, no D3/Cytoscape) using a hardcoded `{agent_id: {x,y}}` layout table and color-coded node state (GRAY/GREEN/YELLOW/BLUE), with pan/zoom and a slide-in inspection drawer; `agents.html` is a sidebar+detail "Agent Control Center" for browsing every node, viewing its raw/AI-analysis JSON, editing its "system prompt", and running the same approve/revise controls; `findings.html` lists every `ForensicAnomaly` aggregated across all agents plus manual findings, most-severe-first, with severity filters, bulk actions, keyboard triage mode, saved views, and a detail drawer (comments/audit-log/lock/pivot/enrich); `iocs.html` (§7.4), `help.html` (§7.5), and `management.html` (§7.3) round out the templates. `login.html`/`change_password.html` are standalone documents with no navbar (there's no logged-in user yet); `forbidden.html` renders on a 403 and does extend `base.html`, since a 403 only ever happens to an already-authenticated user.

Everything is driven by `setInterval(..., 2000)` polling — there are no websockets or server-sent events anywhere in the stack. `onScopeChange()` (Launch Hub scope-selector logic) reads a page-specific element with a null guard, since the same top-level `DOMContentLoaded` handler that calls it is also where the 2-second polling `setInterval` gets registered — an unguarded null-dereference there on a page without that element would throw before the interval is ever set up, silently killing live updates for that entire page (this was a real, since-fixed bug — see `docs/help-center/07-known-limitations.md`).

**Setup Hub list refresh**: `loadExistingInvestigations()` (split out of the old monolithic `loadSetupData()` so a drive-enumeration failure can't silently prevent the investigations list from rendering) is called three ways — once on every page's `DOMContentLoaded`, automatically whenever `fetchStatus()` sees the hub transition from hidden to visible (i.e. right after `POST /api/investigation/stop`'s reload, without needing a second manual reload), and on demand by clicking the "Existing Staging Sessions" heading (`onclick="loadExistingInvestigations(true)"`, `showFeedback=true` surfaces a toast with the count found).

**No-investigation gating**: `topology.html`, `agents.html`, and `findings.html` each wrap their real content in `<div id="page-body">` next to a hidden `<div id="no-investigation-banner">`. `fetchStatus()` toggles the two based on `data.active_investigation_id` on every 2s poll — so visiting one of these pages while `bridge.active_investigation_id` is `None` (nothing chosen yet in the Launch Hub) shows an explicit "No investigation selected" empty state instead of a DAG/list that looks empty by accident.

---

## 9. Field Collection Kit (`field_kit/`, `build_field_kit.py`)

A standalone packaging of **Phase 1 only** (§5), for running evidence collection on a machine that will never have Flask/agents/OpenAI/Python installed — e.g. the actual target machine, air-gapped from the analyst workstation that runs the main app.

- `build_field_kit.py` (project root, dev-only, not part of the running app): invokes PyInstaller (`pip install pyinstaller` on the build machine) to freeze `field_kit/run_kit.py` — which imports `collectors.collector` unmodified — into a single `run_kit.exe` (`--onefile`), then copies `tools/` and `collector_paths.json` alongside it into `dist/IAI_Collection_Kit/` and zips the result. Re-run any time to rebuild from whatever `collectors/collector.py` currently looks like; there is no separate copy of the collector logic to keep in sync.
- `field_kit/run_kit.py`: the standalone entry point bundled into the exe. Thin wrapper around `collectors.collector.run_collection()` — takes `--drive`/`--scope`/`--label` (or prompts interactively via the collector's own `select_drive()`), warns if not running elevated, and computes an output folder named `investigation_staging_<timestamp>_<hostname-or-label>` next to itself. Prints copy-back instructions and blocks on `input()` at the end so the console survives a double-click.
- `field_kit/run_kit.bat`: shipped inside the built kit — warns if not running as Administrator, then launches `run_kit.exe`. `field_kit/rebuild_kit.bat`: **not** shipped in the kit — a dev-only script that installs PyInstaller if missing and reruns `build_field_kit.py`.
- **Frozen-path handling** is the only change `collectors/collector.py` needed: `COLLECTOR_DIR`/`PROJECT_ROOT`/`TOOLS_DIR` now branch on `getattr(sys, "frozen", False)` to anchor off `sys.executable`'s directory instead of `__file__` when running as a PyInstaller exe (otherwise `__file__` resolves inside the frozen bundle, not next to the real `tools/` folder on disk beside the `.exe`). `field_kit/run_kit.py` does the same for `KIT_ROOT`. Everything else is byte-identical to how the main app already runs the collector as a subprocess.
- The kit produces the exact same `investigation_staging_<timestamp>/<category>/{raw,metadata}/`, `hash_manifest.csv`, `execution_report.json` layout as an on-machine collection (§5) — there is no conversion step. The analyst copies the resulting folder into the IAI project root, and it is picked up by `get_existing_investigations()` / "Resume Selected Session" like any other staging folder.
- No dependency on `bridge`, Flask, or any agent code whatsoever — the kit only ever runs Phase 1. Phase 2 (the agent swarm) still only runs inside the main app, against whatever the kit staged.

---

## 10. Known architectural gaps (found during this analysis)

- ~~Hardcoded live API key in `core/base_agent.py`~~ — fixed: agents now read their LLM endpoint/key from `core/llm_config.py`, backed by the Management page's LLM Provider Configuration tab (defaults to a local Open WebUI instance's OpenAI-compatible API, no committed secret). A "Test Connection" action on that same tab sends a real minimal request to verify reachability.
- ~~Google Fonts CDN `@import` in `static/css/style.css`~~ — fixed: removed. This platform is meant to run fully offline; a webfont CDN fetch on every page load is exactly the kind of thing that silently breaks/retries on an air-gapped machine. Falls back to each OS's system UI font instead.
- ~~Prompt overrides don't reach the LLM~~ — fixed: `BaseHITLAgent.__init__` now reads `bridge.prompt_overrides` and uses it in place of the agent's default system prompt if one is set. Saving an override in the "Agent Control Center" UI changes what that agent is told on its *next* run (not retroactively — a run already in progress keeps the prompt it started with).
- **No concurrency between independent agents, except Memory and File Analysis**: every other orchestrator level awaits its children strictly sequentially (`asyncio.gather` never used), so a SUPERVISED run outside those two father agents is fully serialized by human approval clicks. `MemoryAnalysisMaster` (§6.4) and `FileAnalysisMaster` (§6.5) are the two places this was fixed — their independent Stage-2 sub-modules run via `asyncio.gather`, safe there because none of them share mutable state with each other. The other father/sub-master orchestrators were not changed to match; this remains a real limitation for the rest of the tree.
- **`shell=True` subprocess call**: `collectors/collector.py`'s `vssadmin list shadows` call uses `shell=True` with a list of args (an inconsistent/risky subprocess pattern, flagged for hardening).
- **Live state is still in-memory and single-process**: the `bridge` singleton and, in particular, `pending_approvals` (live `asyncio.Event`/loop references) vanish on restart or crash (`debug=True` reloads will also drop mid-run state) and are never persisted. `nodes`/`agent_states`/`logs` now get a best-effort JSON cache per investigation (`dashboard_state.json`, §4), but every write is a bare `try/except: pass` with no corruption check beyond "does `json.load` succeed" — a truncated write (e.g. process killed mid-`json.dump`) silently falls back to a full `reset_state()` on next load, with no error surfaced to the analyst.
- ~~`viewer` role isn't enforced as read-only~~ — fixed: `web/auth.py`'s global gate now rejects any non-GET request from a `viewer` account except sign-out, changing their own password, and the read-only Findings export — see §7.2. What's still genuinely a limitation, not a bug: sessions are server-side (Flask `session` cookie, signed with a key persisted at `instance/.secret_key`) with **no expiry/timeout** — sign out explicitly on a shared machine.
- `collectors/file_extractor.py` and the `investigation_thread` list in `web/routes.py` are both dead code (never invoked / never read after assignment, respectively).
