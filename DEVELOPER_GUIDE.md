# IAI — Developer Guide

This is a map: every file in the repository, what it's for, and what it connects to (what it imports, and who imports it). It is deliberately literal and file-by-file — for the *behavioral* deep-dive (execution order, the HITL cross-thread handshake, why two orchestrators run concurrently, known limitations), read **[ARCHITECTURE.md](ARCHITECTURE.md)** instead; the two documents are meant to be read together, and this one cross-references that one rather than repeating it.

**How to read this doc**: each entry is `path — one-line purpose`, then a short paragraph. "Imports" lists the project-internal modules it depends on (not third-party packages — see `requirements.txt` for those). "Used by" lists what depends on it. If an entry has no "Used by", it's an entry point (run directly, or by an external process like the Flask dev server). Every `__init__.py` under `agents/`, `bridge/`, `collectors/`, `db/`, `web/`, and their subpackages is empty (a package marker only) and isn't given its own entry below — except `core/__init__.py`, which re-exports `ForensicAnomaly`/`AgentAnalysisReport`/`AgentResponse`/`HumanFeedback` (from `models.py`), `locate_staging_directory`/`load_event_context`/`DEFAULT_EVENT_CONTEXT_FILENAME` (from `utils.py`), and `BaseHITLAgent` (from `base_agent.py`) at the package level, though every actual import site in this codebase still spells out the submodule (`from core.models import ...`) rather than relying on this re-export.

---

## Top-level

### `app.py`
Flask application entry point. Creates the `Flask` app, ensures `uploads/` exists (a leftover — see `web/routes.py`'s upload handling, which doesn't actually use this folder), calls `web.routes.register_routes(app)`, and (only when run directly) starts the dev server on `0.0.0.0:5000` with `debug=True`.
**Imports**: `web.routes`. **Used by**: run directly (`python app.py`); also what `field_kit/run_kit.py`'s frozen-path pattern was modeled after, though that file doesn't import this one.

### `requirements.txt`
Pinned minimum versions: `flask`, `werkzeug`, `openai` (used as a Gemini-compatible client, not against OpenAI), `pydantic`, `python-evtx`, `python-registry`, `volatility3` (Memory Analysis), `mcp` (File Analysis). Forensic parser *binaries* (PECmd etc.) are not pip packages — they live in `tools/`.

### `collector_paths.json`
Phase 1 config: 17 categories of Windows artifact glob patterns (e.g. `"Prefetch": ["Windows\\Prefetch\\*.pf"]`), read by `collectors/collector.py`. Malformed/unknown categories are skipped with a warning, never fatal.

### `event_context.txt`
Analyst case-notes free text. Read by `core/utils.py:load_event_context()` and folded into *every* agent's system prompt. Also copied into each investigation's own staging folder so a per-investigation copy persists independently of whatever's currently in this root-level one. Overwritten by the dashboard's "Incident context brief" field and the "quick context injection" control.

### `ioc_list.txt` *(optional, not present by default)*
One IP/domain per line (`#` comments allowed); read by `core/utils.py:load_ioc_list()`, used only by `agents/memory_analysis/network.py`'s deterministic socket correlation. Filename overridable via `IOC_LIST_FILE` env var.

### `build_field_kit.py`
Dev-only packaging script (not imported by the running app). Invokes PyInstaller to freeze `field_kit/run_kit.py` (which imports `collectors.collector` unmodified) into `run_kit.exe`, then copies `tools/` and `collector_paths.json` alongside it into `dist/IAI_Collection_Kit/` and zips the result. Run it any time after changing `collectors/collector.py` to regenerate the field kit.
**Imports**: none project-internal (shells out to `python -m PyInstaller`). **Used by**: run directly, or via `field_kit/rebuild_kit.bat`.

### `.gitignore`
Ignores `__pycache__/`, `*.pyc`, and `dist/` (the field kit build output).

### `README.md`
User-facing: what the project does, install/run, how to use every dashboard page, the field kit, MCP server configuration. Start here if you're a user, not a contributor.

### `ARCHITECTURE.md`
The narrative architecture deep-dive: high-level flow diagram, the bridge's cross-thread HITL handshake, per-subsystem design rationale (§6.1–§6.6), the web layer's route table, the frontend's polling/gating model, the Field Collection Kit, and a running list of known architectural gaps. Read this for *why*, this doc (`DEVELOPER_GUIDE.md`) for *where*.

### `Agents_List_and_Assignments.md`
An early-stage team task-assignment brief (developer initials, "Making it" sketches) predating the actual implementation in several places — treat it as historical planning material, not current documentation. `ARCHITECTURE.md` and this file are what's kept in sync with the code. (An `OVERVIEW.md` with the same problem — describing a pre-dashboard, 7-agent version of the system — was removed for the same reason; see git history if you need it.)

---

## `core/` — foundation shared by every agent

### `core/models.py`
Every Pydantic schema in the system — the data contract every agent's LLM output and every deterministic correlator's output is forced into. Grouped roughly by subsystem:
- Generic: `FileMetadataRecord`, `ForensicAnomaly`, `AgentAnalysisReport` (the schema injected into every LLM system prompt), `AgentResponse` (what an agent hands to the dashboard), `HumanFeedback`.
- Windows Forensics: `RegistryPersistenceEntry`, `CorrelatedSecurityEvent`, `TimelineEvent`, `TimestompingCandidate`, `ExecutionArtifact`.
- Memory Analysis (§6.4): `ProcessAnomaly`, `ProcessTreeFinding`, `MalwareHandoffPayload`, `InjectedMemoryRegion`, `NetworkConnection`, `SocketAnomaly`, `SocketCorrelation`, `MalfindCorrelation`, `MemoryAnalysisReport`.
- File / Malware Analysis (§6.5): `FileHashSet`, `MitreMapping`, `StaticAnalysisReport`, `DecodedStringArtifact`, `DecompiledFunctionFinding`, `ReverseEngineeringModel`, `NetworkArtifact`, `BehavioralIOC`, `StaticDynamicCorrelation`, `DynamicAnalysisReport`, `MalwareAnalysisReport`.
**Imports**: nothing project-internal. **Used by**: every file under `agents/`, `core/base_agent.py`, `core/handoff.py`, `web/routes.py` (indirectly, via `.dict()` output).

### `core/base_agent.py`
`BaseHITLAgent` — the class every one of the ~25 agents subclasses. Provides: the `AsyncOpenAI` client, built from `core/llm_config.py:get_active_llm_config()` (the admin-editable, DB-backed LLM Provider Configuration — see `core/llm_config.py`'s entry below and `ARCHITECTURE.md` §3.2), the forensic safe-file-reading gate (`_inventory_raw_file`, `_looks_like_binary` — executables/known-binary-artifacts are *never* opened as text), `parse_category_artifacts()`/`build_malware_path_payload()`/`build_file_metadata_records()` (the common ways a leaf agent turns a staging category into an LLM payload), `execute_llm_analysis()`, and the two HITL loops every leaf agent ends its `process_task()` with:
- `run_with_hitl(parsed_tool_data)` — calls the LLM, then submits for approval; on REVISE, replays the whole conversation with the analyst's correction folded in and re-calls the LLM.
- `run_automated_with_hitl(parsed_tool_data, deterministic_analysis)` — **never** calls the LLM; submits an already-computed `AgentAnalysisReport`-shaped dict directly for approval. Used by the pure-automation modules in Memory/File Analysis. A REVISE here just logs the analyst's feedback as an annotation (there's no LLM to hand it to) and re-submits the same result.
**Imports**: `core.models`, `core.utils`, and (lazily, inside try/except, so this file never hard-depends on Flask being up) `bridge.hitl_bridge`. **Used by**: every leaf agent file under `agents/`.

### `core/utils.py`
`locate_staging_directory(search_root, explicit_path)` (globs `investigation_staging_*`, returns the newest by mtime if no explicit path given), `load_event_context()` (reads `event_context.txt` from the repo root), `load_ioc_list()` (reads `ioc_list.txt`, used only by Memory Analysis's Network Socket Correlator).
**Imports**: nothing project-internal. **Used by**: `core/base_agent.py` and every orchestrator/leaf agent that needs to resolve a staging directory.

### `core/handoff.py`
Cross-agent file handoff (`ARCHITECTURE.md` §6.6). `iter_anomalies(node)` recursively walks any nested father-agent report for every `anomalies_found` entry, at any depth. `scan_and_handoff_suspicious_files(report_tree, staging_root)` filters those to real, existing, not-already-staged Windows paths of a type File Analysis can parse, copies them into `ProgramDataList/raw/`, and records a `HandoffRecord` in `<staging_root>/handoffs.json`. Called once per father agent by `agents/orchestrators/master_analyst.py`, not by individual leaf agents.
**Imports**: nothing project-internal (lazily imports `bridge.hitl_bridge` for logging only). **Used by**: `agents/orchestrators/master_analyst.py`.

### `core/llm_config.py`
`get_active_llm_config()` — reads the singleton `LlmProviderConfig` DB row (`db/models.py`, id=1) and returns `{provider_label, base_url, api_key, model_name, context_limit}`, the values every agent's `AsyncOpenAI` client is built from. Falls back to a hardcoded Open WebUI-shaped dict only if the DB row is missing entirely (not a live-key fallback for normal operation — see `ARCHITECTURE.md` §3.2). This is what the old hardcoded-Gemini-key setup was replaced with; editable from **System Management → LLM Provider Configuration** (`web/management_routes.py`).
**Imports**: `db.database`, `db.models`. **Used by**: `core/base_agent.py` (every agent), the Findings-page "Deep Analyze with Agent" enrichment helper.

### `core/help_content.py`
Renders `docs/help-center/*.md` server-side for the in-app Help Center. `python-markdown` (`attr_list`, `fenced_code`, `tables`, `sane_lists` extensions) plus a post-processing pass for a custom `{#anchor-id}` heading syntax, emoji-callout blockquotes (`> ℹ️`/`> ⚠️`/`> ✅`/`> 🔧`), and figure placeholders. `_load_all()` is `@lru_cache(maxsize=1)` — parses every article once per process; `reload_content()` exposes a manual `cache_clear()` for picking up an edited `.md` file without a restart.
**Imports**: nothing project-internal. **Used by**: `web/help_routes.py`.

### `core/retention_scheduler.py`
`start_background_checker(project_root, interval_seconds=600)` — a daemon thread, started once from `app.py`, that every 10 minutes calls `check_policies_once()`: for every `RetentionPolicy` with `auto_archive_enabled=True`, runs `core/retention.py`'s `preview_sweep()` and logs a `WARN` via `bridge.log_event()` the moment a category's violation count changes. **Never deletes anything itself** — deletion stays a manual preview-then-confirm action on the Management page's Retention tab.
**Imports**: `core.retention`, lazily `bridge.hitl_bridge`. **Used by**: `app.py` only.

### `core/retention.py`
Storage-usage scanning (per-category size/last-modified across every `investigation_staging_*/`) and the preview/execute sweep logic behind the Management page's Retention tab and `core/retention_scheduler.py`'s background check. Deletion is always an explicit, previewed, admin-confirmed action.
**Imports**: nothing project-internal. **Used by**: `web/management_routes.py`, `core/retention_scheduler.py`.

### `core/sigma_engine.py`
A real, partial-spec Sigma rule evaluator (not just storage) — `CompiledSigmaRule` supports named detection blocks (dict = AND, list-of-dicts = OR), field modifiers `|contains`/`|startswith`/`|endswith`/`|re`, value-list OR, and a `condition` string with `and`/`or`/`not`/parens/`1 of x*`/`all of x*`, evaluated via a restricted `ast` walk rather than `eval` on untrusted YAML. Explicitly not supported: aggregation functions (`count()`, `near`, timeframes) or field-to-field comparisons. Rules live in `db.models.SigmaRule`; compiled rules are cached in-memory and invalidated on any CRUD.
**Imports**: `db.database`, `db.models`. **Used by**: `web/management_routes.py` (CRUD + dry-run test endpoint), `agents/windows_forensics/evtx_sysmon.py` (actual live evaluation against extracted event fields — this is genuinely wired into detection, not just catalogued).

### `core/yara_engine.py`
Validates YARA rule text (`validate_rule_text()`) before a rule is saved from the Management page's YARA tab, so a syntactically invalid rule never makes it into `db.models.YaraRule`.
**Imports**: nothing project-internal. **Used by**: `web/management_routes.py`.

### `core/exclusion_engine.py`
Findings-suppression rule matching behind the Management page's Exclusion Rules tab: file hash/path/IP/domain/port/process name/PID/PPID/finding-category rules, each exact/glob/regex/CIDR, either just hiding a finding behind Findings' "Show excluded" toggle or suppressing it outright. Backs the rule tester and per-rule suppression-count "impact" view too.
**Imports**: `db.models`. **Used by**: `web/management_routes.py`, `web/routes.py` (applied when building the Findings list).

### `core/finding_utils.py`
Shared helpers used by the Findings and IOCs pages — e.g. `classify_ioc_type()`, used when a finding is saved as an IOC (`POST /api/findings/save-as-ioc`) to decide whether a derived value is a hash, IP, domain, etc.
**Imports**: nothing project-internal. **Used by**: `web/routes.py`.

---

## `bridge/` — the state hub

### `bridge/hitl_bridge.py`
`WebHITLBridge` (instantiated once as the module-level `bridge` singleton) — the nervous system connecting the HTTP layer, the background investigation thread, and the async agent swarm. Holds: `execution_mode`, `pipeline_status`, `is_paused`/`pause_event`, the 27-node topology `nodes` dict (`_init_topology_nodes()`), `pending_approvals` (live `asyncio.Event`/loop refs — see the cross-thread handshake in `ARCHITECTURE.md` §4), `agent_states` (latest `AgentResponse` per agent), `prompt_overrides` (display-only, not actually read by any agent — see `ARCHITECTURE.md` §10), and `logs` (a 2000-entry ring buffer).

Key methods: `register_hitl_pause()`/`submit_hitl_decision()` (the approve/revise handshake), `update_node_state()`, `log_event()`, `get_topology()`, `get_all_findings()`, `get_existing_investigations()`, `get_available_drives()`, `set_pause_state()`, and the per-investigation persistence trio `reset_state()`/`save_snapshot()`/`load_snapshot()` (writes/reads `<staging_dir>/dashboard_state.json` so switching investigations doesn't bleed state — see `ARCHITECTURE.md` §4).
**Imports**: nothing project-internal. **Used by**: `web/routes.py` (every route), `core/base_agent.py` (every agent, via `send_to_dashboard_and_wait`/`wait_if_paused`), `core/handoff.py`, and most orchestrators (for logging).

---

## `db/` — persistence for everything outside a single investigation run

Deliberately separate from `bridge`/`investigation_staging_*/`: those hold *this run's* live pipeline state; `db/` holds accounts, platform config, detection rules, and every piece of analyst-added state on findings — things that must survive across and independent of any one investigation.

### `db/database.py`
SQLite engine at `<project_root>/iai.db` (`check_same_thread=False`, so background threads — investigation runs, enrichment jobs — can use it too). `init_db()` (called once from `app.py`) creates every table then calls `_seed_defaults()` — inserts the default `admin`/`changeme` user (`must_change_password=True`) if the `users` table is empty, and a default `LlmProviderConfig` row (id=1) if missing. `get_session()` is a `@contextmanager` — commits on clean exit, rolls back and re-raises on exception, always closes; this is the only way any route touches the database.
**Imports**: `db.models` (inside `init_db()`, so model classes register on `Base` before `create_all()`). **Used by**: `web/routes.py`, `web/management_routes.py`, `web/auth.py`, `core/llm_config.py`, `core/sigma_engine.py`, `core/exclusion_engine.py`.

### `db/models.py`
13 SQLAlchemy model classes: `FindingOverlay` (mutable analyst state layered onto agent-derived findings — status/assignment/tags/MITRE techniques/confidence/cluster/dismissal; agent findings themselves are recomputed from `bridge.agent_states` per request and never persisted, so this table is their only durable state), `ManualFinding`, `LocalIOC`, `AuditLogEntry`, `EnrichmentJob`, `SavedView`, `FindingLock` (poll-based presence lock, `is_stale()` after 25s with no heartbeat), `FindingComment`, `ExclusionRule`, `User` (`admin`/`analyst`/`viewer` role as a plain string column), `LlmProviderConfig` (singleton row, id=1), `YaraRule`, `SigmaRule`, `RetentionPolicy`.
**Imports**: nothing project-internal. **Used by**: `db/database.py`, `web/routes.py`, `web/management_routes.py`, `web/auth.py`, `core/llm_config.py`, `core/sigma_engine.py`, `core/exclusion_engine.py`.

---

## `collectors/` — Phase 1, evidence acquisition

### `collectors/collector.py`
Runs as a **separate subprocess** (`python -m collectors.collector --drive X --staging <dir> --scope <ALL|WINDOWS|FILE|MEMORY>`, or `--folder <path>` instead of `--drive` — see below), never imported in-process by the web app (only ever `Popen`'d) — this isolates a collector crash from Flask and lets its stdout stream live into the dashboard log. Reads `collector_paths.json`, creates `<Category>/{raw,metadata}/` per category, SHA-256-hashes every file before *and* after copy (`hash_manifest.csv`), and runs the Eric Zimmerman/RegRipper/Sysinternals tools in `tools/` against the copied raw files to populate `metadata/`. `run_collection()` is the programmatic entry point both the CLI (`if __name__ == "__main__"`) and `field_kit/run_kit.py` call for a normal drive sweep. `run_folder_collection(folder_path, staging_root)` is the other entry point — ingests one arbitrary folder (any depth, any drive) instead: no drive-root artifact categories apply, it just recursively hashes/copies everything under that folder into `ProgramDataList/raw/` via the same `copy_matched_path()` helper `collect_standard_artifacts()` uses, for File/Malware analysis. This backs the Launch Hub's in-app folder picker (`GET /api/browse-folder` in `web/routes.py`) for when the analyst wants one specific folder analyzed rather than a whole drive. Path resolution (`PROJECT_ROOT`/`TOOLS_DIR`) branches on `sys.frozen` so the exact same module works unmodified when PyInstaller-frozen into the field kit — see `ARCHITECTURE.md` §9.
**Imports**: nothing project-internal. **Used by**: `web/routes.py` (via `subprocess.Popen(["python", "-m", "collectors.collector", ...])`), `field_kit/run_kit.py` (direct import, `from collectors.collector import run_collection, select_drive`).

### `collectors/file_extractor.py`
A small standalone hashing/copy CLI utility. **Dead code** — not called anywhere in the running app; `/api/upload/extract` in `web/routes.py` reimplements its own zip-extraction logic inline instead. Kept for reference/potential reuse, flagged in `ARCHITECTURE.md` §10.

---

## `agents/orchestrators/` — the father/sub-master coordinators

### `agents/orchestrators/master_analyst.py`
`MasterAnalystAgent` — the top of the whole agent tree. `execute_full_investigation(staging_dir, scope)` runs the three father agents in **Memory → Windows → File** order (File runs last because it's the one destination every cross-agent handoff feeds into — `ARCHITECTURE.md` §6.6), each inside its own try/except via `_run_father()` so one crashing doesn't abort the others or prevent the final report. Calls `core.handoff.scan_and_handoff_suspicious_files()` after Memory and after Windows complete. `_compile_executive_intelligence_report()` always runs regardless of per-father failures, aggregating `total_anomalies_flagged`/`critical_findings`/`overall_verdict` across the *entire* nested report tree via `core.handoff.iter_anomalies()`, and writes `Master_Executive_Intelligence_Report.json`.
**Imports**: `core.utils`, `core.handoff`, `agents.orchestrators.{windows_forensics_master, file_analysis_master, memory_analysis_master}`. **Used by**: `web/routes.py`'s `run_wrapper()` (Phase 2 entry point).

### `agents/orchestrators/windows_forensics_master.py`
`WindowsForensicsMaster` — awaits its two sub-masters (`execution_artifacts_master`, `malware_path_master`) then three direct leaf agents (EVTX/Sysmon, Registry Miner, Timeline Anomaly), strictly sequentially. Writes `Windows_Forensics_Master_Report.json`.
**Imports**: `core.utils`, `agents.orchestrators.{execution_artifacts_master, malware_path_master}`, `agents.windows_forensics.{evtx_sysmon, registry_miner, timeline_anomaly}`. **Used by**: `master_analyst.py`.

### `agents/orchestrators/execution_artifacts_master.py`
`ArtifactsAnalyzerMaster` — awaits Prefetch/Amcache/Shimcache sequentially, then `_cross_reference_sources()` diffs binary names across the three sources (e.g. an Amcache entry with no matching Prefetch run — Prefetch's ~1024-slot rolling window ages out or gets cleared). Writes `Execution_Artifacts_Report.json`.
**Imports**: `core.utils`, `agents.windows_forensics.{prefetch, amcache, shimcache}`. **Used by**: `windows_forensics_master.py`.

### `agents/orchestrators/malware_path_master.py`
`CommonMalwarePathsMaster` — awaits 8 leaf agents (Temp, Downloads, AppData/Public, ProgramData, Scheduled Tasks, Services, Drivers, Autoruns) sequentially. Writes `Master_Forensic_Report.json`.
**Imports**: `core.utils`, `agents.malware_paths.*` (all 8 leaf modules). **Used by**: `windows_forensics_master.py`.

### `agents/orchestrators/memory_analysis_master.py`
`MemoryAnalysisMaster` — the concurrent exception (`ARCHITECTURE.md` §6.4). Stage 1: `Malfind_Correlator` (blocking, deterministic). Stage 2 (`asyncio.gather(..., return_exceptions=True)`): Injected Code Analyzer (consumes Stage 1's ranked candidates) + Process & Thread Mapper + Network Socket Correlator, run concurrently since none share mutable state. Compiles a typed `MemoryAnalysisReport` and writes `Memory_Analysis_Master_Report.json`.
**Imports**: `core.models`, `core.utils`, `agents.memory_analysis.{volatility_runner, malfind, malfind_correlator, network, pstree}`. **Used by**: `master_analyst.py`.

### `agents/orchestrators/file_analysis_master.py`
`FileAnalysisMaster` — the other concurrent exception (`ARCHITECTURE.md` §6.5). Stage 1: Static Triage (blocking, pure automation). Conditional gate: if every triaged binary is Clean, Reverse Engineering *and* Dynamic Sandbox are both skipped (`reverse_engineering_skipped_reason`/`dynamic_skipped_reason` explain why). Otherwise Stage 2 runs both concurrently — Dynamic Sandbox takes its `static_capabilities` argument from Stage 1 directly, not from Reverse Engineering, so there's no dependency forcing serialization. Sandboxes only the single highest-severity triaged binary. Compiles a typed `MalwareAnalysisReport` and writes `File_Analysis_Master_Report.json`.
**Imports**: `core.models`, `core.utils`, `agents.file_analysis.{dynamic_sandbox, pestudio_analysis, reverse_engineering}`. **Used by**: `master_analyst.py`.

---

## `agents/windows_forensics/` — Windows Forensics Father Agent's direct children

### `agents/windows_forensics/execution_artifacts_common.py`
Shared, non-agent module: masquerade/typo-squat detection (`KNOWN_SYSTEM_BINARIES` canonical-path table) and defensive CSV column resolution, reused identically by Prefetch/Amcache/Shimcache so "is this binary running from where it should be" is defined once, not three times slightly differently.
**Imports**: `core.models` (`ExecutionArtifact`). **Used by**: `prefetch.py`, `amcache.py`, `shimcache.py`.

### `agents/windows_forensics/prefetch.py` / `amcache.py` / `shimcache.py`
`PrefetchAgent` (`Prefetch_Analyzer`) / `AmcacheAgent` (`Amcache_Analyzer`) / `ShimcacheAgent` (`Shimcache_Analyzer`) — each parses its respective Eric Zimmerman CSV output (via `execution_artifacts_common.py`'s shared parser) into `ExecutionArtifact` records and hands them to the LLM to flag masquerading/anomalous execution evidence. Automation → LLM pattern.
**Imports**: `core.base_agent`, `core.utils`, `execution_artifacts_common`. **Used by**: `execution_artifacts_master.py`.

### `agents/windows_forensics/evtx_sysmon.py`
`EvtxSysmonAgent` (`EVTX_Sysmon_Correlator`) — parses Windows Event Logs/Sysmon via `python-evtx`, pre-filters OS noise, and hands high-value events (process creation, network connections, logon events) to the LLM to chain into attack sequences.
**Imports**: `core.base_agent`, `core.utils`. **Used by**: `windows_forensics_master.py` (direct child, not via a sub-master).

### `agents/windows_forensics/registry_miner.py`
`RegistryMinerAgent` (`Registry_Hive_Miner`) — extracts persistence-relevant registry values (Run keys, services, etc.) from copied SYSTEM/SOFTWARE/NTUSER hives via `python-registry`, hybrid automation+LLM.
**Imports**: `core.base_agent`, `core.utils`, `core.models` (`RegistryPersistenceEntry`). **Used by**: `windows_forensics_master.py`.

### `agents/windows_forensics/timeline_anomaly.py`
`TimelineAnomalyAgent` (`Timeline_Anomaly_Detector`) — builds a unified super-timeline from MFT/EVTX/file-inventory sources (`TimelineEvent`), flags `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp discrepancies (`TimestompingCandidate` — the classic timestomping tell).
**Imports**: `core.base_agent`, `core.utils`, `core.models`. **Used by**: `windows_forensics_master.py`.

---

## `agents/malware_paths/` — the 8 "common drop location" agents

All eight follow the same automation→LLM pattern (`build_malware_path_payload()` or `parse_category_artifacts()` → `run_with_hitl()`); they differ only in which staging category they read and what their system prompt asks the LLM to prioritize.

| File | Class | `agent_name` | Category read |
|---|---|---|---|
| `temp_folder.py` | `TempFolderAgent` | `Temp_Folder_Analyzer` | `TempFolder` |
| `downloads_folder.py` | `DownloadsFolderAgent` | `Downloads_Folder_Analyzer` | `Downloads` |
| `appdata_paths.py` | `AppDataPathsAgent` | `AppData_Public_Paths_Analyzer` | `CommonMalwarePaths` |
| `program_data.py` | `ProgramDataAgent` | `ProgramData_Analyzer` | `ProgramDataList` (listing only, no raw binaries — see `ARCHITECTURE.md` §6.6) |
| `scheduled_tasks.py` | `ScheduledTasksAgent` | `Scheduled_Tasks_Analyzer` | `SysinternalsAutoruns`, filtered to `"task"` rows |
| `services.py` | `ServicesAgent` | `Services_Analyzer` | `SysinternalsAutoruns`, filtered to `"service"` rows |
| `drivers.py` | `DriversAgent` | `Drivers_Analyzer` | `SysinternalsAutoruns`, filtered to `"driver"` rows |
| `autoruns.py` | `AutorunsAgent` | `Autoruns_Analyzer` | `SysinternalsAutoruns`, unfiltered |

**Imports** (all eight): `core.base_agent`, `core.utils`. **Used by**: `agents/orchestrators/malware_path_master.py`.

---

## `agents/memory_analysis/` — Memory Analysis Father Agent's children

See `ARCHITECTURE.md` §6.4 for the full design rationale; this is the file-level map.

### `agents/memory_analysis/volatility_runner.py`
The shared Volatility3 automation layer every sub-module calls into — never called directly by anything outside this package. `run_plugin(image_path, plugin, args, output_dir)` shells out to the `vol` CLI with `-r json` (or `python -m volatility3.cli` if only the package is on `PATH`), degrading to `[]` + a logged warning on any failure. `locate_memory_image(staging_root)` finds the analyst-uploaded dump in `MemoryDumps/raw/`. `find_malfind_dump()`, `sha256_of_file()`/`md5_of_file()`, `sniff_pe_header()` support the Injected Code Analyzer's handoff. Backend is swappable via `set_backend()` (a `VolatilityBackend` subclass) for testing.
**Imports**: nothing project-internal (lazily imports `bridge.hitl_bridge` for warning logs). **Used by**: `pstree.py`, `network.py`, `malfind.py`, `malfind_correlator.py`, `memory_analysis_master.py`.

### `agents/memory_analysis/malfind_correlator.py`
`MalfindCorrelatorAgent` (`Malfind_Correlator`) — pure automation, **zero LLM tokens**. `correlate()` (a pure, independently-unit-testable function) scores every `windows.malfind.Malfind` hit against `windows.thrdscan.ThrdScan`/`windows.handles.Handles`/`windows.dlllist.DllList` with a fixed point table → confidence score → severity. Routed through `run_automated_with_hitl()`.
**Imports**: `core.base_agent`, `core.models` (`MalfindCorrelation`), `core.utils`, `volatility_runner`. **Used by**: `malfind.py` (as a fallback when run standalone), `memory_analysis_master.py`.

### `agents/memory_analysis/malfind.py`
`InjectedCodeAnalyzerAgent` (`MalFind_Injected_Code_Analyzer`) — hybrid. Does **not** re-run malfind; consumes `malfind_correlator`'s ranked list (passed in by the Father Agent, or re-derived if run standalone), spends an LLM call only on candidates scoring ≥25. On analyst approval, builds a `MalwareHandoffPayload` (hash + PE-header sniff of the already-dumped VAD payload) and copies it into `ProgramDataList/raw/` for File Analysis to pick up.
**Imports**: `core.base_agent`, `core.models`, `core.utils`, `volatility_runner`, `malfind_correlator` (for `AGENT_NAME` and the standalone fallback). **Used by**: `memory_analysis_master.py`.

### `agents/memory_analysis/pstree.py`
`ProcessTreeMapperAgent` (`PsTree_Process_Mapper`) — automation → LLM. Runs pslist/pstree/psxview, deterministically computes hidden/unlinked PIDs and parent/child anomalies against a fixed table (`_EXPECTED_PARENTS`) before handing the LLM the pre-flagged candidates plus anything the table has no entry for.
**Imports**: `core.base_agent`, `core.utils`, `volatility_runner`. **Used by**: `memory_analysis_master.py`.

### `agents/memory_analysis/network.py`
`NetworkSocketCorrelatorAgent` (`Network_Socket_Correlator`) — pure automation, zero LLM tokens. `correlate_sockets()` (pure function) flags netscan rows via a fixed rule set (non-networking process making outbound connections, C2-associated ports, high-port listeners, optional IOC-list match via `core.utils.load_ioc_list()`). Routed through `run_automated_with_hitl()`.
**Imports**: `core.base_agent`, `core.models` (`NetworkConnection`/`SocketAnomaly`/`SocketCorrelation`), `core.utils`, `volatility_runner`. **Used by**: `memory_analysis_master.py`.

---

## `agents/file_analysis/` — File / Malware Analysis Father Agent's children

See `ARCHITECTURE.md` §6.5 for the full design rationale.

### `agents/file_analysis/mcp_client.py`
The shared MCP (Model Context Protocol) automation layer — the File Analysis equivalent of `volatility_runner.py`. `MCPServerSpec.from_env()` resolves each of `GHIDRA_MCP`/`CAPA_MCP`/`CUCKOO_MCP` from env vars (command/args for stdio, or a `*_URL` for SSE). `call_tool(server, tool_name, arguments)` talks the real MCP wire protocol via the official `mcp` SDK (lazily imported so every dependent module still imports fine without `pip install mcp`), degrading to `{}` + a logged warning on any failure. Backend swappable via `set_backend()`.
**Imports**: nothing project-internal (lazily imports `bridge.hitl_bridge`). **Used by**: `pestudio_analysis.py`, `reverse_engineering.py`, `dynamic_sandbox.py`.

### `agents/file_analysis/pestudio_analysis.py`
`StaticTriageAndCapabilityMapperAgent` (`PeStudio_Static_Triage_Analyzer`) — pure automation, zero LLM tokens. Contains the project's hand-rolled PE parser (`_parse_pe`, PE header/section/import/export walk, per-section Shannon entropy, packer-name/RWX-section detection, suspicious-API-category table) plus a lightweight ELF parser (`_parse_elf`, header + `.dynsym`/`.dynstr` walk). Computes `imphash` (from the PE import table, no `pefile` dependency), ELF `typehash`, and (best-effort) `ssdeep`. Calls `CAPA_MCP` per binary for `MitreMapping`s. Every binary becomes one `StaticAnalysisReport`; routed through `run_automated_with_hitl()`.
**Imports**: `core.base_agent`, `core.models` (`FileHashSet`/`MitreMapping`/`StaticAnalysisReport`), `core.utils`, `mcp_client`. **Used by**: `file_analysis_master.py`.

### `agents/file_analysis/reverse_engineering.py`
`ReverseEngineeringAndStringAnalyzerAgent` (`Ghidra_Reverse_Engineering_Agent`) — automation → LLM. Calls `GHIDRA_MCP`'s `analyze_binary` for headless decompilation, filters to functions worth an LLM call (`_is_high_priority()`: complexity ≥ 8 and not a compiler-generated/CRT-init name). Also runs string extraction/categorization (absorbed from the now-deleted `strings_analysis.py`) plus two automated decode routines a plain `strings` pass can't produce: `find_xor_encoded_strings()` (brute-forces all 256 single-byte XOR keys over a bounded window, with padding-run trimming so repeated-byte padding doesn't bridge into a real decoded string) and `decode_base64_candidates()` (including a `config-blob` classification for `KEY=VALUE`-shaped decoded C2 configs). The LLM's system prompt instructs it to echo back each function's `name@address` as its `anomalies_found[].filepath` join-key.
**Imports**: `core.base_agent`, `core.models` (`DecodedStringArtifact`/`DecompiledFunctionFinding`), `core.utils`, `mcp_client`. **Used by**: `file_analysis_master.py`.

### `agents/file_analysis/dynamic_sandbox.py`
`DynamicSandboxCorrelatorAgent` (`Dynamic_Sandbox_Correlator`) — hybrid. Calls `CUCKOO_MCP`'s `submit_and_wait` tool, normalizes the behavioral report into `BehavioralIOC`/`NetworkArtifact` records, then `correlate_static_and_dynamic()` (pure function) deterministically cross-references the Static Triage module's CAPA capabilities against what actually happened at runtime — reporting an *uncorroborated* capability as a finding in its own right, never silently dropping it. `compute_risk_score()` is a fixed point table → severity. The LLM call only explains gaps and flags anomalies the deterministic rules don't cover.
**Imports**: `core.base_agent`, `core.models` (`BehavioralIOC`/`MitreMapping`/`NetworkArtifact`/`StaticDynamicCorrelation`), `core.utils`, `mcp_client`. **Used by**: `file_analysis_master.py`.

---

## `web/` — the HTTP layer

**97 `@app.route` declarations across these four files** — supersedes any older "25 routes" figure, which predates authentication, Findings triage, IOCs, System Management, and the Help Center. See `ARCHITECTURE.md` §7.1 for the full grouped route table.

### `web/routes.py`
60 routes: pages (`/`, `/topology`, `/agents`, `/findings`, `/iocs`), `/api/status|logs|topology|agents|hitl/pending`, investigation lifecycle (start/pause/resume/stop/context/stop-collecting/continue-collecting/report), HITL approve/revise, file uploads (`/api/upload/file`, `/api/upload/extract` — two different intake paths, see `ARCHITECTURE.md` §7.1), drive listing + the in-app folder browser (`GET /api/browse-folder`), existing-investigation listing/deletion, per-agent prompt override, and the entire Findings-triage + Saved Views + IOCs API (by far the largest single group — dismiss/bulk-dismiss/restore/delete/assign/tag/mitre/confidence/cluster/manual/save-as-ioc/export/enrich/comments/audit-log/lock/pivot/timeline-context). The one route worth reading closely is `POST /api/investigation/start`'s `run_wrapper()` — the daemon background thread that runs Phase 1 (`subprocess.Popen` of the collector, either `--drive` or `--folder`) then Phase 2 (`asyncio.run(MasterAnalystAgent().execute_full_investigation(...))`), and reports `COMPLETED`/`ERROR` based on `master_analyst.py`'s `father_agent_errors` field (full success / partial success / total failure — see `ARCHITECTURE.md` §6.6).
**Imports**: `bridge.hitl_bridge`, `agents.orchestrators.master_analyst` (lazily, inside the route handler, to avoid a slow import at Flask startup), `collectors.collector` (only via subprocess, not import), `core.exclusion_engine`, `core.finding_utils`, `db.database`, `db.models`. **Used by**: `app.py`.

### `web/auth.py`
3 routes (`/login`, `/logout`, `/change-password`) plus the actual enforcement mechanism for all of them: `_global_auth_gate()`, a `before_request` hook registered by `register_auth(app)`. Session-based login via Flask's own signed-cookie `session["user_id"]` (no Flask-Login, no server-side session store) — `current_user()` looks that id up against `db.models.User` on every request. The gate: static files and `/login`/`/logout` bypass everything; no session → 401 (`/api/*`) or redirect to `/login`; `must_change_password` force-redirects everywhere except `/change-password`; any `/management*`/`/api/management/*` path requires `role == "admin"`; a `viewer` role gets every non-GET request rejected except sign-out/change-password/the Findings export. `role_required(*roles)` is a decorator available for stricter per-route checks but isn't currently used by any route — the coarser checks above (admin-boundary + viewer-read-only) are done globally instead. See `ARCHITECTURE.md` §7.2.
**Imports**: `db.database`, `db.models`. **Used by**: `app.py` (`register_auth(app)`), and implicitly gates every other route file since it's a `before_request` hook.

### `web/management_routes.py`
31 routes, all under `/management` and `/api/management/*`, all admin-only (enforced by `web/auth.py`'s global gate, not per-route). Six tabs: Findings Exclusion Rules, YARA & Sigma Rules, Baseline/Golden-Image Whitelisting, LLM Provider Configuration (+ Test Connection), Data Lifecycle & Retention (storage summary, per-category policy, preview-then-execute sweep), and Auditability & Access Control (user CRUD, global audit log). See `ARCHITECTURE.md` §7.3 for what each tab actually does.
**Imports**: `db.database`, `db.models`, `core.exclusion_engine`, `core.yara_engine`, `core.sigma_engine`, `core.retention`, `bridge.hitl_bridge` (for the merged audit log). **Used by**: `app.py`.

### `web/help_routes.py`
3 routes: `/help` (redirects to the first article), `/help/<slug>` (renders one article + its own TOC via `core.help_content`), `GET /api/help/search-index` (every heading across every article, for client-side fuzzy search in `app.js`). See `ARCHITECTURE.md` §7.5.
**Imports**: `core.help_content`. **Used by**: `app.py`.

---

## `static/` and `templates/` — the frontend

### `static/js/app.js`
The entire dashboard client (no build step, no framework) — roughly 3,700 lines in one file now. `setInterval(..., 2000)` polls the status/logs/topology/agents/findings/HITL-pending endpoints. Major sections, in file order: global state + trusted inline SVG icon fragments; toast/confirm-dialog helpers (replace native `alert()`/`confirm()`); navbar user-menu + theme (light/dark) toggle; `fetchStatus()` (toggles Setup Hub vs Active Dashboard, the pending-HITL flicker, and the "no investigation selected" banner on Topology/Agents/Findings); `loadSetupData()`/`loadExistingInvestigations()` (the Launch Hub's session list); the folder browser (the in-app "Explorer" backing `GET /api/browse-folder`, for the "investigate a specific folder instead" picker); pipeline steering controls; `renderTopologyCanvas()` (the hand-rolled SVG DAG with a hardcoded `{agent_id: {x,y}}` layout table — this is where a new agent node needs a position added) + pan/zoom/maximize + node modal drawer; Agent Control Center; the Findings triage view (filters, clustering, selection/bulk actions, keyboard triage mode, saved views, manual findings, save-as-IOC, export, the finding detail drawer — its single largest section); the IOC Library page; **System Management** (by far the largest section, ~860 lines — exclusions, YARA rules, Sigma rules, baseline import, LLM config + preset detection, retention, users, global audit log); and the Help Center's client-side fuzzy search/tag-filter/scroll-spy logic, at the end of the file.

Every place that renders agent/LLM-originated text (raw parsed tool data, AI analysis JSON, finding fields) does so via `textContent`, never `innerHTML` — worth preserving when adding new render paths, since that data's origin is untrusted from the browser's perspective.

### `static/css/style.css`
All styling; no CSS framework. `.empty-state-page` is the "no investigation selected" placeholder style. Theme (light/dark) is `data-theme` on `<html>`, toggled by `app.js`'s `setTheme()` and persisted in `localStorage`; almost every color is a CSS variable redefined under `html[data-theme="light"]`, **except** a deliberate set of fixed `--console-*` variables used only by the terminal-style panels (log stream, code viewers) that intentionally keep a dark background in both themes — those panels' text colors must use `--console-*`, not the theme-following `--text-*`/`--brand`/etc. variables, or they go unreadable in light mode (a real bug that shipped once — see `docs/help-center/07-known-limitations.md`).

### `templates/base.html`
The nav shell every page extends (except `login.html`/`change_password.html` — see below): brand, 5 nav links (Launch & Telemetry / Dynamic Topology / Agent Control Center / Findings / IOCs), the mode toggle, the pending-HITL badge, and — only when `current_user` is set — a dropdown with Help, System Management (admin-only), a Theme toggle, and Sign out. Also hosts the toast stack, confirm-dialog overlay, and folder-browser overlay containers, and the `<script>` tag loading `app.js`.

### `templates/dashboard.html`
Extends `base.html`. Contains both the Setup Hub (new-investigation form — drive picker, the folder-browser "Browse…" alternative, scope, uploads — + Existing Staging Sessions list) and the Active Dashboard (KPI tiles, pause/resume/stop controls, quick context injection, the **Add File** control, log terminal) — `app.js` toggles which is visible based on `pipeline_status`.

### `templates/topology.html`, `templates/agents.html`, `templates/findings.html`, `templates/iocs.html`
Each extends `base.html`; `topology.html`/`agents.html`/`findings.html` additionally wrap their real content in `<div id="page-body">` next to a `<div id="no-investigation-banner">` (toggled by `fetchStatus()`), since they only make sense once an investigation is selected — `iocs.html` doesn't need that gate, since the IOC library persists across investigations. Otherwise page-specific: the SVG canvas + HITL inspection drawer (`topology.html`), the agent sidebar + detail/prompt-override panel (`agents.html`), the severity filter chips + findings list + detail drawer (`findings.html`), a single IOC table + STIX/MISP/CSV export buttons (`iocs.html`).

### `templates/help.html`, `templates/management.html`
Extend `base.html`. `help.html` renders one Help Center article (`/help/<slug>`) with its own on-page TOC and a sidebar where only the active article's headings expand. `management.html` renders one System Management tab (`/management/<tab>`) — admin-only, see `ARCHITECTURE.md` §7.3.

### `templates/login.html`, `templates/change_password.html`
Standalone full HTML documents — **do not** extend `base.html` (there's no logged-in user yet, so no navbar to render).

### `templates/forbidden.html`
Extends `base.html` (a 403 only ever happens to an already-authenticated user, so the navbar still makes sense). Rendered by `web/auth.py`'s `_forbidden_response()` for the admin-boundary and viewer-read-only checks.

---

## `field_kit/` — the standalone collection kit templates

These are **not** run by the main Flask app; `build_field_kit.py` copies them into `dist/IAI_Collection_Kit/` alongside a frozen `collectors/collector.py`.

### `field_kit/run_kit.py`
The standalone entry point PyInstaller freezes into `run_kit.exe`. Thin wrapper: `--drive`/`--scope`/`--label` args (or interactive prompt via `collectors.collector.select_drive()`), warns if not elevated, computes an `investigation_staging_<timestamp>_<hostname>` output folder next to itself, calls `collectors.collector.run_collection()`, and prints copy-back instructions. Branches on `sys.frozen` for `KIT_ROOT` resolution — see `ARCHITECTURE.md` §9.

### `field_kit/run_kit.bat`
Shipped inside the built kit. Warns if not running as Administrator, then launches `run_kit.exe`.

### `field_kit/rebuild_kit.bat`
**Not** shipped in the kit — dev-only. Installs PyInstaller if missing, reruns `build_field_kit.py`.

### `field_kit/README.txt`
The kit's own end-user instructions (copied verbatim into the built kit) — requirements, how to run it, how to load the result back into IAI.

---

## `tools/` — bundled third-party forensic binaries

`AmcacheParser.exe`, `AppCompatCacheParser.exe`, `EvtxECmd.exe`, `JLECmd.exe`, `LECmd.exe`, `MFTECmd.exe`, `PECmd.exe`, `RBCmd.exe` (Eric Zimmerman's tools), `autorunsc.exe` (Sysinternals), `rip.exe` (RegRipper). Invoked only by `collectors/collector.py` via `subprocess.run`/`Popen` — never imported, never called by any agent directly. Copied verbatim into the field kit by `build_field_kit.py`.

---

## Quick "where do I add X" index

- **A new Windows Forensics leaf agent**: add to `agents/windows_forensics/` or `agents/malware_paths/`, wire it into the relevant orchestrator's `self.sub_agents`/`self.direct_agents` list, add a topology node in `bridge/hitl_bridge.py:_init_topology_nodes()`, add an `{x,y}` position in `static/js/app.js`'s `renderTopologyCanvas()`.
- **A new deterministic (non-LLM) agent**: subclass `BaseHITLAgent`, end `process_task()` with `run_automated_with_hitl(parsed_tool_data, deterministic_analysis)` instead of `run_with_hitl()` — see `malfind_correlator.py` or `pestudio_analysis.py` for the pattern.
- **A new cross-agent handoff trigger**: don't touch individual leaf agents — extend `core/handoff.py`'s eligibility rules (`_HANDOFF_ELIGIBLE_EXTENSIONS`, `_WINDOWS_PATH_RE`) instead; it's already called generically after every father agent.
- **A new dashboard page**: add a template extending `base.html`, a route in `web/routes.py`, a nav link in `base.html`, and (if it should be gated on "no investigation selected" — most pages should, `iocs.html` is the one exception) the `#no-investigation-banner`/`#page-body` pair `fetchStatus()` already knows how to toggle.
- **A new Pydantic schema**: `core/models.py`, grouped near its subsystem's other schemas.
- **A new persistent DB-backed feature** (not tied to a single investigation): a model class in `db/models.py`, a `core/` module for its logic if it needs any beyond CRUD, and routes in `web/management_routes.py` if it belongs on the admin-only Management page — see `ExclusionRule`/`core/exclusion_engine.py` or `SigmaRule`/`core/sigma_engine.py` for the pattern.
- **A new Management tab**: add its slug to `web/management_routes.py`'s `MANAGEMENT_TABS`, a sidebar entry + panel in `templates/management.html`, and the corresponding `/api/management/*` routes — the whole page and API are admin-only via `web/auth.py`'s global gate, so no per-route auth decorator is needed.
- **A new Help Center article**: add a numbered `.md` file under `docs/help-center/`, then add it to `core/help_content.py`'s `ARTICLE_FILES` list in the same reading-order position (that list drives the live page — `docs/help-center/README.md`'s own numbered list is just the human-readable mirror of it).
