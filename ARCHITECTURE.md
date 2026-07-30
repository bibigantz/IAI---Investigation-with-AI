# IAI - Investigate with AI: Architecture & Testing Guide

## Project Overview

IAI is an automated forensic acquisition and multi-agent AI threat hunting system for Windows endpoints. It uses a two-phase pipeline: **Evidence Collection** (Phase 1) and **AI Agent Swarm Analysis** (Phase 2), orchestrated through a Flask web dashboard with Human-In-The-Loop (HITL) approval gates.

---

## Directory Structure

```
IAI---Investigation-with-AI-master/
├── app.py                          # Flask entry point — creates app, registers routes, starts server
├── collector_paths.json            # Config: 19 forensic artifact path patterns for collector
├── event_context.txt               # Analyst-provided case context brief (injected into all agents)
├── requirements.txt                # Python dependencies
│
├── core/                           # FOUNDATION: shared utilities, models, and base agent class
│   ├── __init__.py                 # Re-exports: BaseHITLAgent, models, utils
│   ├── base_agent.py               # BaseHITLAgent class (LLM client, forensic helpers, HITL loop)
│   ├── models.py                   # Pydantic models (ForensicAnomaly, AgentAnalysisReport, etc.)
│   └── utils.py                    # locate_staging_directory(), load_event_context()
│
├── bridge/                         # WEB-AGENT INTERCONNECT: async state manager
│   ├── __init__.py
│   └── hitl_bridge.py             # WebHITLBridge singleton — DAG topology, HITL pauses, logging
│
├── web/                            # FLASK WEB LAYER
│   ├── __init__.py
│   └── routes.py                  # All Flask REST API endpoints (22 routes)
│
├── agents/                         # ALL AI AGENTS by domain
│   ├── __init__.py
│   │
│   ├── orchestrators/             # MASTER ORCHESTRATORS (coordinate sub-agents)
│   │   ├── master_analyst.py              # Top-level — dispatches to 3 father agents
│   │   ├── windows_forensics_master.py    # Windows Forensics father agent
│   │   ├── file_analysis_master.py        # File/Malware Analysis father agent
│   │   ├── memory_analysis_master.py      # Memory Analysis father agent
│   │   ├── execution_artifacts_master.py  # Sub-master: Prefetch + Amcache + Shimcache
│   │   └── malware_path_master.py         # Sub-master: 7 malware path agents
│   │
│   ├── windows_forensics/         # CHILD AGENTS: Windows forensic artifact analysis
│   │   ├── prefetch.py            # Prefetch (.pf) analysis via PECmd
│   │   ├── amcache.py             # Amcache.hve analysis via AmcacheParser
│   │   ├── shimcache.py           # Shimcache/AppCompatCache analysis
│   │   ├── evtx_sysmon.py         # Event Log & Sysmon correlation
│   │   ├── registry_miner.py      # Registry hive analysis via RegRipper
│   │   └── timeline_anomaly.py    # Super-timeline anomaly detection
│   │
│   ├── malware_paths/             # CHILD AGENTS: persistence & execution path hunting
│   │   ├── temp_folder.py         # Temp directory dropper analysis
│   │   ├── downloads_folder.py    # Downloads folder MotW & payload inspection
│   │   ├── program_data.py        # ProgramData manifest analysis
│   │   ├── scheduled_tasks.py     # Scheduled task persistence
│   │   ├── services.py            # Windows service persistence
│   │   ├── drivers.py             # Kernel driver / BYOVD detection
│   │   └── autoruns.py            # Startup/logon autoruns analysis
│   │
│   ├── file_analysis/             # CHILD AGENTS: binary & malware analysis
│   │   ├── pestudio_analysis.py   # PE static analysis (headers, sections, imports, entropy)
│   │   ├── strings_analysis.py    # String extraction + 5 specialized sub-agents
│   │   └── ghidra.py              # Ghidra headless decompilation (placeholder)
│   │
│   └── memory_analysis/           # CHILD AGENTS: volatile memory (Volatility 3)
│       ├── pstree.py              # Process tree & DKOM detection
│       ├── network.py             # Network socket / C2 detection
│       └── malfind.py             # Code injection (reflective DLL, process hollowing)
│
├── collectors/                     # EVIDENCE ACQUISITION
│   ├── collector.py               # Main forensic collection engine (SHA-256 verified copies)
│   └── file_extractor.py          # Standalone file ingestion utility
│
├── static/                         # WEB FRONTEND
│   ├── css/style.css              # Cyberpunk dark theme
│   └── js/app.js                  # Dashboard JS (polling, DAG topology, HITL workflow)
│
├── templates/                      # JINJA2 TEMPLATES
│   ├── base.html                  # Base layout with nav
│   ├── dashboard.html             # Launch hub & pipeline controls
│   ├── topology.html              # SVG DAG topology canvas
│   └── agents.html                # Agent control center
│
├── tools/                          # FORENSIC TOOLS (third-party executables)
│   ├── PECmd.exe, AmcacheParser.exe, AppCompatCacheParser.exe, EvtxECmd.exe
│   ├── rip.exe (RegRipper), autorunsc.exe, RBCmd.exe, MFTECmd.exe, LECmd.exe, JLECmd.exe
│
└── investigation_staging_*/        # Collector output (auto-generated)
    ├── <Category>/raw/             # Collected artifact files
    ├── <Category>/metadata/        # Parsed tool output (CSV, TXT)
    └── *_Report.json               # Investigation reports
```

---

## Agent Hierarchy (25 Nodes)

```
Master_Analyst_Agent
├── Windows_Forensics_Father_Agent
│   ├── Master_Execution_Artifacts_Analyzer
│   │   ├── Prefetch_Analyzer
│   │   ├── Amcache_Analyzer
│   │   └── Shimcache_Analyzer
│   ├── Master_Execution_Paths_Analyzer
│   │   ├── Temp_Folder_Analyzer
│   │   ├── Downloads_Folder_Analyzer
│   │   ├── ProgramData_Analyzer
│   │   ├── Scheduled_Tasks_Analyzer
│   │   ├── Services_Analyzer
│   │   ├── Drivers_Analyzer
│   │   └── Autoruns_Analyzer
│   ├── EVTX_Sysmon_Correlator
│   ├── Registry_Hive_Miner
│   └── Timeline_Anomaly_Detector
├── File_Analysis_Father_Agent
│   ├── PeStudio_Static_Triage_Analyzer
│   ├── Strings_Analyzer
│   └── Ghidra_Reverse_Engineering_Agent
└── Memory_Analysis_Father_Agent
    ├── PsTree_Process_Mapper
    ├── Network_Socket_Correlator
    └── MalFind_Injected_Code_Analyzer
```

---

## Changes Made During Reorganization

### 1. Core Package Split
- **`core_agents.py`** split into `core/base_agent.py`, `core/models.py`, `core/utils.py`
- Models extracted: `ForensicAnomaly`, `AgentAnalysisReport`, `AgentResponse`, `HumanFeedback`
- Utils extracted: `locate_staging_directory()`, `load_event_context()`
- `load_event_context()` path updated from `__file__` parent to project root (two levels up)

### 2. Bridge Isolation
- **`web_hitl_bridge.py`** moved to `bridge/hitl_bridge.py`
- All `from web_hitl_bridge import bridge` changed to `from bridge.hitl_bridge import bridge`
- `core/base_agent.py` imports bridge as `from bridge.hitl_bridge import bridge`

### 3. Web Layer Refactor
- **`app.py`** now a thin entry point — creates Flask app, calls `register_routes(app)`
- All 22 REST API routes moved to `web/routes.py`
- `web/routes.py` imports bridge from `bridge.hitl_bridge`

### 4. Agent Reorganization
- 6 orchestrator agents moved to `agents/orchestrators/`
- 6 windows forensics agents moved to `agents/windows_forensics/`
- **`malware_path_agents.py`** (containing 7 classes) split into individual files under `agents/malware_paths/`
- 3 file analysis agents moved to `agents/file_analysis/`
- 3 memory analysis agents moved to `agents/memory_analysis/`
- All agent filenames shortened (e.g., `prefetch_agent.py` → `prefetch.py`)

### 5. Duplicate Removal
- **`strings_agent.py`** removed (exact duplicate of `strings_analysis_agent.py`)

### 6. Collectors
- `collector_agent.py` moved to `collectors/collector.py`
  - `TOOLS_DIR` path updated from `BASE_DIR/tools` to `parent(BASE_DIR)/tools`
  - `BASE_DIR` now points to `collectors/` not project root
- `File_Extractor.py` moved to `collectors/file_extractor.py`

### 7. Path Dependencies Fixed
- `core/utils.py`: `_SCRIPT_DIR` uses `parent.parent` (now at `core/` → project root) to find `event_context.txt`
- `collectors/collector.py`: `TOOLS_DIR` goes up one level to find `tools/` directory
- `web/routes.py`: `UPLOAD_FOLDER` goes up one level from `web/` to project root
- All imports updated across 40+ files to use new package paths

---

## Testing Guide

### Prerequisites
```bash
pip install -r requirements.txt
```

### Testing Individual Agents (standalone)
Each agent can be run independently for testing (they all have `if __name__ == "__main__"` blocks):

```bash
# Test a windows forensics agent
python -m agents.windows_forensics.prefetch [staging_dir]

# Test an orchestrator
python -m agents.orchestrators.execution_artifacts_master [staging_dir]

# Test the collector
python -m collectors.collector [config_path]
```

### Testing Agent Import Hierarchy
```bash
# Foundation layer
python -c "from core import BaseHITLAgent, locate_staging_directory"
python -c "from core.models import ForensicAnomaly, AgentAnalysisReport"

# Bridge layer
python -c "from bridge.hitl_bridge import bridge, WebHITLBridge"

# Individual agents by domain
python -c "from agents.windows_forensics.prefetch import PrefetchAgent"
python -c "from agents.malware_paths.temp_folder import TempFolderAgent"
python -c "from agents.file_analysis.pestudio_analysis import PeStudioAnalysisAgent"
python -c "from agents.memory_analysis.pstree import PsTreeAgent"

# Orchestrators
python -c "from agents.orchestrators.master_analyst import MasterAnalystAgent"
python -c "from agents.orchestrators.windows_forensics_master import WindowsForensicsMaster"

# Full pipeline import test
python -c "from agents.orchestrators.master_analyst import MasterAnalystAgent; a = MasterAnalystAgent(); print('MasterAnalystAgent created successfully')"
```

### Testing the Full Application
```bash
# Start the web server
python app.py

# The server will start on http://0.0.0.0:5000
# Access the dashboard at http://127.0.0.1:5000/
# Available pages:
#   /           - Dashboard / Launch Hub
#   /topology   - DAG Topology Visualization
#   /agents     - Agent Control Center
```

### Testing the Collector (Phase 1)
```bash
# Interactive mode — selects a drive and collects artifacts
python -m collectors.collector

# With custom config path
python -m collectors.collector custom_paths.json
```

### API Endpoint Testing
After starting the server, test key endpoints:
```bash
# Check system status
curl http://127.0.0.1:5000/api/status

# Get topology
curl http://127.0.0.1:5000/api/topology

# List available drives
curl http://127.0.0.1:5000/api/drives

# List existing investigations
curl http://127.0.0.1:5000/api/investigations/existing

# Toggle mode
curl -X POST http://127.0.0.1:5000/api/mode -H "Content-Type: application/json" -d '{"mode": "AUTOMATIC"}'
```

### Testing End-to-End Investigation
1. Start the server: `python app.py`
2. Open http://127.0.0.1:5000/ in a browser
3. Create a new investigation (or use an existing staging folder)
4. Set scope (ALL / WINDOWS / FILE / MEMORY)
5. Click "Start Investigation"
6. Monitor progress via the dashboard logs and DAG topology

### Running Individual Agent Scripts
Each agent can be run standalone from its folder:
```bash
# These will auto-find the newest investigation_staging_* folder
python -m agents.windows_forensics.prefetch
python -m agents.orchestrators.malware_path_master

# Or specify a staging directory
python -m agents.orchestrators.master_analyst /path/to/investigation_staging_20260721_091608 ALL
```
