# IAI — Investigate with AI

A Windows DFIR (Digital Forensics & Incident Response) platform that pairs a real evidence-acquisition engine with a tree of ~25 AI agents that triage Windows artifacts, suspicious binaries, and memory dumps — with a human analyst approving or revising every finding before it's final.

It runs as a single local web app (Flask + a plain-JavaScript dashboard). Point it at a drive, pick a scope, and it collects evidence, hands it through three specialized agent domains (Windows Forensics, File/Malware Analysis, Memory Analysis), and produces a final downloadable report — while you watch the agent tree light up live and approve or push back on every step.

> **Looking for how the system is built, not how to use it?** See **[ARCHITECTURE.md](ARCHITECTURE.md)** (how everything works and why) and **[DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)** (a map of every file and what it connects to).

---

## What it actually does

```
Target drive / uploaded files / memory dump
        │
        ▼
Phase 1 — Evidence Collection (collectors/collector.py)
  Copies + SHA-256-verifies artifacts, runs Eric Zimmerman / Sysinternals / RegRipper
  tools, writes investigation_staging_<timestamp>/
        │
        ▼
Phase 2 — AI Agent Swarm (agents/)
  Memory Analysis  →  Windows Forensics  →  File / Malware Analysis
  (this order lets a Windows/Memory finding hand a suspicious file straight
  to File Analysis within the same run — see "Cross-agent handoff" below)
        │  each agent's finding pauses for your approve/revise (HITL)
        ▼
Master_Executive_Intelligence_Report.json  (downloadable from the dashboard)
```

- **Windows Forensics**: Prefetch/Amcache/Shimcache execution evidence, EVTX/Sysmon correlation, registry persistence, timeline anomalies, and the classic malware-drop locations (Temp, Downloads, AppData, ProgramData, Scheduled Tasks, Services, Drivers, Autoruns).
- **File / Malware Analysis**: static PE/ELF triage (hashes, entropy, imports, CAPA capability mapping) → Ghidra-assisted reverse engineering with automatic XOR/base64 string decoding → optional sandbox detonation (Cuckoo) that cross-checks what a file *claimed* it could do against what it *actually did* at runtime.
- **Memory Analysis**: Volatility3-driven process tree reconstruction, a deterministic code-injection correlator, and network socket correlation against a live memory image.
- **Cross-agent handoff**: if a Windows Forensics or Memory Analysis agent flags a file that was never actually collected (e.g. a registry-referenced binary), it gets copied into the File Analysis pipeline's intake folder automatically, so the *same* investigation run analyzes it — not just a re-run.
- **Human-In-The-Loop**: every agent's finding pauses the pipeline until you click Approve or Revise (with feedback, which re-runs that agent's LLM step with your correction folded in). Flip to AUTOMATIC mode to let findings self-approve instead.

---

## Requirements

- **Windows** (the collector and several parsers use Windows-only APIs — VSS, ADS, registry hives, `ctypes.windll`).
- **Python 3.10+**
- An **LLM endpoint every agent calls via an OpenAI-compatible API** — this platform is designed to run fully offline, with **[Open WebUI](https://docs.openwebui.com/)** as the supported local AI provider (Open WebUI itself commonly sits in front of Ollama or another local backend, and exposes an OpenAI-compatible API of its own). There's nothing to set via an env var or before first boot: sign in, go to **System Management → AI & Agent Orchestration → LLM Provider Configuration**, and point it at your Open WebUI instance's URL + an API key generated there (Settings → Account → API Keys). Use that page's **Test Connection** button to verify before relying on it. A cloud provider (OpenAI, etc.) works the same way if you're not running offline — just paste its real base URL/key instead.
- Optional, only if you want the corresponding analysis to actually run instead of gracefully reporting "not available":
  - **Volatility3** (`pip install volatility3`, already in `requirements.txt`) + the `vol` CLI on `PATH` — needed for Memory Analysis to parse a real memory image.
  - **Ghidra MCP / CAPA MCP / Cuckoo v3 MCP** servers — needed for File Analysis's Reverse Engineering and Dynamic Sandbox steps to do more than report "server not reachable." See [Configuring the File Analysis MCP servers](#configuring-the-file-analysis-mcp-servers) below.

Everything else (the forensic parser binaries — PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd, EvtxECmd, JLECmd, LECmd, RBCmd, RegRipper, Sysinternals Autoruns) is already bundled under `tools/`.

## Install & run

```bash
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000/** and sign in with the first-run account — username `admin`, password `changeme` — you'll be forced to set a real password immediately. Then configure your LLM provider (see Requirements above) before launching your first investigation.

---

## Using the dashboard

### 1. Launch Hub (`/`)

This is what you see when nothing is running (`pipeline_status == IDLE`).

- **New Investigation** (left panel): pick a target drive (or "Skip drive collection" if you're only uploading files / a memory dump), a **scope** —
  - `ALL` — collect + run every analysis domain
  - `WINDOWS` — Windows Forensics only
  - `FILE` — File/Malware Analysis only (you'll usually want to also attach files via the uploader)
  - `MEMORY` — Memory Analysis only (upload a `.raw`/`.dmp`/`.vmem`/`.mem`/`.lime` dump — the collector can't acquire memory itself)
  - optionally attach files/malware samples directly (auto-extracts password-protected ZIPs, trying `infected` first), add an incident context brief (free text — it's injected into every agent's system prompt so it can prioritize what you tell it to look for), then **Launch AI Swarm Pipeline**.
- **Existing Staging Sessions** (right panel): every past `investigation_staging_*` folder found in the project root, with file counts and whether it has a downloadable report. Click the row to select it, add/edit its case-context brief, and **Resume Selected Session** — this restores exactly the topology/findings/log state that investigation was left in (not a blank slate) and re-runs analysis against files already staged there. Click the panel heading itself to force a re-scan if a folder doesn't show up yet.

### 2. Active Dashboard (while `RUNNING`/`PAUSED`/`COMPLETED`)

KPI tiles (pipeline status, mode, pending HITL count, node count), Pause/Resume/Stop/Return-to-Hub, a live log terminal, and quick context injection (adds to the case brief mid-run without restarting). **Download Report** appears once `Master_Executive_Intelligence_Report.json` exists for the active investigation.

### 3. Dynamic Topology (`/topology`)

A live SVG diagram of the whole agent tree. Node color = state: gray (idle), green (active / a child is active), yellow (awaiting your HITL decision), blue (approved). Click any node to open its findings and Approve/Revise from there. Pan/zoom/maximize controls included. Shows a "no investigation selected" placeholder until you've actually started or resumed one.

### 4. Agent Control Center (`/agents`)

Sidebar of every agent node; pick one to see its raw parsed data, the AI's analysis JSON, edit its system prompt (currently display-only — see note below), and drive the same Approve/Revise controls.

### 5. Findings (`/findings`)

Every anomaly from every agent, aggregated and sorted most-severe-first, with severity filter chips and an "approved only" toggle.

### Execution mode: SUPERVISED vs AUTOMATIC

Toggle in the top-right nav badge. **SUPERVISED** (default) pauses every agent at its finding for your decision. **AUTOMATIC** auto-approves everything the instant it's produced — useful for a fast unattended first pass; switch back to SUPERVISED to review anything specific afterward.

---

## The Field Collection Kit

If you need to collect evidence from a machine that will never run this app (an actual suspect endpoint, air-gapped from your analyst workstation), build a standalone kit:

```bash
pip install pyinstaller
python build_field_kit.py
```

This produces `dist/IAI_Collection_Kit/` (and a `.zip`) containing `run_kit.exe` — a single self-contained executable (no Python needed on the target machine) plus the `tools/` binaries and `collector_paths.json` it needs. Copy the whole folder to a USB drive, run `run_kit.exe` (as Administrator for the fullest capture) on the target machine, and it produces an `investigation_staging_<timestamp>_<hostname>/` folder in the same byte-for-byte format this app already understands. Copy that folder into this project's root directory, click "Existing Staging Sessions" to re-scan on the dashboard, and resume it like any other investigation.

See `field_kit/README.txt` for the exact walkthrough, and `field_kit/rebuild_kit.bat` to rebuild after any change to `collectors/collector.py`.

## Configuring the File Analysis MCP servers

Reverse Engineering and Dynamic Sandbox talk to Ghidra/CAPA/Cuckoo over the Model Context Protocol (`pip install mcp`, already in `requirements.txt`). Point each at your actual server via environment variables (all optional — a missing server just makes that step report "not reachable" instead of crashing):

| Server | Command/stdio | Or a URL (SSE) |
|---|---|---|
| Ghidra MCP | `GHIDRA_MCP_COMMAND`, `GHIDRA_MCP_ARGS` | `GHIDRA_MCP_URL` |
| CAPA MCP | `CAPA_MCP_COMMAND`, `CAPA_MCP_ARGS` | `CAPA_MCP_URL` |
| Cuckoo v3 MCP | `CUCKOO_MCP_COMMAND`, `CUCKOO_MCP_ARGS` | `CUCKOO_MCP_URL` (default transport) |

Also: `*_TIMEOUT` (seconds, default 120) and `*_TRANSPORT` (`stdio` or `sse`) per server if you need to override the default.

## Optional: an IOC list for the Network Socket Correlator

Drop a plain-text file at the project root named `ioc_list.txt` (one IP/domain per line, `#` comments allowed) and Memory Analysis's Network Socket Correlator will flag any matching connection automatically. Override the filename with the `IOC_LIST_FILE` env var.

---

## A note on security

This is a local analyst tool, not a hardened multi-tenant service. It does have session-based login now (default first-run account `admin`/`changeme`, forced password change on first sign-in, and an admin-only System Management area) — but roles beyond "admin vs. not" aren't finely enforced, sessions don't expire, and there's no rate-limiting or audit trail on login attempts. Run it on `localhost`/a trusted network only. See `ARCHITECTURE.md`'s "Known architectural gaps" section for this and a few other things worth hardening before any wider deployment.

---

## Project layout (short version)

```
app.py                  Flask entry point
web/routes.py           All HTTP routes
bridge/hitl_bridge.py   The in-memory state hub connecting the UI, the pipeline, and the agents
collectors/collector.py Phase 1: evidence acquisition
core/                    Shared agent foundation (LLM client, pydantic schemas, cross-agent handoff)
agents/                  Phase 2: the AI swarm (windows_forensics/, file_analysis/, memory_analysis/, orchestrators/)
static/, templates/      The dashboard's frontend
field_kit/, build_field_kit.py   The standalone offline collection kit
tools/                   Bundled third-party forensic parser binaries
```

For what every one of those files actually does and how they connect, see **[DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)**. For the "why" behind the design (execution order, the HITL cross-thread handshake, the concurrency model, known limitations), see **[ARCHITECTURE.md](ARCHITECTURE.md)**.
