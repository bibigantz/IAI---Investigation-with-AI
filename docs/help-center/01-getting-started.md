# Getting Started: Launch Hub & Topology

## Launching an investigation `#AgentConfiguration` {#launching-an-investigation}

The Launch Hub (`/`) is a single page with two states: the **Setup Hub**
(no investigation running) and the **Active Dashboard** (one is), toggled
automatically based on pipeline status.

### Step-by-step: starting a new investigation {#new-investigation-steps}

1. Pick a **scope**: Full System Analysis (all agents), Windows Forensics
   only, File/Malware Analysis only, or Volatility Memory Analysis only.
2. Pick a **target drive** to collect from, or "Skip drive collection" if
   you're supplying files directly instead.
3. Depending on scope, one or more upload areas appear:
   - **File upload** (Full/File scope): `.exe`, `.dll`, `.sys`, `.zip`,
     `.rar`, `.7z`. Password-protected ZIPs are auto-extracted using the
     common malware analysis password `infected` automatically.
   - **Memory dump upload** (Full/Memory scope): `.raw`, `.dmp`, `.vmem`,
     `.mem`, `.lime`.
   - **Deep file extraction** (Full/File scope): a separate "extract and
     stage for analysis" uploader for archives you want unpacked and fed
     straight into the File Analysis pipeline.
4. Optionally add **case context** — free text injected into every agent's
   system prompt (e.g. "Investigating a suspected phishing-delivered
   payload reported by the user around 14:00 on 2026-09-28").
5. Click **Launch AI Swarm Pipeline**.

![Launch Hub Setup view with Full System Analysis scope selected and all three upload areas visible](placeholder-launch-hub-setup.png)
*Figure 1: The Setup Hub with scope set to "Full system analysis (all tiers)," showing the drive selector and all three conditional upload areas.*

> ✅ **Best Practice:** if you're doing a memory-only analysis and skipping
> drive collection, the memory-dump uploader is the only thing gating
> launch — you'll get a clear warning ("Memory Analysis scope requires a
> memory dump file...") if you try to launch without one.

### Step-by-step: resuming an existing investigation {#resuming-investigation-steps}

1. The Setup Hub's right panel lists every `investigation_staging_*` folder
   found in the project root — modified time, file counts, and whether a
   final report already exists.
2. Click a session to select it (the most recent is auto-selected).
3. Optionally add case context, then click **Resume Selected Session**.

> ⚠️ **Warning:** resuming always restarts the pipeline with scope **`ALL`**
> and no drive collection, regardless of what scope the session was
> originally launched with. If you started a Memory-only investigation and
> later resume it, you're not just re-running the memory tier — you're
> potentially kicking off Windows Forensics and File Analysis against
> whatever's already staged, too.

![Existing Staging Sessions list with one session showing a "Report ready" badge](placeholder-existing-sessions.png)
*Figure 2: The Existing Staging Sessions panel — one folder showing "Report ready" with a download icon, another showing "No report yet."*

### The Active Dashboard {#active-dashboard}

Once running: four KPI tiles (pipeline status, execution mode, pending
HITL approvals, total swarm nodes), Pause/Resume, Stop Swarm (confirms
before terminating), Download Report (appears once the master report
exists), a live log terminal (polls every 2 seconds), and a quick
case-context injection box that updates the *currently active*
investigation's context on the fly.

### Execution mode: SUPERVISED vs. AUTOMATIC {#execution-mode}

Toggled from the navbar, applies platform-wide immediately:

- **SUPERVISED** (default): every agent pauses after producing its
  analysis and waits for you to Approve or Revise via the HITL queue.
- **AUTOMATIC**: every agent's output is auto-approved the instant it's
  produced — no human gate. Useful for a fast unattended first pass, but
  means nothing gets a second look before becoming a finding (and, for
  Memory Analysis specifically, means the Injected Code Analyzer's
  handoff to File Analysis fires automatically too, since approval is
  the trigger for that handoff).

![Mode toggle in the navbar switching from SUPERVISED to AUTOMATIC](placeholder-mode-toggle.png)
*Figure 3: The navbar mode badge showing "AUTOMATIC" after clicking Switch, with the confirmation toast visible.*

---

## Agent Control Center `#AgentConfiguration` {#agent-control-center}

`/agents` — a direct window into any single agent's raw parsed data and AI
analysis, plus the HITL approve/revise controls (the same underlying
`/api/hitl/approve` and `/api/hitl/revise` endpoints used by the Topology
page's node-click drawer).

![Agent Control Center with an agent selected, showing raw data and AI analysis side by side](placeholder-agent-control-center.png)
*Figure 4: The Agent Control Center — `MalFind_Injected_Code_Analyzer` selected, raw Volatility output on the left, AI analysis JSON on the right, Approve/Revise controls visible below.*

> ⚠️ **Warning:** the "System Prompt Override" box on this page does not
> currently affect agent behavior — see
> [System Management](06-system-management.md#agent-prompt-overrides).

---

## Topology View {#topology-view}

`/topology` — a live SVG diagram of every agent node (Master → Father →
Sub-master → Leaf), color-coded by state: **Gray** idle, **Green** active,
**Yellow** action required (HITL pending), **Blue** approved. Pan by
dragging, zoom with the on-canvas controls, maximize for a full-screen
view. Clicking any node opens the same detail drawer / approve-revise flow
as the Agent Control Center.

![Topology view showing the full agent tree with several nodes in different states](placeholder-topology-view.png)
*Figure 5: The Topology diagram mid-investigation — Master and both relevant Father Agents green, several leaf nodes yellow awaiting approval, others blue already approved.*

---

## How the swarm actually orchestrates itself {#orchestration-details}

Useful for understanding *why* a run behaves the way it does, especially
under SUPERVISED mode where every approval click is a synchronization
point:

- **Father Agent execution order is always Memory → Windows → File** —
  deliberately, not alphabetical. File Analysis is the terminal handoff
  destination (from Memory Analysis's Injected Code Analyzer), so running
  it last means a same-run handoff has already landed by the time File
  Analysis starts.
- **A failed Father Agent doesn't stop the others.** Each runs in its own
  try/except; a failure is recorded and logged, the master report still
  compiles at the end with whatever did complete, and the pipeline status
  reflects "completed with partial results" rather than a hard failure —
  unless *every* father agent failed, in which case the whole run is
  marked errored.
- **Only two places in the whole agent tree run sub-agents concurrently**:
  Memory Analysis's second stage (Injected Code Analyzer + Process/Thread
  Mapper + Network Socket Correlator run simultaneously via
  `asyncio.gather`), and File Analysis's second stage (Reverse Engineering
  + Dynamic Sandbox, when both run at all). Every other orchestrator level
  — including all of Windows Forensics's six leaf agents — runs strictly
  sequentially. In SUPERVISED mode, that means clicking Approve on one
  Windows Forensics finding is what unblocks the *next* one, one at a time.

---

## Field Collection Kit {#field-collection-kit}

For acquiring evidence on an air-gapped or otherwise Python-less target
machine: `python build_field_kit.py` (requires `pyinstaller`) produces a
standalone `dist/IAI_Collection_Kit/run_kit.exe` that needs no Python
installed on the target. Running it produces an
`investigation_staging_<timestamp>_<hostname>/` folder in the exact same
format the built-in collector produces — copy that folder into this
project's root directory and it shows up in "Existing Staging Sessions"
like any other investigation. See `field_kit/README.txt` for the full
walkthrough and `field_kit/rebuild_kit.bat` to rebuild after any collector
changes.

> ℹ️ **Info:** This is for *acquisition* only — analysis still happens back
> on the main platform after you copy the folder over. The kit doesn't run
> any agents itself.

---

## Collector scopes, precisely {#collector-scopes}

The four scope values (`ALL`, `WINDOWS`, `FILE`, `MEMORY`) aren't just an
agent filter — they also control what the **collector itself** gathers
before any agent runs:

- `MEMORY` scope **skips evidence collection entirely** — the whole point
  is "don't touch the disk, just analyze a memory image I'm supplying."
  You'll see a log line to that effect during launch.
- `WINDOWS` and `FILE` scopes collect only the artifact categories
  relevant to their respective agents, not everything `ALL` would.

---

## Light mode / dark mode {#light-dark-mode}

Click your username (top-right of the navbar) to open the dropdown, then
pick **Theme → ☀ / 🌙**. The choice is saved in your browser (not tied to
your account — it's per-browser, not per-user) and applies immediately, on
every page, without a reload.

> ℹ️ **Info:** Terminal-style panels — the live log stream, the raw
> data/AI analysis code viewers in the Agent Control Center and Topology
> drawers, the Help Center's code blocks — deliberately stay dark in both
> themes. That's a console aesthetic, not page chrome, and it reads as
> intentional rather than "the toggle missed something."
