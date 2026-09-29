# Memory Analysis `#MemoryAnalysis`

## Overview {#memory-overview}

The **Memory Analysis Father Agent** runs Volatility3 against one memory
image per investigation and hands its four leaf agents' findings up to the
main Findings dashboard. It only activates when the investigation scope is
`ALL` or `MEMORY`.

> ⚠️ **Warning — where to put the memory image.** Volatility only ever looks
> in `<staging_folder>/MemoryDumps/raw/`. If you're supplying an image that
> wasn't collected by the field kit, upload it through the Launch Hub's
> "Memory Analysis" scope uploader (accepts `.raw`, `.dmp`, `.vmem`, `.mem`,
> `.lime`) — as of this documentation pass that uploader correctly lands
> files there. If more than one file lands in that folder, the largest one
> is used; don't leave stray small files (checksums, notes) alongside a real
> image.

![Launch Hub with MEMORY scope selected and a .raw file staged in the memory-dump uploader](placeholder-memory-launch.png)
*Figure 1: The Launch Hub's scope selector set to "Volatility memory analysis only," with the memory-dump uploader showing one staged `.raw` file before clicking "Launch AI Swarm Pipeline."*

Under the hood, `run_plugin()` shells out to whichever of `vol`, `vol.py`, or
`python -m volatility3.cli` is on PATH, requesting `-r json` output. Any
failure — missing binary, corrupt image, plugin timeout, non-JSON output —
is caught, logged to the live console as a `WARN`, and degrades to an empty
result rather than crashing the run. If every memory-analysis finding comes
back empty, check the live log terminal for `Volatility` warnings before
assuming the image is clean.

---

## Process & Thread Mapper `#MemoryAnalysis` {#process-thread-mapper}

Runs `windows.pslist.PsList`, `windows.pstree.PsTree`, and
`windows.psxview.PsXView`, then applies two **deterministic** checks before
the LLM ever sees the data:

- **Hidden/unlinked processes**: a PID that shows up in the PsXView
  cross-view scan but is absent from PsList's own linked-list walk — the
  classic DKOM (Direct Kernel Object Manipulation) unlinking tell.
- **Parent/child anomalies**: cross-referenced against a fixed expected-
  parent table (e.g. `svchost.exe` must be spawned by `services.exe` or
  `wininit.exe`). A mismatch is flagged **"Unexpected Parent"** (High); a
  process with no live parent at all is flagged **"Orphaned Process"**
  (Medium).

The agent's own `anomaly_score` is computed purely from these two checks
(`hidden_pids × 40`, plus `15` per High-severity anomaly / `8` per Medium) —
it is not an LLM confidence score. The LLM's job on top of this is narrower:
hunting for masquerading process names and non-standard install paths that
the deterministic pass can't catch.

### Step-by-step: reading a Process & Thread Mapper finding {#process-thread-mapper-steps}

1. Open **Findings**, filter to agent `PsTree_Process_Mapper`.
2. A finding's `filepath` field is not a real filesystem path here — it's
   formatted as `PID <pid> (<process_name>)`. This exact format is also the
   join key the Father Agent uses internally to cross-reference this
   process against other memory findings, so don't expect a Windows path in
   that field for this agent specifically.
3. **"Hidden From PsList"** anomalies are the highest-value ones — this is a
   real rootkit/DKOM signal, not a heuristic guess. Escalate immediately.
4. **"Unexpected Parent"** findings are common false-positive territory for
   unusual-but-legitimate software (some AV/EDR agents, some update
   services). Check the process name against known software before
   escalating.

![Findings page filtered to PsTree_Process_Mapper, showing a Hidden From PsList badge](placeholder-pstree-findings.png)
*Figure 2: A "Hidden From PsList" finding in the Findings list — note the `PID 4172 (svchost.exe)` identifier format in place of a filesystem path.*

> ✅ **Best Practice:** Cross-reference an "Unexpected Parent" finding against
> the Network Socket Correlator's output for the same PID before dismissing
> it — a legitimate-looking process with an unexpected parent *and* an
> unexpected outbound connection is a much stronger signal together than
> either alone.

---

## Injected Code Analyzer `#MemoryAnalysis #MalwareTriage` {#injected-code-analyzer}

This is the agent that actually **hands a suspicious memory region off to
File/Malware Analysis** for deeper reverse engineering — but only under
specific conditions, which matters for understanding why a finding you
approved didn't automatically trigger a File Analysis pass on some other
run.

The Memory Analysis Father Agent runs **Malfind Correlator first** (see
below), then only escalates candidates scoring **25 or higher** to this
agent's LLM. The LLM is explicitly instructed to rule out common false
positives — JIT compilers, .NET/Mono/Java runtimes, PowerShell's AMSI
scanning buffer — and, critically, **ruling something out means simply not
including it in the findings list**, not adding a low-severity note. If a
malfind hit you expected to see isn't in your Findings list at all, the LLM
may have silently cleared it as a known-benign pattern.

### Step-by-step: from finding to handoff {#injected-code-handoff-steps}

1. A candidate is identified as `PID <pid> (<process_name>) @ <virtual_address>`
   — same join-key convention as the Process Mapper.
2. **The handoff to File Analysis only happens after you click Approve** on
   this finding in the HITL flow — not merely because the LLM flagged it.
   Approval is the trigger, not detection.
3. Once approved, the agent locates the actual dumped memory region (written
   to disk by Volatility's `malfind --dump` during the Malfind Correlator
   pass), computes its SHA-256/MD5, checks for a PE header (`MZ` magic
   bytes), and copies it into `ProgramDataList/raw/` in the staging folder
   under a name like `memdump_pid4172_0x7ffe0000_explorer.exe`.
4. That copy is what the File & Malware Analysis Father Agent's Static
   Triage pass picks up **on the same run** — memory-to-malware handoff is
   same-session, not something you trigger separately.

![Finding detail drawer for an injected-code finding, with the handoff note visible in the audit log](placeholder-injected-code-handoff.png)
*Figure 3: The finding detail drawer after approval — the audit log entry confirms the dumped region was copied into `ProgramDataList/raw/` for the next stage.*

> 🔧 **Troubleshooting:** If you approved an injection finding but never see
> a corresponding Static Triage finding referencing the same process name,
> check that a `.dmp` file was actually written — Volatility's `--dump`
> output naming is matched by a glob pattern (`pid.<pid>.*.dmp`) plus a
> virtual-address substring match with a PID-only fallback; a Volatility
> version that names dump files differently can break this match silently.

---

## Network Socket Correlator `#MemoryAnalysis #NetworkForensics` {#network-socket-correlator}

**This agent spends zero LLM tokens.** It's pure deterministic automation —
still routed through the same human-in-the-loop approval queue as every
other agent, but its conclusion is never generated by a language model.

It runs `windows.netscan.NetScan` plus `windows.pslist.PsList` (to know
which PIDs are actually alive) and flags a connection for any of:

- The owning process is on a short list of processes that should never hold
  a network connection (`notepad.exe`, `calc.exe`, `lsass.exe`,
  `winlogon.exe`, `csrss.exe`, `smss.exe`, `wininit.exe`, `explorer.exe`,
  `mspaint.exe`).
- Local or foreign port is one of a fixed suspicious-port set: `4444`,
  `1337`, `6666`, `6667`, `31337`, `8081`, `9001`, `9999`.
- A local port ≥ 49152 (the ephemeral range) is in a `LISTENING` state —
  unusual for a legitimate listener.
- The foreign address matches your local **IOC list** (see below).

Severity is **High** if the IOC list matched or a C2-style port matched,
**Medium** for everything else flagged. Connections whose owning PID no
longer appears in the live process list are reported separately as *orphan
sockets*, not as anomalies — they're contextual, not necessarily suspicious.

### Setting up the local IOC list {#network-ioc-list}

Drop a plain-text file named `ioc_list.txt` in the project root: one IP or
domain per line, `#` for comments. Override the filename with the
`IOC_LIST_FILE` environment variable if you'd rather point at a
per-engagement list.

```text
# Known C2 infrastructure for this engagement
185.220.101.42
update-service-cdn.net
```

> ℹ️ **Info:** This is a static local file, not a live threat-intel feed —
> there's no automatic VirusTotal/AbuseIPDB lookup happening here. If you
> want to pivot a specific finding value out to an external lookup service,
> that's the separate "pivot & hunt" feature on the Findings page — see
> [Findings Management](05-findings-management.md#pivot-and-hunt-links).

![ioc_list.txt open in an editor next to a Network Socket Correlator finding it triggered](placeholder-network-ioc.png)
*Figure 4: A local `ioc_list.txt` entry and the resulting High-severity finding it produced on the Network Socket Correlator's output.*

---

## Malfind Correlator `#MemoryAnalysis #MalwareTriage` {#malfind-correlator}

Also **zero LLM tokens** — this is the deterministic scoring pass that
decides which malfind hits are even worth spending an LLM call on (see
Injected Code Analyzer above).

Runs `windows.malfind.Malfind` (with dumping enabled), `windows.thrdscan.
ThrdScan`, `windows.handles.Handles`, and `windows.dlllist.DllList`
(deliberately *not* `windows.modules.Modules`, which lists kernel drivers,
not per-process loaded DLLs — using the wrong plugin here would silently
break the "is this VA inside a legitimately loaded module" check).

### How the confidence score is built {#malfind-scoring}

| Signal | Points |
|---|---|
| Base: unbacked VAD region (always true for a malfind hit) | +30 |
| A thread's start address falls inside this region | +30 |
| Another process holds a handle to this PID | +25 |
| ...and that handle's access rights include `VM_WRITE`/`CREATE_THREAD`/`ALL_ACCESS`/`VM_OPERATION` | +10 |
| Region protection includes `EXECUTE_READWRITE` | +15 |
| VA falls inside a legitimately loaded module's range | **−40** |

Score is clamped to 0–100. **Severity**: ≥70 Critical, ≥50 High, ≥25
Medium, below 25 Low (and below the Injected Code Analyzer's review
threshold entirely).

> ✅ **Best Practice:** The −40 "inside a loaded module" penalty is doing a
> lot of noise reduction — most RWX regions inside a legitimately mapped
> module are JIT engines or self-modifying-but-legitimate code, not
> injection. Don't override a Low/dismissed verdict here without checking
> whether that penalty is why the score dropped.

![Malfind Correlator finding detail showing the confidence score breakdown in the justification text](placeholder-malfind-score.png)
*Figure 5: A finding's justification text spelling out which scoring rules fired — e.g. "unbacked VAD (+30), thread start in region (+30), remote handle from PID 2201 with VM_WRITE (+25+10) = 95/100, Critical."*
