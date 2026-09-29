# Windows Forensics & Common Malware Paths `#WindowsForensics`

Not called out explicitly in the original feature brief, but this is the
largest single Father Agent in the platform — 6 execution-artifact/timeline
agents plus 8 malware-path agents. Runs when scope is `ALL` or `WINDOWS`.

## Execution Artifacts: Amcache, Shimcache, Prefetch `#WindowsForensics` {#execution-artifacts}

These three agents are documented together because they're designed to be
**cross-referenced against each other**, not read in isolation.

- **Amcache_Analyzer** parses AmcacheParser CSV output. Flags: claims to be
  a Microsoft product but isn't marked as an OS component, or has an
  implausibly-recent compile date relative to its last-write time.
- **Shimcache_Analyzer** parses AppCompatCacheParser output — note this
  lives under the `Registry` category folder, not its own. The "Executed"
  flag Shimcache reports is explicitly treated as *corroborating*, not
  primary evidence — Shimcache's Executed bit is unreliable on several
  Windows versions, and the agent's own prompt says so; presence + path is
  the real signal.
- **Prefetch_Analyzer** parses PECmd output: run count, last execution
  time, volume serial, resolved full path.

### Why cross-referencing matters {#execution-artifacts-cross-reference}

The Father Agent diffs these three sources by executable name and surfaces
**"Amcache entries without a matching Prefetch entry"** and vice versa —
this is the actual point of collecting all three. Prefetch has a rolling
~1024-slot window that ages out old entries (or gets deliberately cleared);
an executable that shows up in Amcache but never in Prefetch is a real
signal that execution evidence was lost or removed.

![Cross-reference finding showing an Amcache entry with no matching Prefetch record](placeholder-execution-artifacts-crossref.png)
*Figure 1: A finding titled "Amcache entry without matching Prefetch record: suspicious_updater.exe" — the actual value-add of running all three agents together.*

---

## EVTX & Sysmon Correlator `#WindowsForensics` {#evtx-sysmon-correlator}

Streams every `.evtx` file under the Logs category, but only ever looks at
a **fixed allow-list of (provider, EventID) pairs** — not "every EventID
1", since the same EventID number means different things for different
providers:

| Provider | EventID | Meaning |
|---|---|---|
| Sysmon | 1 | Process Creation |
| Sysmon | 3 | Network Connection |
| Sysmon | 5 | Process Terminated |
| Sysmon | 11 | File Created |
| Service Control Manager | 7045 | Service Installed |
| Security-Auditing | 4624 / 4625 | Logon Success / Failure |
| PowerShell | 4104 | Script Block Logging |

Everything outside this list is dropped before it ever reaches the LLM
(capped at 300 events per file, 400 total) — this keeps the signal dense,
but also means an event type not on this list will never surface here, no
matter how relevant it might be to your specific case.

> ℹ️ **Info:** If you need an event type not on this list (e.g. Sysmon
> Event ID 7 — Image Loaded), it won't be picked up by this agent today.
> Review the raw `.evtx` directly for anything outside the allow-list.

---

## Registry Hive Miner `#WindowsForensics` {#registry-hive-miner}

Opens raw hive files directly (no external parser dependency). Extracts
four persistence categories, each mapped to a MITRE ATT&CK technique:

- Run/RunOnce keys (both native and Wow6432Node) → **T1547.001**
- Winlogon Shell/Userinit/Notify → **T1547.004**
- AppInit_DLLs (both paths) → **T1546.010**
- Service ImagePath/Start, SYSTEM hive only (resolves the live
  `ControlSet` via `Select\Current`, since `CurrentControlSet` is a
  live-registry symlink that doesn't exist in an offline hive file) →
  **T1543.003**

![Registry Hive Miner finding showing a Run key value mapped to T1547.001](placeholder-registry-miner.png)
*Figure 2: A Run-key persistence finding with `mitre_technique: T1547.001` visible in its raw data view.*

---

## Timeline Anomaly Detector `#WindowsForensics` {#timeline-anomaly-detector}

The most complex agent in this module. Reads Plaso super-timeline exports
(`l2tcsv`, `psort` JSON-line, or a Plaso storage file/SQLite export) plus
MFTECmd CSV output, and runs three independent signal generators:

1. **Timestomping detection** — compares `$STANDARD_INFORMATION` vs.
   `$FILE_NAME` MFT creation timestamps; a discrepancy over 60 seconds is
   flagged.
2. **Log clearing / anti-forensic tool detection** — EventID 1102/104
   (log clear events), plus Prefetch evidence of
   `vssadmin.exe`/`wevtutil.exe`/`wbadmin.exe`/`cipher.exe`/`sdelete.exe`/
   `bcdedit.exe`/`fsutil.exe` execution, plus EVTX command-line pattern
   matches for shadow-copy deletion, `cipher /w`, BCD tampering, and USN
   journal deletion.
3. **Staging cluster detection** — flags an archive file
   (`.zip`/`.rar`/`.7z`/`.iso`/`.cab`/`.gz`/`.tar`) created within 120
   seconds of 3+ other files landing in the same directory — a classic
   "stage then exfiltrate" pattern, detected by reusing file-inventory CSVs
   the malware-path agents already wrote (no re-parsing needed).

Rather than sending an entire super-timeline to the LLM, the agent pivots on
every high-signal timestamp it finds (a log clear, a timestomped file, an
anti-forensic tool run) and slices a ±15-minute window around each. If none
of the above triggers, it falls back to a sliding-window density scan to
find the busiest 15-minute window in the timeline instead.

> ⚠️ **Warning — this agent's timeline/MFT parsing was not independently
> verified end-to-end in a live environment during development** (reading
> a live MFT needs SeBackupPrivilege/administrator rights, and the `plaso`
> package wasn't installable in the development sandbox — the parser falls
> back to a best-effort flattened-table read for non-CSV Plaso exports, and
> MFTECmd's column names are fuzzy-matched rather than hardcoded). If this
> agent's output looks empty or wrong on your data, check the raw
> `Timeline/raw/` and `MFT/metadata/` files are in a format it actually
> recognizes before assuming your host has no timeline anomalies.

![Timeline Anomaly Detector finding showing a staging-cluster detection around a zip file](placeholder-timeline-staging-cluster.png)
*Figure 3: A "Staging Cluster Detected" finding: `exfil_data.zip created 14:32:07, alongside 7 other files created within 90 seconds in the same directory.`*

---

## Common Malware Paths `#MalwareTriage` {#common-malware-paths}

Eight thin, focused agents — each inventories one high-risk location (full
file metadata: timestamps, MD5/SHA256, Authenticode signature status)
rather than doing deep analysis itself; deep analysis of anything
suspicious found here happens downstream in File/Malware Analysis.

| Agent | Category folder | What it looks at |
|---|---|---|
| Temp_Folder_Analyzer | `TempFolder` | Full inventory of the Temp directory |
| Downloads_Folder_Analyzer | `Downloads` | Full inventory; specifically calls out double-extension files (`invoice.pdf.exe`) and Mark-of-the-Web-bypass ISO/IMG files |
| AppData_Public_Paths_Analyzer | `CommonMalwarePaths` | Top-level files only in AppData/Public — subfolders noted by name, not opened |
| ProgramData_Analyzer | `ProgramDataList` | Metadata manifest only — **does not see** binaries that Memory Analysis or Reverse Engineering staged into this same folder for their own downstream use |
| Scheduled_Tasks_Analyzer | `SysinternalsAutoruns` (filtered) | Scheduled task entries only |
| Services_Analyzer | `SysinternalsAutoruns` (filtered) | Service entries only |
| Drivers_Analyzer | `SysinternalsAutoruns` (filtered) | Kernel driver entries (BYOVD hunting) |
| Autoruns_Analyzer | `SysinternalsAutoruns` (unfiltered) | Everything else: Run/RunOnce, Logon items, Startup folder, browser extensions, LOLBins |

> ℹ️ **Info:** The last four agents all read the *same* Autoruns export,
> each just filtering by keyword against different columns — this is why
> you'll see very similar-looking findings from four different agent names
> if Autoruns flagged something that matches multiple categories.

![Downloads Folder Analyzer finding flagging a double-extension file](placeholder-downloads-double-extension.png)
*Figure 4: A Downloads Folder finding: `invoice_Q3_2026.pdf.exe` flagged for a double extension masquerading as a PDF.*
