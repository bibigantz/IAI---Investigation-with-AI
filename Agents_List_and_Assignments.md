### 1. Windows Forensics Father Agent

*(Adapted from our previous disk forensics list, specialized for Windows environments)*

This agent orchestrates the `Autopsy MCP` and `Plaso MCP` to reconstruct the filesystem and timeline of a Windows host.

* **The Disk Mounter & Triage Automaton (Pure Automation):**
  * **Purpose:** Ingests raw `.E01` or `.raw` images, parses the MBR, reconstructs the NTFS file system, and handles the initial I/O bottleneck.
  * **Making it:** A Python script utilizing `pytsk3` or the Autopsy REST API. It calculates evidence hashes and outputs a JSON tree of the file system.
  * **Developer Owner:** [ N ]

* **Execution Artifacts Analyzer (Automation → LLM Agent):**
  * **Purpose:** Parses Prefetch, Amcache, and Shimcache to answer what executed, when, and from where.
  * **Making it:** Use Eric Zimmerman’s tools (e.g., `PECmd`, `AmcacheParser`) to parse raw files into CSV/JSON. The LLM then evaluates the Pydantic models for anomalies (e.g., `SVCHOST.EXE` executing from a user directory).
  * **Developer Owner:** [ G ]

* **Execution Most Common Malware Paths Analyzer (Automation → LLM Agent):**
  * **Purpose:** Lists paths like downloads, temp, appdata and more.
  * **Making it:** List all information about the files in those paths and parse raw files into CSV/JSON. The LLM then evaluates the Pydantic models for anomalies (e.g., `SVCHOST.EXE` executing from a user directory).
  * **Developer Owner:** [ Y ]

* **EVTX & Sysmon Correlator (Automation → LLM Agent):**
  * **Purpose:** Reconstructs the timeline of system events, focusing heavily on Sysmon logs for process creation (Event ID 1), network connections (Event ID 3), and file creation.
  * **Making it:** `python-evtx` parses the logs. An aggressive pre-filter drops standard OS noise. The LLM analyzes the high-value JSON output to identify chained attack sequences like RDP brute-forcing or lateral movement.
  * **Developer Owner:** [ Y ]

* **Registry Hive Miner (Hybrid):**
  * **Purpose:** Extracts SYSTEM, SOFTWARE, and NTUSER.DAT hives to find persistence mechanisms.
  * **Making it:** Automate `RegRipper` to pull specific keys (Run keys, services). The LLM evaluates if the configured paths match known benign software or MITRE ATT&CK persistence techniques.
  * **Developer Owner:** [ Y ]

* **Super Timeline Anomaly Detector (LLM Agent):**
  * **Purpose:** Looks at the entire disk activity window to spot evasion, time-stomping, or hidden data.
  * **Making it:** `Plaso MCP` generates a `log2timeline` output. The LLM Agent, given a specific time window, analyzes this structured timeline for anomalies.
  * **Developer Owner:** [ Y ]

---

### 2. Linux Forensics Father Agent - PENDING LATER

Linux requires a fundamentally different parsing approach, focusing on text-based configurations, logs, and ELF binaries rather than registry hives or EVTX files.

* **Log & Auth Tracker (Pure Automation → LLM Agent):**
  * **Purpose:** Parses `/var/log/auth.log`, `syslog`, `secure`, and `.bash_history` to track user logins, `sudo` usage, and executed commands.
  * **Making it:** Automation uses regex to parse these text files into structured JSON chronologically. The LLM reviews the commands for obfuscation (e.g., base64 encoded bash commands) or unauthorized key additions in `.ssh/authorized_keys`.
  * **Developer Owner:** [ ]

* **Persistence & Rootkit Hunter (Hybrid):**
  * **Purpose:** Scans for common Linux persistence mechanisms and user-mode rootkits.
  * **Making it:** Automation scripts collect data from `cron` jobs, `systemd` service files, and environment variables like `LD_PRELOAD`. The LLM Agent evaluates these configurations to see if they are loading malicious shared objects or establishing reverse shells.
  * **Developer Owner:** [ ]

* **Web Shell & Permissions Analyzer (Pure Automation):**
  * **Purpose:** Identifies malicious scripts dropped into web directories or anomalous file permissions.
  * **Making it:** Pure automation running optimized `find` commands to locate `setuid`/`setgid` binaries, unowned files, and newly created `.php` or `.jsp` files in web server roots (`/var/www/html`). Outputs a structured list of flagged files for the Father Agent to potentially route to the File Analysis agent.
  * **Developer Owner:** [ ]

---

### 3. Memory Analysis Father Agent

This agent orchestrates the `Volatility3 MCP` to parse volatile memory captures (`.raw`, `.dmp`) and uncover active threats that never touch the disk.

* **Process & Thread Mapper (Automation → LLM Agent):**
  * **Purpose:** Reconstructs the active process tree and identifies hidden or unlinked processes.
  * **Making it:** Automation runs Volatility plugins like `windows.pslist` and `windows.psxview`. The LLM analyzes the discrepancies between the two tools to flag processes attempting to hide from the OS.
  * **Developer Owner:** [ G ]

* **Injected Code Analyzer (Hybrid):**
  * **Purpose:** Locates and extracts injected, unbacked executable memory pages (e.g., reflective DLL injection, hollowed processes).
  * **Making it:** Automation runs `windows.malfind` and dumps the flagged memory regions to a staging directory. The LLM reviews the output metadata, but the actual dumped payloads are typically routed to the Malware Analysis Agent for deeper inspection.
  * **Developer Owner:** [ G ]

* **Network Socket Correlator (Pure Automation):**
  * **Purpose:** Extracts active and recently closed network connections from memory.
  * **Making it:** Automation runs `windows.netscan`. It cross-references the PIDs holding open sockets with known malicious IPs/Ports and outputs a structured Pydantic model of active connections for the Father Agent to use.
  * **Developer Owner:** [ G ]

* **MALFIND Correlator (Pure Automation):**
  * **Developer Owner:** [ G ]

---

### 4. File / Malware Analysis Father Agent

This agent handles isolated suspicious files (`.exe`, `.elf`, documents). It heavily relies on the `Ghidra MCP`, `CAPA MCP`, and `Cuckoo v3 MCP`.

* **Static Triage & Capability Mapper (Pure Automation):**
  * **Purpose:** Performs rapid static analysis to identify what the malware is capable of doing without executing it.
  * **Making it:** Automation calculates hashes (SSDEEP, ImpHash) and runs the CAPA MCP. It outputs a structured JSON mapping the file's capabilities directly to the MITRE ATT&CK matrix.
  * **Developer Owner:** [ N ]

* **Reverse Engineering & String Analyzer (Automation → LLM Agent):**
  * **Purpose:** Dissects the binary's code structure to understand specific logic (e.g., decoding C2 domains, encryption routines).
  * **Making it:** The `Ghidra MCP` performs headless auto-analysis, extracting import/export tables and strings. The LLM Agent is fed decompiled pseudo-code of specific, high-entropy functions and is prompted to explain the programmatic intent.
  * **Developer Owner:** [ N ]

* **Dynamic Sandbox NOT IN THIS PROJECT (Hybrid):**
---

**References:**
* https://share.gemini.google/XHvVN3cCSgbw

      
      [ Raw Image / Dump ] 
               │
               ▼
       ┌──────────────────────────────────────────────┐
       │       Forensic Collector Agent               │
       │  (Runs Traverser, Extractor, & Hasher)      │
       └──────────────────────┬───────────────────────┘
                              │
                              ▼ (Populates)
       ┌──────────────────────────────────────────────┐
       │         Structured Staging Folder            │  ◄── Easy for other agents to read!
       │  (Logs, Registry Hives, Prefetch, Binaries)  │
       └──────────────────────┬───────────────────────┘
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
      ┌──────────────────┐          ┌──────────────────┐
      │ Windows Forensics│          │ Malware Analysis │
      │   Father Agent   │          │   Father Agent   │
      └──────────────────┘          └──────────────────┘
