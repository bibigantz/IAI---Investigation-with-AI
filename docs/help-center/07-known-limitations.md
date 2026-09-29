# Known Limitations & Honest Caveats

Every one of these is called out inline in its relevant module too — this
page exists so a new analyst (or a new admin) can read one list before
trusting the platform to do something it doesn't actually do. Most of the
items originally on this list have since been fixed for real (see below) —
what's left is either a deliberate safety choice or a genuine dependency on
infrastructure this codebase can't manufacture on its own.

## Fixed since this page was first written {#fixed-items}

- **Agent System Prompt Override** (`/agents` page) now actually works.
  `BaseHITLAgent.__init__` reads `bridge.prompt_overrides` and uses it in
  place of the agent's default system prompt if one is set. Saving an
  override here changes what the agent is told on its *next* run (not
  retroactively — a run already in progress keeps the prompt it started
  with).
- **Sigma rules now execute for real** against every event the EVTX/Sysmon
  Correlator extracts — see `core/sigma_engine.py`. Scope is stated
  precisely there and in
  [System Management](06-system-management.md#sigma-rules): named
  selection/filter blocks, `|contains`/`|startswith`/`|endswith`/`|re`
  modifiers, value lists (OR), and conditions combining block names with
  `and`/`or`/`not`/parens plus `1 of x*`/`all of x*`. **Not** supported:
  aggregation functions (`count()`, `near`, timeframes) or field-to-field
  comparisons — a rule using those will simply never match here. This is a
  real, useful subset, not the full Sigma spec — don't assume a rule that
  works in a full Sigma toolchain will behave identically here.
- **Ghidra rename suggestions now attempt a real write-back.** After HITL
  approval, `reverse_engineering.py` calls a `rename_function` MCP tool on
  the configured Ghidra server for every suggested rename. This closes the
  "nothing writes it back" gap — but it still needs an actual Ghidra MCP
  server that exposes that tool; without one, it degrades to a logged
  `WARN` (same contract as every other MCP call in this codebase), so it
  moves from "things that look like they'd work but don't" to "depends on
  external infrastructure" below, not all the way to "fully bundled."
- **The retention "auto-flag" toggle now does something automatic.** A
  background checker (`core/retention_scheduler.py`) runs every 10 minutes
  and logs a warning the moment a category with the toggle enabled
  violates its policy. **Deletion is still never automatic** — that's a
  deliberate safety choice, not something this fix was meant to override.
  Turning the toggle on means "notice and tell me," not "clean up
  unattended." (The Management page's retention form was also missing the
  checkbox to actually turn this on in the first place — added alongside
  the fix.)
- **`viewer` role is now genuinely read-only**, enforced globally in
  `web/auth.py`'s request gate rather than per-route: any non-GET request
  from a `viewer` account is rejected except the account-management flows
  every role needs (change password, sign out) and report export (a
  read-only download despite being a POST). The Findings page also hides
  its two most prominent mutating controls (Add Manual Finding, the bulk
  action bar) for `viewer` accounts — a few secondary per-row controls may
  still be visible and clickable, but the backend blocks them regardless,
  so there's no actual security gap even where the UI hasn't been fully
  polished yet.
- **Memory-dump uploader landed files in the wrong folder** (fixed in an
  earlier pass): the Launch Hub's Memory Analysis uploader tagged files
  `category=Logs`; Volatility only ever looks in `MemoryDumps/raw/`. Fixed
  in `static/js/app.js`, verified against `volatility_runner.py`.
- **`README.md`/`ARCHITECTURE.md` stale claims** ("no authentication on any
  route," a hardcoded API key) — both were already fixed by earlier work
  this session; the docs are now updated to match.

## Things that depend on infrastructure this platform doesn't bundle {#things-that-need-external-infra}

These aren't bugs to fix in this codebase — they need something outside it
that this platform deliberately doesn't try to stand up itself.

- **Ghidra decompilation, CAPA capability mapping, Cuckoo sandbox
  execution, and now Ghidra rename write-back** — all real MCP calls, all
  silently degrade to an empty result / a logged `WARN` if their
  respective server isn't configured (`GHIDRA_MCP_*`/`CAPA_MCP_*`/
  `CUCKOO_MCP_*` environment variables). The agent still runs and reports
  "0 findings" rather than erroring, which can look identical to
  "genuinely clean." See
  [File & Malware Analysis](04-file-malware-analysis.md#malware-overview).
- **LLM analysis** — every agent's analysis step, and Findings-page Deep
  Enrichment, depend on the single LLM endpoint configured on the
  Management page (defaults to a local Open WebUI instance). If it's
  unreachable, every agent's LLM step fails the same way — use that page's
  **Test Connection** button to check reachability before assuming
  something else is broken.
- **"Query SIEM" pivot link** — only appears if `SIEM_QUERY_URL_TEMPLATE`
  is set. No bundled SIEM integration exists, and none is planned per this
  deployment's offline-environment requirement.
- **MISP export** — produces a MISP-shaped JSON file for manual import.
  There is no live push to a running MISP instance, and none is planned
  (explicitly out of scope for this platform's offline deployment target).
- **The Gemini / Google AI Studio preset on the LLM Provider Configuration
  page is a deliberate, explicit exception to "offline by default"** — it
  exists purely so you can test agent behavior against a known-good cloud
  model while you have connectivity, not for real engagement work. Selecting
  it shows an inline warning; it isn't hidden or silently allowed.

## Things that are best-effort, not exact — and why they'd need a bigger change to fix {#things-that-are-best-effort}

- **Exclusion rules** — only File Name/Path and Finding Category match a
  real structured field; every other rule type is a text search across a
  finding's free-text fields, because findings don't carry structured
  PID/hash/IP fields today. Actually fixing this would mean adding
  structured indicator fields to the shared finding shape and threading
  them through every leaf agent's anomaly construction (~20 files) — a
  real architectural change, not a patch, and deferred rather than done
  partially/shallowly. See
  [System Management](06-system-management.md#exclusion-rule-types).
- **PII redaction on report export** — a regex-based best-effort scrub
  (usernames in file paths, email addresses). This is inherent to a
  regex-based approach, not a bug to chase — a guaranteed-complete
  redaction would need an actual NER model, which is a different feature,
  not a fix to this one. Review before sharing externally.
- **Timeline Anomaly Detector's timeline/MFT parsing** — not independently
  verified end-to-end against a live MFT or a real `plaso` install
  (reading a live MFT needs administrator/SeBackupPrivilege; `plaso`
  wasn't installable in the development sandbox either). This remains an
  environment constraint, not a code limitation — nothing to "fix" from
  inside this codebase alone. See
  [Windows Forensics](03-windows-forensics.md#timeline-anomaly-detector).
- **SSDEEP fuzzy hashing** — degrades to `null` if the native `libfuzzy`
  library isn't installed. Confirmed genuinely environment-dependent:
  `pip install ssdeep` fails outright in this development environment
  (needs a native build toolchain plus `libfuzzy`, not just a Python
  package). Expected in most environments, not a bug to chase further.

## Platform-wide architectural notes worth knowing {#platform-wide-notes}

- **Only two orchestration levels run sub-agents concurrently** (Memory
  Analysis stage 2, File Analysis stage 2) — every other father/sub-master
  level runs its children strictly sequentially. In SUPERVISED mode, that
  means each approval click is a real serialization point for most of the
  agent tree.
- **`bridge` state is in-memory and single-process.** A crash or an
  in-place restart loses any pending HITL approval (the live
  `asyncio.Event` it was waiting on is gone). Completed agent
  states/topology/logs get a best-effort JSON snapshot per investigation,
  but that write path has no corruption check beyond "did `json.load`
  succeed" — a truncated write falls back to a full reset with no error
  surfaced to the analyst.
- **Sessions don't expire.** There's no idle timeout on a logged-in
  session; sign out explicitly on a shared machine.
- **The Help Center's rendered content is cached in-process** after first
  request (`core/help_content.py`'s `@lru_cache`) — editing a `.md` file
  under `docs/help-center/` needs a server restart or an explicit
  `help_content.reload_content()` call to show up, it won't refresh
  automatically per request.
- **If a hardcoded API key literal was ever committed to git history**
  before this session's fixes, removing it from the current file doesn't
  remove it from history — rotating that key (if it was ever real/live)
  and considering a history rewrite is a separate, deliberate decision,
  not something to do silently as part of a documentation pass.
