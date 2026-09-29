# System Management & Administration `#ExclusionRules #AgentConfiguration #AccessControl`

The System Management area (`/management`) is **admin-role only**. If you
land on a "Admin access required" page, your account is `analyst` or
`viewer` — ask an admin to change your role from the Access Control tab.

![System Management page with the left sidebar showing all five category groups](placeholder-management-overview.png)
*Figure 1: The Management page's left navigation — Rule & Detection Management, AI & Agent Orchestration, Data Lifecycle & Retention, and Auditability & Access Control.*

---

## Exclusion Engine Configuration `#ExclusionRules` {#exclusion-engine-configuration}

### Where exclusion evaluation actually happens {#exclusion-evaluation-point}

This matters for understanding what exclusion rules can and can't do:
findings on this platform are **recomputed fresh from live agent state on
every page load**, not stored in a database table. So there's no "insert
pipeline" to filter — exclusion rules are evaluated once per finding, every
time the Findings page (or its API) is queried, against a rule set compiled
once and cached in memory (recompiled only when you change a rule, not on
every 2-second poll the Findings page does).

### Rule types and what they actually match against {#exclusion-rule-types}

| Type | Matches against |
|---|---|
| File Hash | Best-effort text search across the finding's filepath + anomaly type + justification |
| File Name/Path | The finding's actual filepath field, exact/glob/regex |
| IP Address (+ CIDR) | Text search for IP-shaped tokens in filepath/justification; CIDR mode parses and checks network containment |
| Domain Name | Text search, same fields |
| Port | Text search with word-boundary matching (avoids "444" matching inside "4444") |
| Process Name / PID / PPID | Text search, same fields, word-boundary for numeric types |
| Finding Category | **Exact structured match** — by source agent and/or minimum severity |

> ⚠️ **Warning — read this before assuming "exact match."** Findings on
> this platform only carry a generic shape (filepath, anomaly type,
> justification, severity) — there's no structured PID/hash/IP field
> attached to a generic finding. Every rule type except **File Name/Path**
> and **Finding Category** is a best-effort *text search* across whatever
> free-text fields the finding has, not a guaranteed structured-field
> comparison. This is genuinely useful in practice (most exclusion targets
> — known-good hashes, known-good paths — do show up in that text), but a
> hash rule won't match a finding that mentions the hash nowhere in its
> visible text.

### Step-by-step: creating a rule {#exclusion-rule-steps}

1. Click **+ Add Rule**.
2. Choose a rule type. If you pick "Finding Category," the pattern field
   hides and an agent/severity filter appears instead.
3. Choose a pattern mode (Exact/Glob/Regex, or CIDR for IP rules).
4. **Test before saving**: paste a real sample value into the "Test before
   saving" field and click Test — this runs the exact same matcher your
   rule would use, without writing anything to the database. Always do
   this before saving a glob/regex rule; a too-broad pattern (`*.exe`) can
   silently suppress real findings with no other feedback.
5. Choose the matching action (see below) and write a reason — required,
   shows up in the audit trail and on the finding itself.
6. Optionally set an expiration date.

![Add Exclusion Rule drawer with the test-before-saving field showing a match result](placeholder-exclusion-rule-drawer.png)
*Figure 2: The Add Exclusion Rule drawer — File Path type, glob mode, pattern `*\Windows\System32\svchost.exe`, test result showing "✓ Matches" against a sample value.*

### Exclusion Actions: "Hide Completely" vs. "Mark as Excluded" {#exclusion-actions}

- **Mark as excluded**: the finding is hidden from the default Findings
  view but remains fully auditable — visible via the "Show excluded"
  toggle, tagged with which rule suppressed it and why. Use this for
  almost everything; it's reversible and doesn't hide evidence.
- **Hide completely**: the finding never appears in any view, ever, for as
  long as the rule is active. There's no "show hidden" override. Use this
  sparingly and only for things you're certain are pure noise (e.g. a
  testing artifact from your own tooling) — not for "probably benign"
  findings, where "mark as excluded" preserves the audit trail.

The **exclusion impact** count shown next to each rule (e.g. "Suppressing
14 findings") is computed live against the current investigation's
findings — use it to sanity-check that a new rule isn't suppressing far
more than you expected.

### Baseline / Golden-Image Whitelisting {#baseline-whitelisting}

A dedicated sub-tab for bulk-importing known-good file hashes (e.g. from a
clean reference image's hash manifest) as exclusion rules in one action,
rather than one at a time.

### Step-by-step {#baseline-import-steps}

1. Go to **Baseline / Golden-Image Whitelisting**.
2. Click **+ Import Hash List**.
3. Paste one hash per line (MD5/SHA1/SHA256 — mixed lengths are fine, each
   becomes its own rule).
4. Give a shared reason (defaults to "Golden-image baseline import").
5. Submit — each hash becomes its own "Mark as excluded" file-hash rule, all
   visible and individually toggleable/deletable on this same tab.

![Baseline Import modal with a pasted list of golden-image hashes](placeholder-baseline-import.png)
*Figure 3: The baseline import textarea with a dozen pasted SHA-256 hashes and the reason field set to "Windows 11 23H2 golden image, build 2026-06."*

---

## YARA & Sigma Rules `#AgentConfiguration #MalwareTriage` {#yara-rules}

### YARA — fully wired into the pipeline {#yara-rules-detail}

Rules you add here are **actually executed**, not just catalogued: every
active rule runs against every raw evidence file during the File Analysis
pipeline's Static Triage pass (see
[File & Malware Analysis](04-file-malware-analysis.md#static-triage-yara)), and a
match becomes a real finding.

### Step-by-step {#yara-rule-steps}

1. Click **+ Add YARA Rule**.
2. Write standard YARA syntax. Set a `severity` meta field
   (`Critical`/`High`/`Medium`/`Low`) if you want matches to carry a
   specific severity — defaults to High if omitted.
3. Save. **The rule is compile-validated immediately** — a syntax error is
   rejected on save with the exact YARA compiler error message, it never
   gets silently stored broken.
4. Toggle a rule's Active checkbox to disable it without deleting it.

```yara
rule known_ransomware_note_dropper {
    meta:
        severity = "Critical"
        description = "Matches a known ransom-note template string"
    strings:
        $a = "Your files have been encrypted" nocase
        $b = ".onion"
    condition:
        $a and $b
}
```

![YARA rule editor drawer with a rule pasted in and a compile error shown](placeholder-yara-editor.png)
*Figure 4: The Add YARA Rule drawer showing a red compile-error banner after submitting a rule with a missing `condition:` block.*

> 🔧 **Troubleshooting:** If an active rule stops matching anything and you
> suspect it broke, check the rule's row in the table — a rule that fails
> to recompile (e.g. after an edit) shows its last compile error inline
> instead of silently dropping out. One broken rule never takes down
> scanning for every other active rule.

### Sigma — executed against every EVTX/Sysmon event {#sigma-rules}

Rules you add here **are actually evaluated** against every event the
EVTX/Sysmon Correlator extracts, and a match becomes a real finding titled
"Sigma Match: <rule name>" — same pattern as YARA above.

> ⚠️ **Warning — this is a real but scoped subset of the Sigma spec, not
> the full language.** Supported: named `selection`/`filter` blocks (dict =
> AND across fields, list of dicts = OR), field modifiers
> `|contains`/`|startswith`/`|endswith`/`|re`, value lists (OR), and a
> `condition` string combining block names with `and`/`or`/`not`/parens
> plus `1 of x*`/`all of x*` quantifiers. **Not supported**: aggregation
> functions (`count()`, `near`, timeframes) or field-to-field comparisons —
> a rule using those constructs will compile and save, but will simply
> never match here. Test with a real sample event's fields (JSON) before
> trusting a rule in production.

```yaml
title: Suspicious PowerShell EncodedCommand
detection:
  selection:
    Image|endswith: 'powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  filter:
    ParentImage|endswith: 'explorer.exe'
  condition: selection and not filter
```

### Step-by-step: testing a Sigma rule before saving {#sigma-rule-test-steps}

1. In the Add Sigma Rule drawer, paste sample event field values as JSON
   into the "Test before saving" box (e.g.
   `{"Image": "powershell.exe", "CommandLine": "-EncodedCommand ..."}`).
2. Click **Test** — runs the exact same evaluator your rule would use at
   runtime, without saving anything.
3. Save once it matches what you expect.

Rules are also validated as well-formed YAML with a top-level `detection`
block on save — a syntax error or missing `detection` block is rejected
immediately, not stored broken.

---

## LLM Provider Configuration `#AgentConfiguration` {#llm-provider-configuration}

Every agent's analysis step, and the Findings page's "Deep Analyze"
enrichment, read this single configuration.

### Step-by-step {#llm-config-steps}

1. Go to **AI & Agent Orchestration → LLM Provider Configuration**.
2. Set **Base URL** to any OpenAI-compatible chat completions endpoint.
   Defaults to a local Ollama instance (`http://localhost:11434/v1`) —
   this platform is designed to run with **zero external network access**
   by default.
3. Set **Model name** to whatever model that endpoint serves (e.g.
   `llama3.1`, or a hosted model name if you're pointing at a cloud
   provider instead).
4. **API key** — leave blank to keep the current key. Local Ollama accepts
   any placeholder value here; a real cloud provider needs a real key.
5. **Context limit** — the character cap applied to payloads sent to the
   LLM (agent-side truncation, not a token-accurate count).
6. Save.

![LLM Provider Configuration form filled in for a local Ollama endpoint](placeholder-llm-config.png)
*Figure 5: The LLM Provider Configuration form — Base URL `http://localhost:11434/v1`, model `llama3.1:8b`.*

> ℹ️ **Info:** There is exactly **one** active provider configuration at a
> time — no per-agent overrides, and no automatic fallback chain between
> multiple providers. If the configured endpoint is unreachable, every
> agent's LLM analysis step fails the same way (degrades to an error
> result, logged, doesn't crash the run).

> ⚠️ **Warning — this only configures the LLM.** Ghidra, CAPA, and Cuckoo
> are separate MCP tool servers with their own environment-variable
> configuration (`GHIDRA_MCP_*`, `CAPA_MCP_*`, `CUCKOO_MCP_*`) — there is no
> Management-page UI for those yet. See
> [File & Malware Analysis](04-file-malware-analysis.md#malware-overview).

### Individual agent system-prompt overrides {#agent-prompt-overrides}

The Agent Control Center page (`/agents`) has a "System Prompt Override"
box per agent, with a Save button.

> ℹ️ **Info — this affects the *next* run, not one already in progress.**
> Saving an override here changes what `BaseHITLAgent` builds as that
> agent's system prompt from the next time it's constructed (i.e. the next
> investigation, or the next re-run of that agent) — an agent instance
> that's already mid-analysis when you save doesn't retroactively pick it
> up. Leave the box empty to fall back to the agent's default prompt.

---

## Data Lifecycle & Retention {#data-lifecycle-and-retention}

### Step-by-step: checking storage usage {#retention-storage-steps}

1. Go to **Data Lifecycle & Retention**.
2. Three summary cards show total size and file count for Memory Dumps,
   PCAPs, and General Evidence — bucketed by file extension across
   *every* investigation staging folder on disk, not just the active one.
3. The table below breaks the same data down per investigation folder.

![Retention page showing the three storage summary cards and per-investigation table](placeholder-retention-summary.png)
*Figure 6: Storage summary cards reading "Memory Dumps: 2.1 GB (3 files)", "PCAPs: 0 B (0 files)", "General Evidence: 14.8 GB (2,140 files)."*

### Step-by-step: running a retention sweep {#retention-sweep-steps}

1. Set a policy for a category — max age in days, and/or a max total size
   in GB — optionally check **Auto-flag violations**, and click **Save
   policy**.
2. Click **Run Sweep Preview** (or wait for the automatic check — see
   below). This is always a **dry run**: it lists every file that violates
   the policy (too old, or oldest-first once the category exceeds its size
   quota) without touching anything.
3. Review the list — every candidate shows its full path, size, age, and
   why it was flagged. Uncheck anything you want to keep.
4. Click **Delete Selected** and confirm. Only the files you explicitly
   confirmed are deleted.

![Sweep Preview modal listing candidate files with checkboxes](placeholder-sweep-preview.png)
*Figure 7: The Sweep Preview modal — five candidate files listed, each with its age and the specific policy it violated, three checked for deletion.*

### "Auto-flag violations" — automatic detection, never automatic deletion {#auto-flag-violations}

Checking this box for a category starts a real background check (every ~10
minutes) that runs the same preview logic automatically and logs a warning
— visible in the live log terminal and the global audit log below — the
moment that category newly violates its policy.

> ✅ **Best Practice:** There is **no unattended background deletion** on
> this platform, by design. "Auto-flag" means exactly that — automatic
> *detection and notification*, not automatic cleanup. Every deletion still
> requires an analyst to open the Sweep Preview and explicitly confirm,
> regardless of whether auto-flag is on. Deleting forensic evidence
> unattended is a meaningfully riskier feature than noticing a policy
> violation automatically, and this platform deliberately only builds the
> latter.

---

## Audit Logs & Access Control `#AccessControl` {#audit-logs-and-access-control}

### Global audit log {#global-audit-log}

Unions per-finding audit history (dismiss/restore/assign/tag/enrich/
comment) with platform-wide pipeline events (investigation start/stop,
mode changes, exclusion rule changes, retention sweeps), most recent first.

![Global audit log table showing a mix of finding-level and pipeline-level events](placeholder-global-audit-log.png)
*Figure 8: The audit log table interleaving `admin dismissed finding derived-24735a...: "confirmed benign"` with `MANAGEMENT WARN: Exclusion rule created (file_path: svchost.exe) by admin`.*

### User management and roles {#user-management}

Three roles exist: **admin** (full System Management access), **analyst**,
and **viewer**.

> ℹ️ **Info:** `viewer` is enforced globally, not per-route — any
> state-changing request (POST/PUT/PATCH/DELETE) from a `viewer` account is
> rejected except changing their own password, signing out, and exporting
> a report (a read-only download despite being a POST). The Findings page
> also hides its two most prominent mutating controls (Add Manual Finding,
> the bulk action bar) for `viewer` accounts. A few secondary per-row
> controls elsewhere in the UI may still render for a `viewer` account
> even though the backend will reject the action if clicked — that's a
> UI-polish gap, not a security one.

### Step-by-step: creating and managing users {#user-management-steps}

1. Go to **Auditability & Access Control**.
2. Click **+ Create User**, set a username, a temporary password (8+
   characters), and a role. The new user is required to set their own
   password on first sign-in.
3. Change a user's role anytime via the dropdown in their row — takes
   effect immediately.
4. **Reset password** prompts for a new temporary password and re-flags
   that account for a forced change on next login.
5. You cannot delete your own account from this page (prevents accidental
   admin lockout).

![Create User modal and the resulting row in the users table with a forced-password-change badge](placeholder-create-user.png)
*Figure 9: The Create User modal, and the resulting table row showing "Password reset pending" for the new account.*

> ℹ️ **Info — first-run default account.** A fresh install seeds one
> account: username `admin`, password `changeme`, forced to change it
> immediately on first login. Sessions are server-side and don't currently
> expire on their own — sign out explicitly (top-right of the navbar) on a
> shared machine.
