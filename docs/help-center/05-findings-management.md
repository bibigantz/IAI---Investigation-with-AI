# Findings Management `#IOCs`

The Findings page (`/findings`) is the main triage surface: every anomaly
from every agent across the current investigation, aggregated, deduplicated,
and actionable. Nothing here is a separate database table you insert into —
the list is recomputed fresh from live agent state on every load, with a
persisted "overlay" (status, tags, assignment, confidence, comments) layered
on top so your triage work survives.

![Findings page with the bulk action bar visible after selecting three findings](placeholder-findings-overview.png)
*Figure 1: The Findings page with severity filter chips, the "Show dismissed"/"Show excluded" toggles, and the bulk action bar that appears once you select one or more findings.*

---

## Saving Findings as IOCs `#IOCs` {#saving-findings-as-iocs}

### Step-by-step {#save-as-ioc-steps}

1. Check the box on one or more findings (or open a single finding's detail
   drawer).
2. Click **Save as IOC** in the bulk action bar.
3. Choose a TLP marking (White/Green/Amber/Red) — this travels with the
   indicator into every export format.
4. Confirm. Each finding's value (its filepath, or another indicator you
   select) is auto-classified into an indicator type — file hash, domain,
   IP, registry key, process name, or file path — and saved into the local
   **IOC Library** (`/iocs`).

![Save as IOC modal with TLP marking selector](placeholder-save-as-ioc-modal.png)
*Figure 2: The Save as IOC modal — TLP:AMBER selected, showing the count of findings about to be converted.*

### Exporting the IOC Library {#ioc-library-export}

From `/iocs`, three export formats are available:

- **STIX 2.1 bundle** — a real `Indicator` object per IOC with a proper
  pattern (`[file:name = '...']`, `[ipv4-addr:value = '...']`, etc.),
  downloadable and importable into any STIX-consuming tool.
- **MISP-shaped JSON** — an `Event`/`Attribute` structure matching MISP's
  own import format, for "Add Event from file" — **this is a one-way file
  export, not a live push to a running MISP instance.** There's no MISP API
  key configuration anywhere in this platform.
- **CSV** — flat, for spreadsheet-based workflows.

> ℹ️ **Info:** There is no live threat-intel enrichment on save (no
> automatic VirusTotal/AbuseIPDB lookup populating a reputation score) — an
> IOC is saved exactly as extracted from the finding. Use the pivot links
> (below) if you want to manually check a value against an external
> service.

---

## Report Generation & Export {#report-generation-and-export}

### Step-by-step {#export-report-steps}

1. Select findings (or select none to export everything currently visible).
2. Click **Export to Report**.
3. Choose a **template**: Executive Summary (severity breakdown + only
   Critical/High findings), Technical Forensic Report (full detail per
   finding), Incident Summary, or Legal Hold (adds dismissal
   history/justification per finding).
4. Choose a **format**: Markdown, JSON, or CSV.
5. Optionally enable **Redact PII** (best-effort regex scrub of username
   path segments and email addresses — not a guaranteed-complete redaction,
   review before sharing externally) and **Include chain of custody**
   (notes which agent produced the finding and its approval state).
6. Click **Generate & Download** — the file downloads immediately in your
   browser, no job queue involved.

![Export to Report modal with template and format selectors](placeholder-export-report-modal.png)
*Figure 3: The Export modal — "Technical Forensic Report" template, Markdown format, chain-of-custody enabled.*

> ⚠️ **Warning: there is no PDF export.** Only Markdown, JSON, and CSV are
> supported. If you need a PDF for a client deliverable, generate the
> Markdown version and convert it with an external tool (e.g. Pandoc, or
> paste into a document editor).

---

## Adding & Managing Manual Findings {#manual-findings}

For anything discovered outside the automated pipeline — manual memory
inspection with an external tool, offline registry review, an external
threat-intel tip.

### Step-by-step {#manual-findings-steps}

1. Click **+ Add Manual Finding** at the top of the Findings page.
2. Fill in anomaly type, severity, an artifact path (optional), and a
   justification (required).
3. Optionally add a "source/tool" note — this is a free-text chain-of-
   custody field (e.g. "Manual review of NTUSER.DAT with Registry
   Explorer"), not a structured artifact link.
4. Submit. The finding appears immediately, tagged `Manual Entry`, and is
   already "approved" by definition (there's no LLM output to review).

![Add Manual Finding modal filled out with a registry persistence example](placeholder-manual-finding-modal.png)
*Figure 4: The Add Manual Finding modal, filled in for a manually-discovered Run key persistence entry.*

> ℹ️ **Info:** Manual findings are scoped to whichever investigation is
> currently active when you create them — they won't appear if you later
> resume a *different* staging folder.

---

## AI Agent Deep Enrichment {#ai-deep-enrichment}

Available on any **agent-derived** finding (not manual findings — there's no
underlying agent/raw data to re-analyze for those).

### Step-by-step {#deep-enrichment-steps}

1. Open a finding's detail drawer.
2. Under "Agent enrichment," choose **Deep Analyze** (re-examine in more
   depth, add corroborating detail), **Rescan** (re-derive from scratch,
   flag any discrepancy with the prior conclusion), or **Reputation
   lookup** (focus specifically on IPs/domains/hashes worth checking
   externally).
3. This re-runs the LLM analysis step against the *same* raw data the
   original agent collected — it does not re-run Volatility/Ghidra/etc.
   from scratch. If the finding came from a plugin whose raw output no
   longer reflects reality (e.g. you've since re-imaged), enrichment won't
   pick that up.
4. Status polls automatically every 2 seconds; a new corroborating anomaly
   (if the LLM finds one) is appended to that agent's findings and appears
   in the main list once complete.

![Finding detail drawer mid-enrichment, showing the polling status message](placeholder-deep-enrichment.png)
*Figure 5: The detail drawer's enrichment panel showing "Deep analysis running..." followed by a completed summary and an entry in the enrichment history below it.*

> 🔧 **Troubleshooting:** Enrichment uses whichever LLM provider is
> configured on the Management page's LLM tab
> (see [System Management](06-system-management.md#llm-provider-configuration)).
> If it fails immediately, use that page's **Test Connection** button to
> check the provider is actually reachable before assuming enrichment
> itself is broken — an unreachable Open WebUI endpoint fails every
> enrichment call the same way it would fail every original agent
> analysis call.

---

## Dismissing / Deleting Findings {#dismissing-findings}

Every dismissal is **soft** and **audit-logged** — nothing is hard-deleted
from the Findings page itself.

### Step-by-step {#dismiss-steps}

1. Select one or more findings, or open a single finding's drawer.
2. Choose **Acknowledge** (confirmed real, handled), **Mark false
   positive**, or **Dismiss** — each prompts for a reason.
3. Dismissed/false-positive findings disappear from the default view;
   toggle **"Show dismissed"** to bring them back into view (still tagged
   with who dismissed them, when, and why).
4. Every action — dismiss, restore, assign, tag, comment, enrich — writes an
   entry to that finding's **audit log**, visible in its detail drawer.

![Finding detail drawer's audit log tab showing a dismiss-then-restore history](placeholder-audit-log.png)
*Figure 6: A finding's audit log showing `dismissed by alice: "confirmed benign — signed MS binary"` followed by `restored by bob` — full accountability for both actions.*

> ✅ **Best Practice:** If you're dismissing the *same* kind of finding
> repeatedly across an investigation (a known-good signed binary showing up
> in every scan, say), stop dismissing one-by-one and create an
> **exclusion rule** instead — see
> [System Management](06-system-management.md#exclusion-engine-configuration).
> Dismissal is per-finding and per-investigation; exclusion rules apply
> platform-wide, automatically, going forward.

---

## Everything else built into this page {#findings-page-extras}

These weren't in the original feature brief but exist and are worth
documenting:

### Pivot & hunt links `#PivotLinks` {#pivot-and-hunt-links}

Every indicator-shaped value (an IP, domain, or hash detected in a finding's
filepath) gets a **"Pivot & hunt"** section in its detail drawer with
outbound links: VirusTotal/AbuseIPDB lookups (real external URLs, opens in
a new tab — no API key or automatic scoring, just a convenience link), and
a "Query SIEM" link **only if** your deployment has set the
`SIEM_QUERY_URL_TEMPLATE` environment variable. Without it, the link shows
as disabled with a note explaining how to configure it. There is no bundled
SIEM integration.

### Confidence, tags, and MITRE ATT&CK technique tagging `#AgentConfiguration` {#mitre-tagging}

Every finding gets a default confidence score derived from its severity
(Critical→90, High→75, Medium→55, Low→35), adjustable per-finding via a
slider in the detail drawer. Free-text tags and a curated local MITRE
ATT&CK technique picker (a fixed offline list of ~20 common DFIR-relevant
techniques, not a live ATT&CK database fetch) are both available in the
same drawer.

### Duplicate clustering {#duplicate-clustering}

Findings sharing the same artifact path and anomaly type across *different*
agents auto-collapse into one card with a "N sources" badge (expand to see
each source). You can also force-merge unrelated findings you believe
represent the same underlying issue via **Merge as duplicate** in the bulk
action bar.

### Assignment, comments, and presence locking {#assignment-and-collaboration}

Assign a finding to a named analyst; leave threaded comments in its detail
drawer. Opening a finding's drawer also takes a **soft, poll-based lock** —
if another analyst opens the same finding within the last ~25 seconds,
you'll both see a banner naming who else is looking at it. This is a
courtesy indicator, not a real-time lock — there's no websocket push behind
it, so it's refreshed on a timer, not instantly.

### Saved views and keyboard triage mode {#saved-views-and-keyboard-mode}

Save your current severity/approval filter combination as a named view for
one-click reapplication later. Toggle **Keyboard mode** (top of the page)
for `j`/`k` to move focus, `x` to select, `a` to acknowledge, `d` to
dismiss, `Enter` to open, `Esc` to close — fast triage for a large findings
queue without touching the mouse.

### The exclusion engine's effect on this page {#exclusion-effect-on-findings}

If a finding matches an active exclusion rule with action "Mark as
excluded," it's hidden from the default view but still visible via **"Show
excluded"** (with a badge explaining which rule suppressed it). If the
rule's action is "Hide completely," it never appears here at all, in any
view — see [System Management](06-system-management.md#exclusion-engine-configuration)
for setting these up.
