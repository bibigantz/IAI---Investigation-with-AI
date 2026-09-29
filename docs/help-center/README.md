# IAI Help Center — Content Index & Page Design

This directory holds the source content for the in-app Help & Documentation
Center (`/help`). Each file below is one article, in sidebar order; headings
inside each file become that article's on-page TOC via their anchor IDs.

**Status: implemented.** `/help/<slug>` renders each file below server-side
via `core/help_content.py` (Python-Markdown + a small post-processing pass
for callout boxes, figure placeholders, and heading anchors), with a live
fuzzy search over `/api/help/search-index`, tag-filter chips, and scroll-spy
on the per-page on-page TOC. Parsed content is cached in-process
(`@lru_cache` in `core/help_content.py`) after the first request — editing a
`.md` file here won't show up until you restart the dev server (which
re-imports the module fresh) or call `help_content.reload_content()` from a
shell attached to the running process.

## Page architecture

- **Route**: `/help/<slug>` — one real page per article (`01-getting-
  started`, `02-memory-analysis`, ...), mirroring the `/management/<tab>`
  pattern already used elsewhere in this app. `/help` redirects to the
  first article. Each article's own headings are anchors within that page
  (`/help/02-memory-analysis#malfind-correlator`).
- **Search**: `/api/help/search-index` returns every heading across every
  article as `{title, tags, anchor, slug, excerpt}`, fuzzy-matched
  client-side in `app.js` — no new frontend dependency, consistent with the
  rest of this codebase's "no build step" approach.
- **Layout**: three columns reusing existing CSS primitives — a sidebar of
  every article (expanded to that article's own headings only when it's
  the active one), the rendered article, and a sticky on-page TOC for
  *that* article. Callouts render as styled blockquotes (`> ℹ️ Info:`,
  `> ⚠️ Warning:`, `> ✅ Best Practice:`, `> 🔧 Troubleshooting:`).
- **Filter tags**: `#MemoryAnalysis` `#MalwareTriage` `#WindowsForensics`
  `#ExclusionRules` `#IOCs` `#AgentConfiguration` `#NetworkForensics`
  `#PivotLinks` `#AccessControl` `#Retention`. (`#SIEM` from the original
  brief was renamed `#PivotLinks` — there's no live SIEM integration in this
  platform, only a configurable outbound link; see
  [Findings Management](05-findings-management.md#pivot-and-hunt-links).)

## Contents

Ordered to match how an analyst actually encounters this platform: how to
launch an investigation, then the three analysis engines in the order they
actually run (Memory → Windows → File — see `master_analyst.py`), then how
to work the results, then how to administer the platform, then the
appendix.

1. [Getting Started: Launch Hub & Topology](01-getting-started.md)
2. [Memory Analysis](02-memory-analysis.md)
3. [Windows Forensics & Common Malware Paths](03-windows-forensics.md)
4. [File & Malware Analysis](04-file-malware-analysis.md)
5. [Findings Management](05-findings-management.md)
6. [System Management & Administration](06-system-management.md)
7. [Known Limitations & Honest Caveats](07-known-limitations.md) — read this
   one before promising an analyst something the platform doesn't actually
   do yet.

The filename numbering is the actual sidebar/reading order — `core/
help_content.py`'s `ARTICLE_FILES` list must match it exactly (it drives
the live page, this list is just the human-readable index).
