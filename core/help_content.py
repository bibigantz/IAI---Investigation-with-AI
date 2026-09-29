"""Loads and renders the Help Center's markdown source (docs/help-center/)
into HTML + a TOC + a client-side search index, at request time.

Content is a handful of small files re-parsed per request rather than
pre-built at deploy time -- consistent with this app's "no build step"
philosophy, and cheap enough (~50KB of markdown total) that caching would be
premature. If that ever changes, this module is the one place to add a
cache.
"""
import re
from functools import lru_cache
from pathlib import Path

import markdown as md

HELP_DIR = Path(__file__).resolve().parent.parent / "docs" / "help-center"

# Order here is the left-sidebar order -- matches how an analyst actually
# encounters this platform: launch an investigation, then the three analysis
# engines in the order they actually run (Memory -> Windows -> File, see
# agents/orchestrators/master_analyst.py), then working the results, then
# administering the platform, then the appendix. README.md is repo-
# contributor meta content (page-architecture notes for whoever builds/
# extends this), not an analyst-facing article, so it's deliberately
# excluded from this list.
ARTICLE_FILES = [
    "01-getting-started.md",
    "02-memory-analysis.md",
    "03-windows-forensics.md",
    "04-file-malware-analysis.md",
    "05-findings-management.md",
    "06-system-management.md",
    "07-known-limitations.md",
]

_HEADING_RE = re.compile(r"^(#{1,3})\s+(.*)$")
_ANCHOR_RE = re.compile(r"\{#([\w-]+)\}\s*$")
_TAG_SPAN_RE = re.compile(r"`(#[A-Za-z0-9]+(?:\s+#[A-Za-z0-9]+)*)`")
_FENCED_CODE_RE = re.compile(r"```.*?```", re.DOTALL)

_CALLOUT_EMOJI_CLASS = {
    "ℹ️": "callout-info",           # ℹ️
    "⚠️": "callout-warning",        # ⚠️
    "✅": "callout-success",              # ✅
    "\U0001f527": "callout-troubleshooting",  # 🔧
}


def _slugify(text: str) -> str:
    text = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[\s_]+", "-", text)


def _strip_markdown_inline(text: str) -> str:
    text = re.sub(r"[`*_]", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return text.strip()


def _extract_tags(rest: str):
    tags = []
    for span in _TAG_SPAN_RE.finditer(rest):
        tags.extend(span.group(1).split())
    return tags


def _parse_article(raw_text: str, source_file: str, module_index: int):
    """Returns (headings, body_by_anchor) -- headings is TOC-ready structure,
    body_by_anchor is {anchor: plain-text excerpt} for the search index."""
    text_no_code = _FENCED_CODE_RE.sub("", raw_text)
    lines = text_no_code.splitlines()

    heading_positions = []  # (line_index, level, title, anchor, tags)
    for i, line in enumerate(lines):
        m = _HEADING_RE.match(line)
        if not m:
            continue
        level = len(m.group(1))
        rest = m.group(2).strip()
        anchor_m = _ANCHOR_RE.search(rest)
        if anchor_m:
            anchor = anchor_m.group(1)
            rest = _ANCHOR_RE.sub("", rest).strip()
        else:
            anchor = None
        tags = _extract_tags(rest)
        for span in _TAG_SPAN_RE.finditer(rest):
            rest = rest.replace(span.group(0), "")
        title = rest.strip(" -")
        if not anchor:
            anchor = _slugify(title)
        heading_positions.append((i, level, title, anchor, tags))

    headings = []
    body_by_anchor = {}
    for idx, (line_no, level, title, anchor, tags) in enumerate(heading_positions):
        next_line_no = heading_positions[idx + 1][0] if idx + 1 < len(heading_positions) else len(lines)
        body_lines = lines[line_no + 1:next_line_no]
        body_text = " ".join(l.strip().lstrip(">").strip() for l in body_lines if l.strip())
        body_text = _strip_markdown_inline(body_text)
        excerpt = (body_text[:200] + "…") if len(body_text) > 200 else body_text

        headings.append({
            "level": level, "title": title, "anchor": anchor, "tags": tags,
            "source_file": source_file, "module_index": module_index,
        })
        body_by_anchor[anchor] = excerpt

    return headings, body_by_anchor


def _preprocess_for_render(raw_text: str) -> str:
    """Converts this project's `{#anchor-id}` heading syntax into the
    `attr_list` extension's `{: #anchor-id}` syntax, so rendered headings get
    real, stable `id` attributes matching the TOC/search anchors above."""
    return re.sub(r"\{#([\w-]+)\}(\s*)$", r"{: #\1}\2", raw_text, flags=re.MULTILINE)


def _callout_repl(m: "re.Match") -> str:
    emoji = m.group(1)
    cls = _CALLOUT_EMOJI_CLASS.get(emoji, "")
    return f'<blockquote class="callout {cls}">\n<p>{emoji}'


def _placeholder_box(alt: str) -> str:
    return (
        '<div class="help-img-placeholder">'
        '<svg class="icon" viewBox="0 0 24 24" width="28" height="28">'
        '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/>'
        '<path d="M21 15l-5-5-4 4-3-3-6 6"/></svg>'
        f'<span>Screenshot placeholder: {alt}</span></div>'
    )


# Markdown emits an image immediately followed by its `*Figure N: ...*`
# caption line as ONE paragraph (no blank line between them in the source),
# so the naive per-tag replacement below would leave an invalid <div> nested
# inside a <p>. This matches that whole merged paragraph and rewrites it as
# a proper <figure>/<figcaption> instead of trying to patch it in place.
_FIGURE_BLOCK_RE = re.compile(
    r'<p><img alt="(?P<alt>[^"]*)" src="placeholder-[^"]*"[^>]*/?>\s*'
    r'(?:<em>(?P<caption>Figure \d+:.*?)</em>)?\s*</p>',
    re.DOTALL,
)


def _figure_block_repl(m: "re.Match") -> str:
    alt = m.group("alt")
    caption = m.group("caption")
    caption_html = f"<figcaption>{caption}</figcaption>" if caption else ""
    return f'<figure class="help-figure">{_placeholder_box(alt)}{caption_html}</figure>'


def _postprocess_html(html: str) -> str:
    html = re.sub(r"<blockquote>\s*<p>(ℹ️|⚠️|✅|\U0001f527)", _callout_repl, html)
    html = _FIGURE_BLOCK_RE.sub(_figure_block_repl, html)
    # Fallback for any placeholder image that didn't match the merged-
    # paragraph pattern above (e.g. one with no caption line at all and on
    # its own line) -- still replaced, just without a <figure> wrapper.
    html = re.sub(
        r'<img alt="(?P<alt>[^"]*)" src="placeholder-[^"]*"[^>]*/?>',
        lambda m: _placeholder_box(m.group("alt")), html,
    )
    return html


def _render_markdown(raw_text: str) -> str:
    renderer = md.Markdown(extensions=["attr_list", "fenced_code", "tables", "sane_lists"])
    html = renderer.convert(_preprocess_for_render(raw_text))
    return _postprocess_html(html)


@lru_cache(maxsize=1)
def _load_all():
    articles = []
    all_headings = []
    search_entries = []

    for module_index, filename in enumerate(ARTICLE_FILES):
        path = HELP_DIR / filename
        if not path.is_file():
            continue
        raw_text = path.read_text(encoding="utf-8")
        headings, body_by_anchor = _parse_article(raw_text, filename, module_index)
        html = _render_markdown(raw_text)

        module_title = headings[0]["title"] if headings else filename
        articles.append({
            "source_file": filename, "module_index": module_index,
            "title": module_title, "html": html,
        })
        all_headings.extend(headings)
        for h in headings:
            if h["level"] == 1:
                continue  # the module title itself isn't a useful search hit
            search_entries.append({
                "title": h["title"], "anchor": h["anchor"], "tags": h["tags"],
                "module_title": module_title, "excerpt": body_by_anchor.get(h["anchor"], ""),
            })

    return articles, all_headings, search_entries


def get_articles():
    """List of {source_file, module_index, title, html} in sidebar order."""
    return _load_all()[0]


def get_toc():
    """Flat list of every heading across every article, in document order --
    the left-sidebar table of contents is built from this client-side."""
    return _load_all()[1]


def get_search_index():
    """Flat list of {title, anchor, tags, module_title, excerpt} for the
    Help Center's client-side fuzzy search."""
    return _load_all()[2]


def get_all_tags():
    tags = set()
    for h in get_toc():
        tags.update(h["tags"])
    return sorted(tags)


def reload_content():
    """Drops the cache -- call this if docs/help-center/*.md changes without
    a server restart (there's no file-watcher; this is a manual escape
    hatch, e.g. from a shell/REPL during content edits)."""
    _load_all.cache_clear()
