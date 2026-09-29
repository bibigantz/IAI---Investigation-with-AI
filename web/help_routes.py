from flask import render_template, redirect, jsonify

from core import help_content

_SLUGS = [f[:-3] for f in help_content.ARTICLE_FILES]  # strip ".md"


def register_help_routes(app):
    @app.route("/help")
    def help_default():
        return redirect(f"/help/{_SLUGS[0]}")

    @app.route("/help/<slug>")
    def help_article(slug):
        if slug not in _SLUGS:
            slug = _SLUGS[0]
        articles = help_content.get_articles()
        active = next((a for a in articles if a["source_file"] == f"{slug}.md"), articles[0])
        active_headings = [h for h in help_content.get_toc() if h["source_file"] == f"{slug}.md" and h["level"] in (2, 3)]

        # Sidebar: every module's title + (only for the active module) its
        # own H2 headings, so the inactive modules stay collapsed to a
        # single link -- a lightweight version of a collapsible nested TOC
        # without needing client-side expand/collapse state.
        sidebar_modules = []
        for a in articles:
            module_slug = a["source_file"][:-3]
            sidebar_modules.append({
                "slug": module_slug, "title": a["title"], "active": module_slug == slug,
                "headings": [h for h in help_content.get_toc()
                             if h["source_file"] == a["source_file"] and h["level"] == 2] if module_slug == slug else [],
            })

        return render_template(
            "help.html",
            active_article=active, active_slug=slug,
            active_headings=active_headings,
            sidebar_modules=sidebar_modules,
            all_tags=help_content.get_all_tags(),
        )

    @app.route("/api/help/search-index")
    def help_search_index():
        entries = help_content.get_search_index()
        # Attach the module slug each entry lives on, so a search result can
        # link straight to /help/<slug>#<anchor> across modules.
        by_source = {a["source_file"]: a["source_file"][:-3] for a in help_content.get_articles()}
        toc_by_anchor = {h["anchor"]: by_source.get(h["source_file"], "") for h in help_content.get_toc()}
        enriched = [{**e, "slug": toc_by_anchor.get(e["anchor"], "")} for e in entries]
        return jsonify({"entries": enriched})
