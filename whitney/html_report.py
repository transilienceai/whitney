"""Self-contained HTML report renderer for Whitney.

Two public functions: :func:`render_scan_html` for ``whitney scan`` output,
:func:`render_sbom_html` for ``whitney sbom`` output. Both return a complete
HTML document as a string (no file I/O inside this module — the CLI writes
to disk).

Design constraints (per docs/superpowers/specs/2026-04-26-html-reports-design.md):

- Stdlib only — no Jinja2, no requests, no JS framework.
- Single self-contained file: CSS inlined, no web fonts, no images, no
  external scripts.
- XSS-safe: every interpolated user-content field passes through
  :func:`html.escape`; every URL value through :func:`urllib.parse.quote`.
- Light theme by default; ``prefers-color-scheme: dark`` auto-flip.
- Severity palette is consistent with the CLI's `--severity` ordering:
  critical / high / medium / low / info.
- Embeds the raw findings/SBOM JSON in a ``<script type="application/json">``
  block so power users can extract via ``cat report.html | sed -n '/whitney-data/,/script>/p' | head -n -1 | tail -n +2 | jq``
  (or any equivalent extraction).
"""
from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

__all__ = ["render_scan_html", "render_sbom_html", "__version__"]

__version__ = "0.2.0"

# Severity → (display label, hex colour, ordering rank low-is-first).
# The ordering rank drives the per-severity grouping in the scan report.
_SEVERITY: dict[str, tuple[str, str, int]] = {
    "critical": ("Critical", "#dc2626", 0),
    "high":     ("High",     "#ea580c", 1),
    "medium":   ("Medium",   "#d97706", 2),
    "low":      ("Low",      "#65a30d", 3),
    "info":     ("Info",     "#0891b2", 4),
}

# Stable colour assignment for AI providers in the SBOM grouping panel.
# Falls back to the accent colour for unknown providers.
_PROVIDER_COLOURS: dict[str, str] = {
    "openai":      "#10a37f",
    "anthropic":   "#cc785c",
    "aws":         "#ff9900",
    "azure":       "#0078d4",
    "google":      "#4285f4",
    "huggingface": "#ffb000",
    "cohere":      "#39594d",
    "mistral":     "#fa520f",
    "meta":        "#0668e1",
    "litellm":     "#7c3aed",
    "together":    "#0099ff",
    "groq":        "#f55036",
    "replicate":   "#7e3ff2",
    "ollama":      "#000000",
    "vllm":        "#5b21b6",
    "unknown":     "#6b7280",
}

_ACCENT = "#0891b2"

_CSS = """
:root {
  --bg: #ffffff;
  --fg: #1f2937;
  --fg-muted: #6b7280;
  --card-bg: #ffffff;
  --card-border: #e5e7eb;
  --code-bg: #f9fafb;
  --code-border: #e5e7eb;
  --accent: """ + _ACCENT + """;
  --shadow: 0 1px 3px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.06);
  --radius: 8px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f172a;
    --fg: #e2e8f0;
    --fg-muted: #94a3b8;
    --card-bg: #1e293b;
    --card-border: #334155;
    --code-bg: #0b1220;
    --code-border: #334155;
    --shadow: 0 1px 3px rgba(0,0,0,0.4);
  }
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--fg);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}
.wrap { max-width: 1200px; margin: 0 auto; padding: 32px 24px 64px; }
header {
  border-bottom: 1px solid var(--card-border);
  margin-bottom: 32px;
  padding-bottom: 16px;
}
header .brand {
  font-size: 0.75rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--accent);
  font-weight: 700;
}
header h1 { margin: 4px 0 4px; font-size: 1.75rem; font-weight: 700; }
header .sub { color: var(--fg-muted); font-size: 0.9rem; }
nav.sticky {
  position: sticky;
  top: 0;
  background: var(--bg);
  border-bottom: 1px solid var(--card-border);
  padding: 12px 0;
  margin-bottom: 24px;
  z-index: 5;
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 0.875rem;
}
nav.sticky a { color: var(--fg-muted); text-decoration: none; }
nav.sticky a:hover { color: var(--accent); }
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}
.card {
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: var(--radius);
  padding: 16px 20px;
  box-shadow: var(--shadow);
}
.card .num { font-size: 2.25rem; font-weight: 700; line-height: 1; }
.card .lbl {
  color: var(--fg-muted);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-top: 8px;
}
section { margin-bottom: 40px; }
section > h2 {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--card-border);
}
.sev-header {
  position: sticky;
  top: 56px;
  background: var(--bg);
  padding: 12px 0;
  z-index: 4;
  display: flex;
  align-items: center;
  gap: 12px;
  font-weight: 600;
  font-size: 1rem;
  border-bottom: 1px solid var(--card-border);
  margin-bottom: 12px;
}
.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: white;
}
.finding {
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: var(--radius);
  padding: 16px 20px;
  margin-bottom: 16px;
  box-shadow: var(--shadow);
}
.finding .meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  font-size: 0.875rem;
  color: var(--fg-muted);
  margin-bottom: 8px;
}
.finding .meta a { color: var(--accent); text-decoration: none; }
.finding .meta a:hover { text-decoration: underline; }
.finding .check-id {
  font-family: "JetBrains Mono", "SF Mono", Consolas, monospace;
  font-size: 0.8rem;
  color: var(--fg-muted);
}
.finding .title { font-weight: 600; margin: 8px 0; }
pre.code {
  background: var(--code-bg);
  border: 1px solid var(--code-border);
  border-radius: 6px;
  padding: 12px 16px;
  overflow-x: auto;
  font-family: "JetBrains Mono", "SF Mono", Consolas,
               "Liberation Mono", monospace;
  font-size: 0.8rem;
  line-height: 1.55;
  margin: 12px 0;
  white-space: pre;
}
.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin: 12px 0 4px;
}
.chip {
  display: inline-block;
  padding: 2px 8px;
  border: 1px solid var(--card-border);
  border-radius: 10px;
  font-size: 0.7rem;
  font-family: "JetBrains Mono", "SF Mono", Consolas, monospace;
  color: var(--fg-muted);
  background: var(--code-bg);
}
details {
  margin-top: 12px;
  font-size: 0.9rem;
}
details summary {
  cursor: pointer;
  color: var(--accent);
  font-size: 0.85rem;
  font-weight: 500;
}
details > p { margin: 8px 0 0; color: var(--fg); }
.provider-strip {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  border-radius: 6px;
  margin: 24px 0 12px;
  color: white;
  font-weight: 600;
}
.provider-strip .count {
  font-weight: 400;
  opacity: 0.9;
  font-size: 0.85rem;
}
table.components {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
table.components th, table.components td {
  text-align: left;
  padding: 8px 12px;
  border-bottom: 1px solid var(--card-border);
}
table.components th {
  background: var(--code-bg);
  font-weight: 600;
  color: var(--fg-muted);
  text-transform: uppercase;
  font-size: 0.7rem;
  letter-spacing: 0.06em;
}
table.components td.purl {
  font-family: "JetBrains Mono", "SF Mono", Consolas, monospace;
  font-size: 0.75rem;
  color: var(--fg-muted);
}
.vuln {
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-left: 4px solid #dc2626;
  border-radius: var(--radius);
  padding: 14px 18px;
  margin-bottom: 12px;
  box-shadow: var(--shadow);
}
.vuln .id {
  font-family: "JetBrains Mono", "SF Mono", Consolas, monospace;
  font-weight: 700;
  font-size: 0.95rem;
}
.vuln .pkg {
  font-family: "JetBrains Mono", "SF Mono", Consolas, monospace;
  font-size: 0.8rem;
  color: var(--fg-muted);
  margin-left: 8px;
}
.vuln .desc { margin: 8px 0; }
.vuln .meta {
  font-size: 0.8rem;
  color: var(--fg-muted);
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
}
.vuln .meta a { color: var(--accent); text-decoration: none; }
.vuln .meta a:hover { text-decoration: underline; }
.empty {
  padding: 24px;
  text-align: center;
  color: var(--fg-muted);
  background: var(--code-bg);
  border-radius: var(--radius);
  font-style: italic;
}
footer {
  margin-top: 48px;
  padding-top: 16px;
  border-top: 1px solid var(--card-border);
  font-size: 0.8rem;
  color: var(--fg-muted);
}
footer a { color: var(--accent); text-decoration: none; }
@media (max-width: 600px) {
  .wrap { padding: 16px 12px 32px; }
  header h1 { font-size: 1.4rem; }
  nav.sticky { font-size: 0.8rem; gap: 8px; }
  .sev-header { top: 84px; }
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    """HTML-escape any value, coercing to string first."""
    return html.escape(str(value), quote=True)


def _safe_url(value: str) -> str:
    """Percent-encode a URL value for safe interpolation into href/src."""
    return quote(value, safe=":/?#[]@!$&'()*+,;=%")


def _embed_json(payload: Any) -> str:
    """Serialise `payload` and escape `</` so it can't break out of the
    surrounding ``<script>`` tag (the JSON-in-script standard precaution).
    """
    raw = json.dumps(payload, indent=2, default=str)
    return raw.replace("</", "<\\/")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _shell(*, title: str, subtitle: str, body: str, embedded_json: str,
           data_id: str) -> str:
    """Render the outer HTML shell (header / nav / body / footer / data block).

    All caller-supplied strings must already be HTML-escaped where needed.
    The ``embedded_json`` value must already have been passed through
    :func:`_embed_json`.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="whitney {__version__}">
<title>{_esc(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="brand">Whitney v{__version__}</div>
  <h1>{_esc(title)}</h1>
  <div class="sub">{subtitle}</div>
</header>
{body}
<footer>
  Generated {_esc(_now_utc())} by
  <a href="https://github.com/transilienceai/whitney">Whitney</a>
  v{__version__}.
</footer>
</div>
<script type="application/json" id="{_esc(data_id)}">
{embedded_json}
</script>
</body>
</html>
"""


def _severity_rank(sev: str) -> int:
    return _SEVERITY.get(sev.lower(), ("?", "#888888", 99))[2]


def _severity_label(sev: str) -> str:
    return _SEVERITY.get(sev.lower(), (sev.title(), "#888888", 99))[0]


def _severity_colour(sev: str) -> str:
    return _SEVERITY.get(sev.lower(), ("?", "#888888", 99))[1]


def _badge(sev: str) -> str:
    colour = _severity_colour(sev)
    label = _severity_label(sev)
    return f'<span class="badge" style="background:{colour}">{_esc(label)}</span>'


def _provider_colour(provider: str) -> str:
    return _PROVIDER_COLOURS.get(provider.lower(), _ACCENT)


def _finding_to_plain(f: Any) -> dict:
    """Coerce a Finding (or anything with ``to_dict``) to a plain dict."""
    if hasattr(f, "to_dict"):
        return f.to_dict()
    if hasattr(f, "__dict__"):
        return {k: v for k, v in f.__dict__.items() if not k.startswith("_")}
    return dict(f)


# ---------------------------------------------------------------------------
# Scan report
# ---------------------------------------------------------------------------


def _render_finding(f: dict, scan_root: Path) -> str:
    """Render a single finding card."""
    details = f.get("details") or {}
    severity = str(f.get("severity") or "info").lower()
    check_id = str(f.get("check_id") or "unknown")
    title = str(f.get("title") or check_id)
    file_path = str(details.get("file_path") or f.get("resource_id") or "")
    line_number = details.get("line_number") or 0

    # Build a vscode:// link to the absolute path. Won't resolve if the
    # report is opened on a different machine, but harmless if so.
    vscode_link = ""
    if file_path:
        try:
            abs_path = str((scan_root / file_path).resolve())
        except (OSError, ValueError):
            abs_path = file_path
        href = f"vscode://file/{_safe_url(abs_path)}:{int(line_number) or 1}"
        vscode_link = (
            f'<a href="{href}" title="Open in VS Code">'
            f'{_esc(file_path)}:{_esc(line_number)}</a>'
        )
    else:
        vscode_link = '<span class="fg-muted">no file</span>'

    code_snippet = str(details.get("code_snippet") or "").rstrip()
    code_block = (
        f"<pre class=\"code\">{_esc(code_snippet)}</pre>" if code_snippet else ""
    )

    chips: list[str] = []
    for cwe in details.get("cwe") or []:
        chips.append(f'<span class="chip">{_esc(cwe)}</span>')
    for owasp in details.get("owasp") or []:
        chips.append(f'<span class="chip">{_esc(owasp)}</span>')
    for owasp_a in details.get("owasp_agentic") or []:
        chips.append(f'<span class="chip">{_esc(owasp_a)}</span>')
    for tech in details.get("technology") or []:
        chips.append(f'<span class="chip">{_esc(tech)}</span>')
    confidence = details.get("confidence")
    if confidence:
        chips.append(f'<span class="chip">conf: {_esc(confidence)}</span>')
    tags_html = (
        f'<div class="tags">{"".join(chips)}</div>' if chips else ""
    )

    remediation = (f.get("remediation") or "").strip()
    remediation_html = (
        f'<details><summary>Remediation</summary><p>{_esc(remediation)}</p></details>'
        if remediation else ""
    )

    triage = details.get("suppressed_by_llm_triage")
    triage_html = ""
    if triage:
        triage_html = (
            f'<div class="meta" style="margin-top:12px;color:var(--accent)">'
            f'Suppressed by LLM triage '
            f'(model={_esc(triage.get("model", "?"))}, '
            f'prompt_version={_esc(triage.get("prompt_version", "?"))})'
            f'</div>'
        )

    return f"""<article class="finding">
  <div class="meta">
    {_badge(severity)}
    <span class="check-id">{_esc(check_id)}</span>
    {vscode_link}
  </div>
  <div class="title">{_esc(title)}</div>
  {code_block}
  {tags_html}
  {remediation_html}
  {triage_html}
</article>"""


def render_scan_html(findings: list[Any], scan_root: Path | str) -> str:
    """Render a complete HTML document for a Whitney scan result.

    Args:
        findings: list of Finding objects (or dicts with the same shape).
        scan_root: directory the scan was rooted at — used to build
            absolute paths for ``vscode://`` deep links.

    Returns:
        Complete HTML document as a string. Caller writes to disk.
    """
    scan_root_path = Path(scan_root)
    plain_findings = [_finding_to_plain(f) for f in findings]
    # Coerce nested enums to strings for JSON embedding.
    for d in plain_findings:
        for k, v in list(d.items()):
            if hasattr(v, "value"):
                d[k] = v.value

    # Sort: severity rank ascending (critical first), then by file/line.
    plain_findings.sort(key=lambda f: (
        _severity_rank(str(f.get("severity") or "info").lower()),
        str((f.get("details") or {}).get("file_path") or ""),
        int((f.get("details") or {}).get("line_number") or 0),
    ))

    # Group by severity for the stacked sticky-header layout.
    by_sev: dict[str, list[dict]] = defaultdict(list)
    for f in plain_findings:
        by_sev[str(f.get("severity") or "info").lower()].append(f)

    sev_keys_present = sorted(by_sev.keys(), key=_severity_rank)
    sev_counts = {sev: len(by_sev[sev]) for sev in sev_keys_present}
    total = len(plain_findings)

    # --- summary cards ---
    cards = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = sev_counts.get(sev, 0)
        cards.append(
            f'<div class="card" style="border-top:4px solid {_severity_colour(sev)}">'
            f'<div class="num">{n}</div>'
            f'<div class="lbl">{_severity_label(sev)}</div>'
            f'</div>'
        )
    cards.append(
        f'<div class="card" style="border-top:4px solid var(--accent)">'
        f'<div class="num">{total}</div>'
        f'<div class="lbl">Total findings</div>'
        f'</div>'
    )
    cards_html = f'<div class="cards">{"".join(cards)}</div>'

    # --- top-offenders panel (only when N > 10) ---
    top_offenders_html = ""
    if total > 10:
        file_counts = Counter(
            str((f.get("details") or {}).get("file_path") or "")
            for f in plain_findings
        )
        check_counts = Counter(str(f.get("check_id") or "") for f in plain_findings)

        def _li(rows: list[tuple[str, int]]) -> str:
            return "".join(
                f'<li><span class="chip">{_esc(c)}</span> &nbsp; {_esc(name)}</li>'
                for name, c in rows
            )
        top_offenders_html = f"""<section id="top">
  <h2>Top offenders</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
    <div>
      <h3 style="font-size:0.95rem;color:var(--fg-muted);margin:0 0 8px">By file</h3>
      <ul style="list-style:none;padding:0;margin:0">{_li(file_counts.most_common(5))}</ul>
    </div>
    <div>
      <h3 style="font-size:0.95rem;color:var(--fg-muted);margin:0 0 8px">By check_id</h3>
      <ul style="list-style:none;padding:0;margin:0">{_li(check_counts.most_common(3))}</ul>
    </div>
  </div>
</section>"""

    # --- findings list ---
    findings_html_parts: list[str] = ['<section id="findings"><h2>Findings</h2>']
    if not plain_findings:
        findings_html_parts.append('<div class="empty">No findings.</div>')
    else:
        for sev in sev_keys_present:
            n = sev_counts[sev]
            findings_html_parts.append(
                f'<div class="sev-header">{_badge(sev)} '
                f'<span>{n} {_severity_label(sev).lower()} '
                f'finding{"" if n == 1 else "s"}</span></div>'
            )
            for f in by_sev[sev]:
                findings_html_parts.append(_render_finding(f, scan_root_path))
    findings_html_parts.append("</section>")
    findings_html = "".join(findings_html_parts)

    # --- triage-suppressed panel (only when present) ---
    suppressed_html = ""
    suppressed = [
        f for f in plain_findings
        if (f.get("details") or {}).get("suppressed_by_llm_triage")
    ]
    if suppressed:
        rows = "".join(
            f'<li><span class="chip">{_esc((f.get("details") or {}).get("file_path", ""))}</span> '
            f'{_esc(f.get("title", ""))}</li>'
            for f in suppressed
        )
        suppressed_html = f"""<section id="suppressed">
  <h2>Suppressed by LLM triage</h2>
  <div class="empty" style="text-align:left">
    These findings flagged by Semgrep but were classified as defended by an
    LLM-as-judge implementation, and therefore suppressed in the final output.
    <ul style="margin:12px 0 0;padding-left:18px">{rows}</ul>
  </div>
</section>"""

    # --- nav + assemble ---
    nav_links = ['<a href="#findings">Findings</a>']
    if top_offenders_html:
        nav_links.insert(0, '<a href="#top">Top offenders</a>')
    if suppressed_html:
        nav_links.append('<a href="#suppressed">Suppressed</a>')
    nav_html = (
        f'<nav class="sticky">{" · ".join(nav_links)}</nav>'
    )

    body = cards_html + nav_html + top_offenders_html + findings_html + suppressed_html

    subtitle = (
        f'Scanned <code>{_esc(str(scan_root_path))}</code> · '
        f'{_esc(_now_utc())} · '
        f'{total} finding{"" if total == 1 else "s"}'
    )
    return _shell(
        title="Whitney scan report",
        subtitle=subtitle,
        body=body,
        embedded_json=_embed_json(plain_findings),
        data_id="whitney-data",
    )


# ---------------------------------------------------------------------------
# SBOM report
# ---------------------------------------------------------------------------


def _render_component_table(components: list[dict]) -> str:
    if not components:
        return '<div class="empty">No components.</div>'
    rows = []
    for c in components:
        props = {p["name"]: p["value"] for p in (c.get("properties") or [])}
        ctype = props.get("whitney:component_type", "")
        ecosystem = props.get("whitney:ecosystem", "")
        source = props.get("whitney:source", "")
        rows.append(
            f"<tr>"
            f"<td>{_esc(c.get('name', ''))}</td>"
            f"<td>{_esc(c.get('version', ''))}</td>"
            f"<td>{_esc(ctype)}</td>"
            f"<td>{_esc(ecosystem)}</td>"
            f"<td>{_esc(source)}</td>"
            f"<td class=\"purl\">{_esc(c.get('purl', ''))}</td>"
            f"</tr>"
        )
    return f"""<table class="components">
<thead><tr>
<th>Name</th><th>Version</th><th>Type</th><th>Ecosystem</th>
<th>Source</th><th>purl</th>
</tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>"""


def _render_vulnerability(v: dict) -> str:
    vuln_id = v.get("id") or v.get("cve") or "UNKNOWN"
    description = v.get("description", "")
    package = v.get("package") or v.get("affects", [{}])[0].get("ref", "?")
    version = v.get("version", "")
    pkg_label = f"{package}@{version}" if version else package

    severity_raw = v.get("severity", "medium") or "medium"
    if isinstance(severity_raw, list) and severity_raw:
        severity_raw = severity_raw[0]
    severity = str(severity_raw).lower()

    constraint = v.get("constraint", "") or v.get("affected_range", "")
    fix_version = v.get("fix_version", "")

    refs = v.get("references") or []
    ref_links: list[str] = []
    for ref in refs[:3]:  # cap at 3 to keep cards compact
        url = ref if isinstance(ref, str) else ref.get("url", "")
        if not url:
            continue
        ref_links.append(
            f'<a href="{_esc(_safe_url(url))}" target="_blank" '
            f'rel="noopener">{_esc(url[:60])}{"…" if len(url) > 60 else ""}</a>'
        )
    refs_html = " · ".join(ref_links) if ref_links else ""

    meta_parts = []
    if constraint:
        meta_parts.append(f"affected: {_esc(constraint)}")
    if fix_version:
        meta_parts.append(f"fix: {_esc(fix_version)}")
    if refs_html:
        meta_parts.append(refs_html)
    meta_html = " · ".join(meta_parts)

    return f"""<div class="vuln">
  <span class="id">{_esc(vuln_id)}</span>
  <span class="pkg">{_esc(pkg_label)}</span>
  {_badge(severity)}
  <p class="desc">{_esc(description)}</p>
  <div class="meta">{meta_html}</div>
</div>"""


def render_sbom_html(sbom: dict) -> str:
    """Render a complete HTML document for a Whitney CycloneDX SBOM.

    Args:
        sbom: a CycloneDX 1.5 dict as produced by
            :func:`whitney.sbom.scan_ai_sbom_code_only`. May contain
            additional Whitney-specific fields like ``vulnerabilities``.

    Returns:
        Complete HTML document as a string.
    """
    components = sbom.get("components") or []
    vulnerabilities = sbom.get("vulnerabilities") or []

    # --- summary stats ---
    sdks = [c for c in components
            if any(p.get("name") == "whitney:component_type"
                   and p.get("value") == "sdk"
                   for p in (c.get("properties") or []))]
    models = [c for c in components
              if any(p.get("name") == "whitney:component_type"
                     and p.get("value") == "model"
                     for p in (c.get("properties") or []))]
    providers = sorted({
        next((p["value"] for p in (c.get("properties") or [])
              if p["name"] == "whitney:provider"), "unknown")
        for c in components
    })

    cards = (
        f'<div class="card" style="border-top:4px solid {_ACCENT}">'
        f'<div class="num">{len(sdks)}</div><div class="lbl">SDKs</div></div>'
        f'<div class="card" style="border-top:4px solid {_ACCENT}">'
        f'<div class="num">{len(models)}</div><div class="lbl">Models</div></div>'
        f'<div class="card" style="border-top:4px solid #dc2626">'
        f'<div class="num">{len(vulnerabilities)}</div>'
        f'<div class="lbl">Vulnerabilities</div></div>'
        f'<div class="card" style="border-top:4px solid {_ACCENT}">'
        f'<div class="num">{len(providers)}</div>'
        f'<div class="lbl">Providers</div></div>'
    )
    cards_html = f'<div class="cards">{cards}</div>'

    # --- per-provider grouping ---
    by_provider: dict[str, list[dict]] = defaultdict(list)
    for c in components:
        prov = next(
            (p["value"] for p in (c.get("properties") or [])
             if p["name"] == "whitney:provider"),
            "unknown",
        )
        by_provider[prov].append(c)

    provider_sections: list[str] = []
    for provider in sorted(by_provider.keys()):
        comps = by_provider[provider]
        colour = _provider_colour(provider)
        n = len(comps)
        provider_sections.append(
            f'<div class="provider-strip" style="background:{colour}">'
            f'<span>{_esc(provider)}</span>'
            f'<span class="count">{n} component{"" if n == 1 else "s"}</span>'
            f'</div>'
            f'{_render_component_table(comps)}'
        )
    components_html = (
        '<section id="components"><h2>Components</h2>'
        + "".join(provider_sections)
        + "</section>"
    ) if provider_sections else (
        '<section id="components"><h2>Components</h2>'
        '<div class="empty">No AI components found.</div></section>'
    )

    # --- vulnerabilities ---
    vulns_html = ""
    if vulnerabilities:
        vulns_html = (
            '<section id="vulns"><h2>Known vulnerabilities</h2>'
            + "".join(_render_vulnerability(v) for v in vulnerabilities)
            + "</section>"
        )

    # --- enrichment provenance ---
    enrichment = sbom.get("enrichment") or {}
    if enrichment.get("source"):
        src = enrichment["source"]
        ts = enrichment.get("timestamp", "")
        n_queried = enrichment.get("queried", 0)
        provenance = (
            f'<section id="provenance"><div class="empty" style="text-align:left">'
            f'Enriched from <code>{_esc(src)}</code> at {_esc(ts)} '
            f'({n_queried} component query{"" if n_queried == 1 else "ies"}).'
            f'</div></section>'
        )
    else:
        provenance = (
            '<section id="provenance"><div class="empty" style="text-align:left">'
            'No external enrichment performed. Re-run with '
            '<code>--enrich</code> to cross-reference components against '
            'the OSV.dev vulnerability database.'
            '</div></section>'
        )

    # --- nav ---
    nav_links = ['<a href="#components">Components</a>']
    if vulns_html:
        nav_links.append('<a href="#vulns">Vulnerabilities</a>')
    nav_links.append('<a href="#provenance">Enrichment</a>')
    nav_html = f'<nav class="sticky">{" · ".join(nav_links)}</nav>'

    body = cards_html + nav_html + components_html + vulns_html + provenance

    metadata = sbom.get("metadata") or {}
    timestamp = metadata.get("timestamp") or _now_utc()
    component_meta = metadata.get("component", {})
    account_id = (component_meta.get("name") or "").replace("ai-inventory-", "")
    subtitle = (
        f'Account <code>{_esc(account_id)}</code> · {_esc(timestamp)} · '
        f'{len(components)} component{"" if len(components) == 1 else "s"}'
    )
    return _shell(
        title="Whitney AI SBOM",
        subtitle=subtitle,
        body=body,
        embedded_json=_embed_json(sbom),
        data_id="whitney-data",
    )
