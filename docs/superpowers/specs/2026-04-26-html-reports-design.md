# Whitney HTML Reports + OSV CVE Enrichment — Design

**Date:** 2026-04-26
**Status:** Approved (brainstorming → spec; awaiting plan)
**Owner:** kkmookhey

## Context

Whitney today produces three CLI outputs: a plain-text severity table, JSON via `--json`, and a CycloneDX 1.5 dict from `whitney sbom`. None of these read well in a screen-recorded demo to technical decision-makers (CTOs, security leads, AppSec teams) — the natural medium for a demo is a browser tab, not a terminal scrollback.

This spec adds a single self-contained HTML report per command (`whitney scan --html out.html`, `whitney sbom --html out.html`) and an opt-in CVE-enrichment path (`whitney sbom --html out.html --enrich`) that queries OSV.dev for vulnerabilities affecting the discovered SDKs.

## Goals

1. Produce a polished HTML artifact that replaces the CLI as the primary demo surface — one file you double-click, no build step, no server.
2. Keep Whitney's "standalone OSS, zero new runtime deps, deterministic default path" virtues intact.
3. Cross-reference the SBOM against a real public vulnerability database (OSV.dev) on opt-in, so the SBOM ships actual security signal beyond the tiny built-in `VULNERABLE_SDK_VERSIONS` table.
4. Stay out of Shasta's lane: CVE enrichment via the proprietary Transilience API belongs in Shasta's compliance pipeline, not in Whitney.

## Non-goals

- PDF export (browser print-to-PDF is enough)
- SARIF output (separate slice if any IDE consumer asks)
- GitHub PR-comment auto-post / GitHub Pages publishing
- Indirect-dependency enumeration in the SBOM (still direct-deps only)
- Interactive sorting/filtering / drill-down panels (Approach C territory; not in scope)
- Web fonts, JavaScript frameworks, build tooling
- Multi-language source coverage (still Python-only per Phase A scope)

## Architecture

### New module: `whitney/html_report.py`

Single file, ~300 lines. Pure rendering — no file I/O inside the module. Two public functions:

```python
def render_scan_html(findings: list[Finding], scan_root: Path) -> str:
    """Return a complete self-contained HTML document for a scan result."""

def render_sbom_html(sbom: dict) -> str:
    """Return a complete self-contained HTML document for an SBOM dict."""
```

Templating uses stdlib only: f-string interpolation with `html.escape()` on every user-content field, `urllib.parse.quote()` on any value used in a URL. One inline `<style>` block. One `<script type="application/json" id="whitney-data">` block at end carrying the raw input data for `jq` extraction.

### CLI integration

Modify `whitney/cli.py`:

- `scan` subcommand: add `--html PATH`. Coexists with `--json` (both written if both set).
- `sbom` subcommand: add `--html PATH` and `--enrich` (opt-in OSV.dev cross-reference).

```bash
whitney scan ./repo --html report.html
whitney sbom ./repo --html sbom.html --enrich
```

When `--html PATH` is set: create `PATH.parent` if missing, overwrite `PATH` without prompting (CI-friendly).

### Dependencies

Zero new runtime deps. `pyproject.toml` stays at `dependencies = ["semgrep>=1.150"]`. Network call for `--enrich` uses `urllib.request` (stdlib).

`pyproject.toml` version bump 0.1.0 → 0.2.0 (additive feature, but worth signalling).

### Backwards compatibility

All changes additive. Default CLI behaviour unchanged. Existing `whitney scan ./repo` users see no difference unless they pass `--html`.

## Report structure

### Shared shell (both reports)

- `<header>` — text-only Whitney logo, report title, subtitle (`Scanned ./my-repo · 2026-04-26 14:30 UTC · 41 findings`), Whitney version
- `<nav>` (sticky on scroll) — anchor links to each section, severity filter pills (CSS-only via `:has()` selectors, no JS)
- Content sections (vary by report)
- `<footer>` — link to github.com/transilienceai/whitney, version, generation timestamp
- `<script type="application/json" id="whitney-data">` carrying raw JSON for `jq` extraction

### `whitney scan --html` sections

1. **Summary cards row** — 4 severity-coded tiles (Critical / High / Medium-Low / Total).
2. **Top offenders** (rendered only when total findings > 10) — top 5 files by count, top 3 check_ids by frequency.
3. **Findings list** — stacked cards, severity-grouped with sticky headers (Critical first). Each card:
   - Severity badge + check_id + file_path:line_number (rendered as `vscode://file/<absolute_path>:<line>` link)
   - Title (single line)
   - Code snippet from `details.code_snippet` (preserved indentation, monospace, line-numbered gutter)
   - Tag chips: CWE / OWASP LLM Top 10 / OWASP Agentic / technology
   - Remediation text in `<details>` (closed by default)
4. **Suppressed-by-triage** (rendered only if any finding has `details.suppressed_by_llm_triage`) — separate panel listing the triage-suppressed findings with model_id + prompt_version.

### `whitney sbom --html` sections

1. **Summary cards row** — SDKs / Models / Vulnerabilities / Providers counts.
2. **Provider grouping** — components clustered by provider (OpenAI / Anthropic / AWS / Azure / etc.). Coloured strip header per group with component count.
3. **Components table** — name, version, type (sdk/model/cloud_service), ecosystem, source file, purl. Sortable deferred (v1 is render-order only).
4. **Vulnerabilities panel** (rendered only if `sbom["vulnerabilities"]` is non-empty after enrichment) — each vuln as a card: CVE/GHSA ID + severity badge + affected `package@version` + description + affected version range + fix version (if known) + link to source advisory URL.
5. **Enrichment provenance** (footer note) — `Enriched from osv.dev at <UTC timestamp>` or `No enrichment performed (run with --enrich for OSV.dev cross-reference)`.

### Visual style

- System font stack: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif` — no web fonts, no FOUT.
- Light theme default; auto-flip via `@media (prefers-color-scheme: dark)`. No theme toggle button in v1.
- Severity palette (works in both themes): Critical `#dc2626`, High `#ea580c`, Medium `#d97706`, Low `#65a30d`, Info `#0891b2`.
- Generous whitespace, no decorative borders, content-first.
- Max width 1200px, centered.
- Single accent colour `#0891b2`.
- Code blocks: `JetBrains Mono, "SF Mono", Consolas, "Liberation Mono", monospace`, `font-size: 0.875rem`, line-numbered gutter.
- Target file size: <60KB inline for a 50-finding report (no images, no fonts, no JS = naturally small).

## OSV.dev enrichment (`--enrich`)

### Flow

1. After `scan_ai_sbom_code_only()` produces components, walk every component with `component_type == SDK` and a non-empty `version`.
2. POST to `https://api.osv.dev/v1/query` per component:
   ```json
   {"version": "<version>", "package": {"name": "<name>", "ecosystem": "PyPI" | "npm"}}
   ```
   No auth required. Public rate limit ≈ 100 req/s.
3. Parse `vulns[]`: each entry yields `id` (GHSA-* or CVE-*), `summary`, `severity`, `affected[].ranges[]` (introduced / fixed versions), `references[].url`. Fold into the SBOM's `vulnerabilities` list using the existing dict shape.
4. Merge with built-in `VULNERABLE_SDK_VERSIONS` table (additive, not replacement). Dedupe by CVE/GHSA ID.

### Caching

Keyed by `(ecosystem, name, version, query_date)` where `query_date` is the calendar UTC day. Persisted to `~/.whitney/osv_cache.json` — same persistence model as `whitney/llm_triage.py`'s triage cache. Re-running enrichment on the same SBOM same day is free.

### Concurrency

`concurrent.futures.ThreadPoolExecutor` with `max_workers=8`. Real-world AI-component SBOMs are typically <30 SDKs; finishes in ~1s.

### Rate guard

`MAX_OSV_QUERIES_PER_RUN = 200`. Above the cap: log warning and stop enriching further components — fail-open, render the report with partial enrichment marked as such.

### Error handling (consistent with Whitney's existing patterns)

- **OSV unreachable / 5xx:** log warning, render report with built-in table only. Footer notes `enrichment skipped: <reason>`. Exit code 0.
- **Single-component query fails:** skip that component, continue. Log debug-level only.
- **HTML render fails (rare — malformed Finding/SBOM):** log error, exit non-zero, do NOT write a partial HTML file.
- **`--html PATH` parent missing:** auto-create with `PATH.parent.mkdir(parents=True, exist_ok=True)`.
- **`PATH` already exists:** overwrite without prompting.
- **XSS hardening:** every user-content interpolation goes through `html.escape()`. Every URL value goes through `urllib.parse.quote()`. Tested explicitly (see Testing).

## Why OSV.dev (not Transilience)

Transilience belongs in Shasta. Whitney is the open-source, standalone, zero-network-by-default scanner. Wiring a proprietary API key into an OSS tool's primary feature path:

- Adds API-key config friction to the "pip install whitney; whitney sbom ./repo" first-experience demo
- Weakens the "no network calls in default path" claim that's load-bearing in the README
- Couples Whitney's reliability to Transilience's uptime

OSV.dev is the right CVE source for OSS:

- Free, no auth, comprehensive (PyPI / npm / Go / Cargo / Maven / NuGet / Linux distros — covers every ecosystem Whitney's SBOM might surface)
- Google-backed, well-maintained
- Same data Snyk / GitHub Advisory Database / pip-audit ultimately resolve to

Shasta consumes Whitney's CycloneDX JSON and applies Transilience enrichment as part of its compliance pipeline. The plug-point is generic ("an enrichment provider takes an SBOM and returns vulnerabilities") so Shasta can wire Transilience there without Whitney needing to know.

## Testing (`tests/test_html_report.py`)

Three test classes. No HTML snapshot files (snapshots break on every cosmetic CSS change).

### `TestRenderScanHtml`

- Document parses as valid HTML5 (use stdlib `html.parser`)
- Every finding's `file_path` appears verbatim in output
- Every distinct severity badge is present
- The `<script type="application/json">` block round-trips: parse it, assert it equals input list
- XSS test: a finding with `details.code_snippet = '<script>alert(1)</script>'` produces escaped output, no live `<script>` element in body

### `TestRenderSbomHtml`

- Document parses as valid HTML5
- All components appear by name and version
- Vulnerabilities panel rendered iff `sbom["vulnerabilities"]` non-empty
- Provider grouping: components correctly clustered
- Same XSS test for component name and source-file fields

### `TestEnrichOsv`

- Mock `urllib.request.urlopen` to return canned OSV responses
- Assert correct fold of vulns into SBOM dict
- Test rate-limit cap fires at `MAX_OSV_QUERIES_PER_RUN`
- Test cache hit path (second call to same component returns cached, no network)
- Test network-failure fallback (renders report with built-in table only, no exception propagated)

No new dev deps. Stdlib + pytest (already in `[dev]`).

## Files touched

**New:**
- `whitney/html_report.py` (~300 lines)
- `tests/test_html_report.py` (~250 lines)
- `docs/superpowers/specs/2026-04-26-html-reports-design.md` (this file)

**Modified:**
- `whitney/cli.py` — add `--html` to scan + sbom, add `--enrich` to sbom
- `whitney/sbom.py` — add `enrich_with_osv()` function (the OSV query + cache + fold logic)
- `pyproject.toml` — version 0.1.0 → 0.2.0
- `README.md` — short section on `--html` flag (1-2 paragraphs); link to a sample report
- `docs/SCANNER.md` — note `--html` in the Usage section

**Demo artifact (committed for showcase):**
- `docs/sample-reports/scan.html` — generated by running Whitney against a known repo (e.g., `aimaster-dev/chatbot-using-rag-and-langchain` from the blind-test set) and committing the output. Lets visitors preview without installing.
- `docs/sample-reports/sbom.html` — same, for SBOM with `--enrich`.

## Verification

End-to-end manual checks before declaring done:

1. `pytest tests/test_html_report.py -v` → all green
2. `whitney scan ./tests/corpus/prompt_injection/positives --html /tmp/scan.html && open /tmp/scan.html` → renders correctly in Safari, Firefox, Chrome (no JS errors in console; no broken layout)
3. `whitney sbom ./tests/corpus --html /tmp/sbom.html` → renders without `--enrich`, footer shows the no-enrichment notice
4. `whitney sbom <real-AI-repo> --html /tmp/sbom_enriched.html --enrich` → renders with vulnerabilities populated from OSV; second run hits the cache and completes in <100ms
5. View source on a generated report: confirm `<script type="application/json" id="whitney-data">` block is present and `cat /tmp/scan.html | grep -A 999 'whitney-data' | grep -B 999 '</script>' | sed '1d;$d' | jq` extracts the findings
6. Print-to-PDF in browser produces a usable PDF (verifies the layout doesn't depend on viewport quirks)

## Open questions

None at design freeze. (`vscode://` link target uses absolute paths — will work for the local user running the scan but not for shared reports across machines. Acceptable: the report is primarily a local-dev artifact and a demo asset, not a multi-user dashboard.)

## Out of scope (YAGNI)

- PDF export
- SARIF output
- GitHub PR-comment auto-post
- GitHub Pages publish workflow
- `requirements-frozen.txt` / lockfile parsing for indirect deps
- Interactive sorting / filtering (Approach C territory)
- Light/dark theme toggle button
- Web fonts
- Multi-language source coverage
