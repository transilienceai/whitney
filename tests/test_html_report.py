"""Tests for whitney.html_report and whitney.sbom OSV enrichment.

Three test classes:

- TestRenderScanHtml — structural invariants + XSS hardening for the
  scan report.
- TestRenderSbomHtml — same shape for the SBOM report.
- TestEnrichOsv — mocks ``urllib.request.urlopen`` to validate the OSV
  fold-in, the cache hit path, the per-run cap, and fail-open on network
  error.

No HTML snapshot files — snapshots break on every cosmetic CSS change.
Tests assert content-level invariants (specific strings present, JSON
round-trips, no live ``<script>`` injection from user content).
"""
from __future__ import annotations

import io
import json
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

import pytest

from whitney.html_report import render_sbom_html, render_scan_html
from whitney.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StructureParser(HTMLParser):
    """Minimal HTML5 parser that records tag stack depth and any tag names
    that appear. Used to assert no live ``<script>`` element was injected
    via unescaped user content.
    """

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.script_count_with_text: int = 0
        self._in_script: bool = False
        self._current_script_type: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str]]) -> None:
        self.tags.append(tag)
        if tag == "script":
            attr_dict = dict(attrs)
            self._in_script = True
            self._current_script_type = attr_dict.get("type")

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False
            self._current_script_type = None

    def handle_data(self, data: str) -> None:
        # Count only executable scripts (no `type=` or `type=text/javascript`).
        if (self._in_script
                and self._current_script_type in (None, "text/javascript")
                and data.strip()):
            self.script_count_with_text += 1


def _parse(html: str) -> _StructureParser:
    parser = _StructureParser()
    parser.feed(html)
    return parser


def _make_finding(
    *,
    check_id: str = "code-prompt-injection-risk",
    title: str = "Test finding",
    severity: Severity = Severity.HIGH,
    file_path: str = "app/handler.py",
    line_number: int = 42,
    code_snippet: str = 'prompt = f"hi {user_text}"',
    cwe: list[str] | None = None,
    remediation: str = "Add a guardrail.",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        description=title,
        severity=severity,
        status=ComplianceStatus.FAIL,
        domain=CheckDomain.AI_GOVERNANCE,
        resource_type="Code::Repository::File",
        resource_id=file_path,
        region="code",
        account_id="code-scan",
        remediation=remediation,
        details={
            "file_path": file_path,
            "line_number": line_number,
            "code_snippet": code_snippet,
            "cwe": cwe or ["CWE-94"],
            "owasp": ["LLM01:2025"],
            "owasp_agentic": ["AA01:2026"],
            "technology": ["flask"],
            "confidence": "MEDIUM",
        },
    )


# ---------------------------------------------------------------------------
# Scan report
# ---------------------------------------------------------------------------


class TestRenderScanHtml:
    def test_empty_findings_renders_valid_doc(self, tmp_path: Path) -> None:
        html = render_scan_html([], tmp_path)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html
        # Should render with the empty-state message.
        assert "No findings." in html

    def test_basic_findings_appear_verbatim(self, tmp_path: Path) -> None:
        f = _make_finding(file_path="src/api.py", line_number=99)
        html = render_scan_html([f], tmp_path)
        assert "src/api.py" in html
        assert "99" in html
        assert "code-prompt-injection-risk" in html
        assert "CWE-94" in html
        assert "LLM01:2025" in html
        assert "AA01:2026" in html

    def test_severity_grouping_renders_each_present_bucket(
        self, tmp_path: Path
    ) -> None:
        critical = _make_finding(severity=Severity.CRITICAL, title="A")
        high = _make_finding(severity=Severity.HIGH, title="B")
        low = _make_finding(severity=Severity.LOW, title="C")
        html = render_scan_html([critical, high, low], tmp_path)
        # Severity badge labels appear (in the summary cards AND in the
        # per-severity sticky headers).
        assert html.count("Critical") >= 1
        assert html.count("High") >= 1
        assert html.count("Low") >= 1

    def test_summary_card_counts_match_input(self, tmp_path: Path) -> None:
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
        ]
        html = render_scan_html(findings, tmp_path)
        # The total card should show the literal "3".
        assert ">3<" in html  # appears in `<div class="num">3</div>`

    def test_embedded_json_round_trips(self, tmp_path: Path) -> None:
        f = _make_finding()
        html = render_scan_html([f], tmp_path)
        # Pull out the <script type="application/json"> block.
        marker_open = '<script type="application/json" id="whitney-data">'
        marker_close = "</script>"
        start = html.index(marker_open) + len(marker_open)
        end = html.index(marker_close, start)
        # The renderer escapes "</" → "<\\/" inside the JSON; reverse before parse.
        json_blob = html[start:end].replace("<\\/", "</").strip()
        parsed = json.loads(json_blob)
        assert isinstance(parsed, list)
        assert len(parsed) == 1
        assert parsed[0]["check_id"] == "code-prompt-injection-risk"

    def test_xss_in_code_snippet_is_escaped(self, tmp_path: Path) -> None:
        """A finding whose code_snippet contains a live <script> element
        must NOT inject an executable script into the rendered page."""
        f = _make_finding(
            code_snippet='<script>alert(1)</script>',
            file_path='evil.py',
        )
        html = render_scan_html([f], tmp_path)
        # The literal escaped form must be present in the body.
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        # And the parser should see only the data-block <script>
        # (type="application/json"), no executable script with body content.
        parser = _parse(html)
        assert parser.script_count_with_text == 0

    def test_xss_in_file_path_is_escaped(self, tmp_path: Path) -> None:
        f = _make_finding(file_path='"><script>alert(1)</script>')
        html = render_scan_html([f], tmp_path)
        # Crucially: no executable script element from the file_path injection.
        parser = _parse(html)
        assert parser.script_count_with_text == 0

    def test_top_offenders_only_when_findings_exceed_threshold(
        self, tmp_path: Path
    ) -> None:
        # 5 findings: no top-offenders panel.
        few = [_make_finding(file_path=f"f{i}.py") for i in range(5)]
        html = render_scan_html(few, tmp_path)
        assert "Top offenders" not in html

        # 11 findings: panel renders.
        many = [_make_finding(file_path=f"f{i}.py") for i in range(11)]
        html = render_scan_html(many, tmp_path)
        assert "Top offenders" in html

    def test_triage_suppressed_panel_renders_when_present(
        self, tmp_path: Path
    ) -> None:
        f = _make_finding()
        f.details["suppressed_by_llm_triage"] = {
            "model": "claude-opus-4-6",
            "prompt_version": "v1",
            "reason": "judge classified as defended",
        }
        html = render_scan_html([f], tmp_path)
        assert "Suppressed by LLM triage" in html
        assert "claude-opus-4-6" in html

    def test_remediation_in_collapsible_details(self, tmp_path: Path) -> None:
        f = _make_finding(remediation="Apply a recognised guardrail.")
        html = render_scan_html([f], tmp_path)
        assert "<details>" in html
        assert "Apply a recognised guardrail." in html


# ---------------------------------------------------------------------------
# SBOM report
# ---------------------------------------------------------------------------


def _make_sbom(*, components: list[dict] | None = None,
                vulnerabilities: list[dict] | None = None,
                enrichment: dict | None = None) -> dict:
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "timestamp": "2026-04-26T00:00:00Z",
            "component": {
                "type": "application",
                "name": "ai-inventory-test",
                "version": "1.0.0",
            },
        },
        "components": components or [],
        "vulnerabilities": vulnerabilities or [],
    }
    if enrichment is not None:
        sbom["enrichment"] = enrichment
    return sbom


def _component(name: str, version: str, *, provider: str = "openai",
                ecosystem: str = "pypi", ctype: str = "sdk") -> dict:
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem}/{name}@{version}",
        "properties": [
            {"name": "whitney:component_type", "value": ctype},
            {"name": "whitney:provider", "value": provider},
            {"name": "whitney:ecosystem", "value": ecosystem},
            {"name": "whitney:source", "value": "code:requirements.txt"},
        ],
    }


class TestRenderSbomHtml:
    def test_empty_sbom_renders_valid_doc(self) -> None:
        html = render_sbom_html(_make_sbom())
        assert html.startswith("<!DOCTYPE html>")
        assert "No AI components found." in html

    def test_components_appear_grouped_by_provider(self) -> None:
        sbom = _make_sbom(components=[
            _component("openai", "1.0.0", provider="openai"),
            _component("anthropic", "0.25.0", provider="anthropic"),
            _component("langchain", "0.0.300", provider="langchain"),
        ])
        html = render_sbom_html(sbom)
        # All three components surface by name.
        for n in ("openai", "anthropic", "langchain"):
            assert n in html
        # Provider strips render with provider names as headers.
        assert html.count("provider-strip") >= 3

    def test_vulnerabilities_panel_renders_iff_present(self) -> None:
        # No vulns → no panel.
        html = render_sbom_html(_make_sbom(components=[
            _component("openai", "1.0.0"),
        ]))
        assert "Known vulnerabilities" not in html

        # With vulns → panel renders.
        html = render_sbom_html(_make_sbom(
            components=[_component("langchain", "0.0.300", provider="langchain")],
            vulnerabilities=[{
                "id": "CVE-2023-46229", "package": "langchain",
                "version": "0.0.300", "severity": "high",
                "description": "PALChain RCE via prompt injection",
                "constraint": "< 0.0.325", "fix_version": "0.0.325",
            }],
        ))
        assert "Known vulnerabilities" in html
        assert "CVE-2023-46229" in html
        assert "PALChain RCE" in html

    def test_enrichment_provenance_shows_source(self) -> None:
        sbom = _make_sbom(
            components=[_component("openai", "1.0.0")],
            enrichment={
                "source": "osv.dev",
                "timestamp": "2026-04-26 12:00 UTC",
                "queried": 5, "cached": 2, "components_considered": 7,
            },
        )
        html = render_sbom_html(sbom)
        assert "osv.dev" in html
        # No "Re-run with --enrich" prompt when enrichment is present.
        assert "Re-run with" not in html

    def test_no_enrichment_prompt_when_absent(self) -> None:
        html = render_sbom_html(_make_sbom(components=[
            _component("openai", "1.0.0"),
        ]))
        assert "--enrich" in html
        assert "OSV.dev" in html

    def test_summary_card_counts(self) -> None:
        sbom = _make_sbom(
            components=[
                _component("openai", "1.0.0", ctype="sdk"),
                _component("anthropic", "0.25.0", ctype="sdk"),
                _component("gpt-4", "", ctype="model", provider="openai"),
            ],
            vulnerabilities=[{"id": "CVE-X", "package": "x", "severity": "high"}],
        )
        html = render_sbom_html(sbom)
        # SDKs=2, Models=1, Vulnerabilities=1 should all appear as `<num>`.
        assert ">2<" in html  # SDKs
        assert ">1<" in html  # multiple cards have count 1

    def test_xss_in_component_name_is_escaped(self) -> None:
        sbom = _make_sbom(components=[
            _component('"><script>alert(1)</script>', "1.0.0"),
        ])
        html = render_sbom_html(sbom)
        parser = _parse(html)
        assert parser.script_count_with_text == 0

    def test_embedded_json_round_trips(self) -> None:
        sbom = _make_sbom(components=[_component("openai", "1.0.0")])
        html = render_sbom_html(sbom)
        marker_open = '<script type="application/json" id="whitney-data">'
        marker_close = "</script>"
        start = html.index(marker_open) + len(marker_open)
        end = html.index(marker_close, start)
        json_blob = html[start:end].replace("<\\/", "</").strip()
        parsed = json.loads(json_blob)
        assert parsed["bomFormat"] == "CycloneDX"
        assert len(parsed["components"]) == 1


# ---------------------------------------------------------------------------
# OSV enrichment
# ---------------------------------------------------------------------------


def _mock_osv_response(vulns: list[dict]) -> mock.MagicMock:
    """Build a mock urlopen return value carrying OSV-shaped JSON."""
    body = json.dumps({"vulns": vulns}).encode("utf-8")
    resp = mock.MagicMock()
    resp.__enter__ = lambda self: resp
    resp.__exit__ = lambda *a: None
    resp.read.return_value = body
    return resp


class TestEnrichOsv:
    def test_no_sdk_components_returns_unchanged(self, tmp_path,
                                                  monkeypatch) -> None:
        from whitney import sbom as sbom_mod
        # Force a fresh cache file to a temp path so the test doesn't pollute.
        monkeypatch.setattr(sbom_mod, "OSV_CACHE_FILE",
                            tmp_path / "osv_cache.json")
        sbom = _make_sbom(components=[
            _component("gpt-4", "", ctype="model", ecosystem="ai"),
        ])
        result = sbom_mod.enrich_with_osv(sbom)
        # No targets to query → no enrichment block written.
        assert "enrichment" not in result

    def test_osv_match_folds_into_vulnerabilities(self, tmp_path,
                                                    monkeypatch) -> None:
        from whitney import sbom as sbom_mod
        monkeypatch.setattr(sbom_mod, "OSV_CACHE_FILE",
                            tmp_path / "osv_cache.json")

        canned = [{
            "id": "GHSA-xxxx-yyyy",
            "aliases": ["CVE-2023-46229"],
            "summary": "PALChain code execution",
            "severity": [{"score": "CVSS_V3:9.8"}],
            "affected": [{"ranges": [{"events": [
                {"introduced": "0"},
                {"fixed": "0.0.325"},
            ]}]}],
            "references": [{"url": "https://github.com/advisory/example"}],
        }]
        with mock.patch.object(sbom_mod, "_urlreq") as urlreq:
            urlreq.urlopen.return_value = _mock_osv_response(canned)
            urlreq.Request = mock.MagicMock()
            sbom = _make_sbom(components=[
                _component("langchain", "0.0.300", ecosystem="pypi",
                           provider="langchain"),
            ])
            result = sbom_mod.enrich_with_osv(sbom)

        vulns = result.get("vulnerabilities", [])
        assert any(v.get("id") == "GHSA-xxxx-yyyy" for v in vulns)
        v = next(v for v in vulns if v.get("id") == "GHSA-xxxx-yyyy")
        assert v["package"] == "langchain"
        assert v["version"] == "0.0.300"
        assert v["fix_version"] == "0.0.325"
        assert v["source"] == "osv.dev"
        # Severity translated from CVSS score.
        assert v["severity"] == "critical"
        # Provenance block populated.
        assert result["enrichment"]["source"] == "osv.dev"
        assert result["enrichment"]["queried"] == 1

    def test_existing_builtin_vulns_not_replaced(self, tmp_path,
                                                   monkeypatch) -> None:
        from whitney import sbom as sbom_mod
        monkeypatch.setattr(sbom_mod, "OSV_CACHE_FILE",
                            tmp_path / "osv_cache.json")
        with mock.patch.object(sbom_mod, "_urlreq") as urlreq:
            urlreq.urlopen.return_value = _mock_osv_response([])
            urlreq.Request = mock.MagicMock()
            sbom = _make_sbom(
                components=[_component("openai", "1.0.0", provider="openai")],
                vulnerabilities=[{
                    "id": "WHITNEY-AI-1",
                    "description": "Built-in entry — pre-1.0 SDK",
                    "package": "openai", "version": "1.0.0", "severity": "medium",
                }],
            )
            result = sbom_mod.enrich_with_osv(sbom)
        ids = {v["id"] for v in result["vulnerabilities"]}
        assert "WHITNEY-AI-1" in ids  # built-in retained

    def test_cache_hit_does_not_query_network(self, tmp_path,
                                                monkeypatch) -> None:
        from whitney import sbom as sbom_mod
        cache_file = tmp_path / "osv_cache.json"
        # Pre-populate the cache for today's date.
        from datetime import date
        key = f"pypi::langchain::0.0.300::{date.today().isoformat()}"
        cache_file.write_text(json.dumps({key: []}), encoding="utf-8")
        monkeypatch.setattr(sbom_mod, "OSV_CACHE_FILE", cache_file)

        with mock.patch.object(sbom_mod, "_urlreq") as urlreq:
            sbom = _make_sbom(components=[
                _component("langchain", "0.0.300", ecosystem="pypi"),
            ])
            result = sbom_mod.enrich_with_osv(sbom)
            urlreq.urlopen.assert_not_called()

        # Still gets an enrichment block (cached counts as queried=0).
        assert result["enrichment"]["queried"] == 0
        assert result["enrichment"]["cached"] == 1

    def test_network_failure_fails_open(self, tmp_path,
                                          monkeypatch) -> None:
        from whitney import sbom as sbom_mod
        monkeypatch.setattr(sbom_mod, "OSV_CACHE_FILE",
                            tmp_path / "osv_cache.json")
        with mock.patch.object(sbom_mod, "_urlreq") as urlreq:
            urlreq.urlopen.side_effect = sbom_mod._urlerror.URLError(
                "network unreachable",
            )
            urlreq.Request = mock.MagicMock()
            sbom = _make_sbom(components=[
                _component("langchain", "0.0.300", ecosystem="pypi"),
            ])
            result = sbom_mod.enrich_with_osv(sbom)

        # No exception, no extra vulns added, but enrichment block still
        # records the attempt.
        assert "enrichment" in result
        # Vulnerability list unchanged from input (which was empty).
        assert result["vulnerabilities"] == []

    def test_query_cap_limits_targets(self, tmp_path,
                                        monkeypatch) -> None:
        from whitney import sbom as sbom_mod
        monkeypatch.setattr(sbom_mod, "OSV_CACHE_FILE",
                            tmp_path / "osv_cache.json")
        monkeypatch.setattr(sbom_mod, "MAX_OSV_QUERIES_PER_RUN", 3)

        components = [
            _component(f"pkg{i}", "1.0.0", ecosystem="pypi")
            for i in range(10)
        ]
        with mock.patch.object(sbom_mod, "_urlreq") as urlreq:
            urlreq.urlopen.return_value = _mock_osv_response([])
            urlreq.Request = mock.MagicMock()
            result = sbom_mod.enrich_with_osv(_make_sbom(components=components))

        # The cap clamps targets to 3, so components_considered = 3.
        assert result["enrichment"]["components_considered"] == 3
