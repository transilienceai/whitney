"""Whitney code scanner — entry point.

This is the public interface for Whitney's static AI-security source
code scanner. It runs Semgrep (via :mod:`whitney.semgrep_runner`)
against a repository and returns a list of :class:`Finding` objects.

The scanner is intentionally thin — ~20 lines of orchestration logic.
All detection complexity lives in the Semgrep rule YAML files under
``whitney/rules/``.

Compliance framework enrichment (ISO 42001, EU AI Act, NIST AI RMF,
MITRE ATLAS, etc.) is **not** performed by Whitney — it is the
responsibility of downstream tooling that consumes Whitney's findings.
Whitney findings carry CWE, OWASP LLM Top 10, and OWASP Agentic Top 10
metadata directly in each rule's YAML, so those tags ship with the
finding for free. Regulatory framework mapping is a separate concern
and lives in the Shasta compliance package or any equivalent layer
the consumer wants to plug in.

LLM-as-judge triage (Phase D) is opt-in via the
``WHITNEY_STRICT_JUDGE_PROMPTS`` environment variable. When unset,
the default scan path has zero LLM calls and produces byte-identical
output across runs. See :mod:`whitney.llm_triage` for details.
"""
from __future__ import annotations

import logging
from pathlib import Path

from whitney.models import Finding
from whitney.semgrep_runner import (
    SemgrepNotInstalledError,
    run_semgrep,
)

log = logging.getLogger(__name__)

__all__ = ["scan_repository", "SemgrepNotInstalledError", "Finding"]


def scan_repository(repo_path: Path | str) -> list[Finding]:
    """Scan a repository for AI security issues.

    Runs Semgrep against the given path using Whitney's bundled rules.
    Each finding carries CWE / OWASP LLM Top 10 / OWASP Agentic Top 10
    tags from the rule metadata. Regulatory framework enrichment is
    not performed here — that lives in downstream consumers (e.g.,
    Shasta's compliance mapper).

    Args:
        repo_path: Directory or file to scan.

    Raises:
        SemgrepNotInstalledError: If the ``semgrep`` CLI is missing.

    Returns:
        A list of :class:`Finding` objects, one per detected issue.
    """
    repo_path = Path(repo_path)

    findings = run_semgrep(repo_path)

    # Phase D — LLM-as-judge triage (opt-in via WHITNEY_STRICT_JUDGE_PROMPTS).
    # When disabled (the default), this is a no-op. When enabled, findings
    # on files containing a correctly-implemented LLM-as-judge defense are
    # suppressed. See whitney.llm_triage for details.
    try:
        from whitney.llm_triage import (
            apply_llm_triage_to_findings,
            is_triage_enabled,
        )

        if is_triage_enabled():
            findings, suppressed = apply_llm_triage_to_findings(
                findings, scan_root=repo_path
            )
            if suppressed:
                log.info(
                    "LLM triage suppressed %d finding(s) on %d file(s)",
                    len(suppressed),
                    len({f.details.get("file_path") for f in suppressed}),
                )
    except ImportError as exc:
        log.debug("llm_triage module not available, skipping: %s", exc)

    return findings
