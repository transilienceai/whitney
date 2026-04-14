"""Semgrep runner — spawns the Semgrep CLI and parses its JSON output.

Whitney does not implement its own static analysis engine. This module is
a thin subprocess wrapper around the Semgrep OSS binary; all detection
logic lives in the rule YAML files under ``./rules/``.

The runner is deliberately minimal:

1. Locate the rules directory next to this file.
2. Spawn ``semgrep --config <rules_dir> --json --quiet <scan_path>``.
3. Parse the JSON output into :class:`Finding` objects.
4. Return the list.

Semgrep CLI exit codes (as of semgrep 1.x):

- ``0`` — scan complete, no findings
- ``1`` — scan complete, findings present
- ``2`` — scan complete, findings + non-fatal errors (e.g. per-file parse errors)
- ``>2`` — fatal error (config invalid, CLI not found, crash)

Codes 0/1/2 are all treated as successful scans; codes >2 are logged
and the runner returns an empty list (fail-open on infrastructure errors
so the caller never gets silently stuck).
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from whitney.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)

log = logging.getLogger(__name__)

#: Directory containing Whitney's Semgrep rule YAML files.
RULES_DIR: Path = Path(__file__).parent / "rules"

#: Maximum scan wall-clock time in seconds.
SEMGREP_TIMEOUT_SECONDS: int = 600

#: Semgrep severity → Whitney severity mapping (fallback when rule metadata
#: does not specify ``whitney_severity``).
_SEMGREP_TO_WHITNEY_SEVERITY: dict[str, Severity] = {
    "INFO": Severity.LOW,
    "WARNING": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
}


class SemgrepNotInstalledError(RuntimeError):
    """Raised when the ``semgrep`` CLI is not available on ``PATH``."""


def run_semgrep(
    repo_path: Path,
    rules_dir: Path | None = None,
) -> list[Finding]:
    """Run Semgrep against ``repo_path`` and return parsed Findings.

    Args:
        repo_path: Directory (or file) to scan.
        rules_dir: Directory containing rule YAML files. Defaults to
            Whitney's bundled :data:`RULES_DIR`.

    Raises:
        SemgrepNotInstalledError: If the ``semgrep`` binary is not found.

    Returns:
        A list of :class:`Finding` objects, one per Semgrep result.
        Empty list on any non-fatal failure (missing rules dir, parse
        error, Semgrep fatal exit) — failures are logged, not raised,
        because the caller usually wants to produce a partial scan
        rather than abort.
    """
    rules_dir = rules_dir or RULES_DIR
    if not rules_dir.exists() or not any(rules_dir.glob("*.yaml")):
        log.warning(
            "Semgrep rules directory has no .yaml files: %s — returning []",
            rules_dir,
        )
        return []

    # Path excludes — vendored code, virtualenvs, test fixtures, example/demo
    # directories, and build outputs are noise. A finding inside `venv/` or
    # `tests/fixtures/` is an FP from the user's perspective regardless of
    # its technical correctness. Added after the blind-test "egg on face"
    # check flagged that Whitney had no default excludes.
    _EXCLUDES = [
        "venv", ".venv", "env", ".env",
        "__pycache__", ".git", ".tox", ".mypy_cache", ".pytest_cache",
        "node_modules", "dist", "build", ".eggs", "*.egg-info",
        "tests", "test", "test_*", "*_test.py", "*_tests.py",
        "fixtures", "examples", "example", "docs", "doc",
        "site-packages",
    ]
    cmd = [
        "semgrep",
        "--config",
        str(rules_dir),
        "--json",
        "--quiet",
        "--no-git-ignore",
    ]
    for ex in _EXCLUDES:
        cmd.extend(["--exclude", ex])
    cmd.append(str(repo_path))

    try:
        # Force UTF-8 decoding. On Windows the default is cp1252 which
        # chokes on em dashes and other non-ASCII characters commonly
        # present in rule messages and source code snippets. errors="replace"
        # so a single weird byte doesn't nuke the entire scan output.
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SEMGREP_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise SemgrepNotInstalledError(
            "Semgrep CLI not found on PATH. Install with `pip install semgrep`."
        ) from exc
    except subprocess.TimeoutExpired:
        log.error("Semgrep scan timed out after %ss", SEMGREP_TIMEOUT_SECONDS)
        return []

    if result.returncode > 2:
        log.error(
            "Semgrep failed (exit %s): %s",
            result.returncode,
            (result.stderr or "")[:500],
        )
        return []

    try:
        data = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError as exc:
        log.error("Failed to parse Semgrep JSON output: %s", exc)
        return []

    findings: list[Finding] = []
    for semgrep_result in data.get("results", []):
        finding = _semgrep_result_to_finding(semgrep_result)
        if finding is not None:
            findings.append(finding)

    return findings


def _semgrep_result_to_finding(sr: dict[str, Any]) -> Finding | None:
    """Convert a single Semgrep result dict into a Whitney :class:`Finding`.

    Returns ``None`` on parse error (logged).
    """
    try:
        extra = sr.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}

        # check_id: prefer the Whitney-canonical check_id from metadata over
        # Semgrep's rule id (which is unique per rule, e.g., "whitney-prompt-
        # injection-taint-comprehensive"). The canonical check_id is what
        # compliance/mapper.py uses to look up framework controls.
        check_id = metadata.get("check_id") or sr.get("check_id", "unknown")

        # severity: prefer whitney_severity metadata over Semgrep severity.
        whitney_sev = metadata.get("whitney_severity")
        if whitney_sev:
            try:
                severity = Severity(str(whitney_sev).lower())
            except ValueError:
                log.warning(
                    "Invalid whitney_severity %r in rule %s; defaulting to MEDIUM",
                    whitney_sev,
                    check_id,
                )
                severity = Severity.MEDIUM
        else:
            semgrep_sev = str(extra.get("severity", "WARNING")).upper()
            severity = _SEMGREP_TO_WHITNEY_SEVERITY.get(semgrep_sev, Severity.MEDIUM)

        raw_message = str(extra.get("message", "")).strip()
        first_line = raw_message.split("\n", 1)[0] if raw_message else check_id
        title = first_line[:120] or check_id
        description = raw_message or title
        remediation = str(metadata.get("remediation", "") or "")

        file_path = str(sr.get("path", ""))
        start = sr.get("start", {}) or {}
        end = sr.get("end", {}) or {}
        line_number = int(start.get("line", 0) or 0)

        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.AI_GOVERNANCE,
            resource_type="Code::Repository::File",
            resource_id=file_path,
            region="code",
            account_id="code-scan",
            remediation=remediation,
            soc2_controls=list(metadata.get("soc2_controls", []) or []),
            details={
                "file_path": file_path,
                "line_number": line_number,
                "end_line": int(end.get("line", line_number) or line_number),
                "code_snippet": str(extra.get("lines", "") or ""),
                "semgrep_rule_id": str(sr.get("check_id", "") or ""),
                "engine": "semgrep",
                "cwe": list(metadata.get("cwe", []) or []),
                "owasp": list(metadata.get("owasp", []) or []),
                "owasp_agentic": list(metadata.get("owasp_agentic", []) or []),
                "confidence": str(metadata.get("confidence", "") or ""),
                "technology": list(metadata.get("technology", []) or []),
            },
        )
    except Exception as exc:  # pragma: no cover — defensive parse guard
        log.warning("Failed to parse Semgrep result: %s", exc)
        return None
