"""Whitney — open-source static AI security scanner.

Whitney scans application source code for AI security vulnerabilities:
prompt injection across 15 source types, broken LLM-as-judge defenses,
critical agent sinks (PAL/SQL chains), and AI dependency SBOM extraction.

The detection layer is a curated Semgrep ruleset plus a thin Python
wrapper. The default scan path has zero LLM calls and produces
byte-identical output across runs. An opt-in LLM-as-judge classifier
(Claude Opus) is available behind ``WHITNEY_STRICT_JUDGE_PROMPTS=1``
for users who want the final precision lift on guard-style defenses.

Public API:

    from whitney import scan_repository, generate_ai_sbom
    findings = scan_repository("./my-repo")
    sbom = generate_ai_sbom("./my-repo")

CLI:

    whitney scan ./my-repo --json > findings.json
    whitney sbom ./my-repo --output sbom.json

Project: https://github.com/transilienceai/whitney
"""

from whitney.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)
from whitney.scanner import (
    SemgrepNotInstalledError,
    scan_repository,
)

__version__ = "0.1.0"

__all__ = [
    "scan_repository",
    "SemgrepNotInstalledError",
    "Finding",
    "Severity",
    "ComplianceStatus",
    "CheckDomain",
    "__version__",
]
