"""Whitney AI SBOM (Model Bill of Materials) scanner.

Discovers AI components across code repositories and cloud environments,
outputting a CycloneDX 1.5 JSON inventory of AI SDKs, models, and services.

Code-only mode: scans dependency files and source code for AI SDKs and
models. Cloud-aware SBOM (AWS Bedrock / SageMaker, Azure OpenAI / ML)
lives separately in the Shasta package.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

# ---------------------------------------------------------------------------
# Self-contained file/parsing helpers and constants.
#
# These were previously imported from whitney.code.checks and
# whitney.code.patterns, both of which were deleted in the 2026-04-13
# Whitney rebuild (commit 0d7946d). Inlining them here makes the SBOM
# scanner self-contained and ready for the Day 2 move into the standalone
# Whitney repo with zero external dependencies.
# ---------------------------------------------------------------------------

MAX_FILE_SIZE_BYTES = 1_000_000

EXCLUDED_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
        ".egg-info", ".eggs",
    }
)

SOURCE_CODE_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb"}
)

ALL_SCANNABLE_EXTENSIONS: frozenset[str] = SOURCE_CODE_EXTENSIONS | frozenset(
    {".yaml", ".yml", ".json", ".toml", ".cfg", ".ini",
     ".txt", ".md", ".env", ".sh", ".bash"}
)

# Vulnerable SDK versions for SBOM vulnerability checks.
VULNERABLE_SDK_VERSIONS: dict[str, list[dict[str, str]]] = {
    "langchain": [
        {
            "constraint": "< 0.0.325",
            "cve": "CVE-2023-46229",
            "description": "Arbitrary code execution via prompt injection in PALChain",
        },
    ],
    "openai": [
        {
            "constraint": "< 1.0.0",
            "cve": "N/A",
            "description": "Pre-1.0 SDK has deprecated API patterns and lacks safety defaults",
        },
    ],
    "transformers": [
        {
            "constraint": "< 4.36.0",
            "cve": "CVE-2023-49810",
            "description": "Unsafe pickle deserialization in model loading",
        },
    ],
}

# Generic (unpinned) model name patterns for the model-version SBOM check.
GENERIC_MODEL_NAMES: list[re.Pattern[str]] = [
    re.compile(r"""model\s*=\s*["']gpt-4["']"""),
    re.compile(r"""model\s*=\s*["']gpt-3\.5-turbo["']"""),
    re.compile(r"""model\s*=\s*["']gpt-4-turbo["']"""),
    re.compile(r"""model\s*=\s*["']gpt-4o["']"""),
    re.compile(r"""model\s*=\s*["']claude-3-opus["']"""),
    re.compile(r"""model\s*=\s*["']claude-3-sonnet["']"""),
    re.compile(r"""model\s*=\s*["']claude-3-haiku["']"""),
]

# Models with date suffixes (gpt-4-0613, claude-3-5-sonnet-20240620) are pinned.
PINNED_MODEL_PATTERN: re.Pattern[str] = re.compile(
    r"""model\s*=\s*["'][a-z0-9-]+-\d{4,8}["']"""
)


def _iter_files(
    repo_path: Path,
    extensions: frozenset[str] | None = None,
    include_hidden_env: bool = False,
) -> list[Path]:
    """Walk *repo_path* and yield files matching *extensions*."""
    if extensions is None:
        extensions = ALL_SCANNABLE_EXTENSIONS
    files: list[Path] = []
    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue
        if any(seg in path.parts for seg in EXCLUDED_PATH_SEGMENTS):
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue
        suffix = path.suffix.lower()
        if suffix in extensions:
            files.append(path)
        elif (
            include_hidden_env
            and path.name.startswith(".env")
            and not path.name.endswith(".example")
        ):
            files.append(path)
    return files


def _read_file(path: Path) -> str | None:
    """Read file contents, returning None on encoding errors."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _parse_requirements_txt(content: str) -> dict[str, str]:
    """Extract package==version pairs from requirements.txt."""
    deps: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for sep in ("==", ">=", "<=", "~=", "!="):
            if sep in line:
                name, version = line.split(sep, 1)
                deps[name.strip().lower()] = (
                    version.strip().split(",")[0].split(";")[0].strip()
                )
                break
    return deps


def _parse_pyproject_toml(content: str) -> dict[str, str]:
    """Best-effort extraction of dependencies from pyproject.toml."""
    deps: dict[str, str] = {}
    for m in re.finditer(
        r'"([a-zA-Z0-9_-]+)\s*([><=!~]+)\s*([0-9][0-9a-zA-Z.]*)"', content
    ):
        deps[m.group(1).lower()] = m.group(3)
    return deps


def _parse_package_json(content: str) -> dict[str, str]:
    """Best-effort extraction of dependencies from package.json."""
    import json as _json

    deps: dict[str, str] = {}
    try:
        data = _json.loads(content)
    except _json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            clean = re.sub(r"^[^0-9]*", "", version)
            if clean:
                deps[name.lower()] = clean
    return deps


def _version_tuple(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for p in version.split("."):
        num = re.match(r"(\d+)", p)
        if num:
            parts.append(int(num.group(1)))
        else:
            break
    return tuple(parts)


def _version_matches_constraint(version_str: str, constraint: str) -> bool:
    """Check if *version_str* matches a simple '< X.Y.Z' constraint."""
    m = re.match(r"<\s*([0-9][0-9a-zA-Z.]*)", constraint)
    if not m:
        return False
    threshold = m.group(1)
    try:
        return _version_tuple(version_str) < _version_tuple(threshold)
    except (ValueError, TypeError):
        return False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known AI packages: lowercase name -> provider
KNOWN_AI_PACKAGES: dict[str, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "langchain": "langchain",
    "langchain-core": "langchain",
    "langchain-community": "langchain",
    "langchain-openai": "langchain",
    "transformers": "huggingface",
    "cohere": "cohere",
    "huggingface_hub": "huggingface",
    "huggingface-hub": "huggingface",
    "google-generativeai": "google",
    "replicate": "replicate",
    "together": "together",
    "groq": "groq",
    "mistralai": "mistral",
    "boto3": "aws",  # included when used with bedrock/sagemaker
    "azure-ai-openai": "azure",
    "litellm": "litellm",
    "ollama": "ollama",
    "vllm": "vllm",
    # npm
    "@anthropic-ai/sdk": "anthropic",
    "@google/generative-ai": "google",
}

# Model name prefix -> provider
MODEL_PROVIDER_PREFIXES: dict[str, str] = {
    "gpt-": "openai",
    "o1-": "openai",
    "o3-": "openai",
    "claude-": "anthropic",
    "gemini-": "google",
    "llama-": "meta",
    "mistral-": "mistral",
    "mixtral-": "mistral",
    "command-": "cohere",
    "embed-": "cohere",
}

# Broader model= assignment pattern
MODEL_ASSIGNMENT_PATTERN: re.Pattern[str] = re.compile(
    r"""model\s*=\s*["']([a-zA-Z0-9._/-]+(?:[-:][a-zA-Z0-9._/-]+)*)["']"""
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class AIComponentType(str, Enum):
    """Type of AI component in the inventory."""

    SDK = "sdk"
    MODEL = "model"
    CLOUD_SERVICE = "cloud_service"


@dataclass
class AIComponent:
    """A single AI component discovered in the inventory."""

    name: str
    version: str  # "1.3.0" for SDKs, "" for models/services
    component_type: AIComponentType
    provider: str  # "openai", "anthropic", "aws", "azure", etc.
    ecosystem: str  # "pypi", "npm", "aws", "azure"
    source: str  # "code:requirements.txt", "aws:bedrock", etc.
    purl: str = ""


@dataclass
class AISBOMReport:
    """AI-specific Software Bill of Materials report."""

    account_id: str
    generated_at: str
    total_components: int = 0
    component_types: dict[str, int] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    components: list[AIComponent] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _infer_model_provider(model_name: str) -> str:
    """Infer the AI provider from a model name."""
    lower = model_name.lower()
    for prefix, provider in MODEL_PROVIDER_PREFIXES.items():
        if lower.startswith(prefix):
            return provider
    return "unknown"


def _make_purl(ecosystem: str, name: str, version: str = "") -> str:
    """Build a Package URL string."""
    if version:
        return f"pkg:{ecosystem}/{name}@{version}"
    return f"pkg:{ecosystem}/{name}"


# ---------------------------------------------------------------------------
# Code scanning
# ---------------------------------------------------------------------------


def scan_code_for_ai_components(repo_path: str | Path) -> list[AIComponent]:
    """Scan dependency files and source code for AI SDKs and models.

    Returns a list of AIComponent objects for discovered AI SDKs (from
    dependency files) and AI models (from model= assignments in source code).
    """
    repo_path = Path(repo_path)
    components: list[AIComponent] = []
    seen_sdks: set[tuple[str, str]] = set()  # (name, version) dedup
    seen_models: set[str] = set()  # model name dedup

    # --- 1. Scan dependency files for AI SDKs ---
    dep_files: dict[str, tuple] = {
        "requirements.txt": (_parse_requirements_txt, "pypi"),
        "pyproject.toml": (_parse_pyproject_toml, "pypi"),
        "package.json": (_parse_package_json, "npm"),
    }

    for fname, (parser, ecosystem) in dep_files.items():
        for fpath in repo_path.rglob(fname):
            if any(seg in fpath.parts for seg in EXCLUDED_PATH_SEGMENTS):
                continue
            content = _read_file(fpath)
            if content is None:
                continue
            deps = parser(content)
            for pkg_name, version in deps.items():
                pkg_lower = pkg_name.lower()
                if pkg_lower not in KNOWN_AI_PACKAGES:
                    continue
                key = (pkg_lower, version)
                if key in seen_sdks:
                    continue
                seen_sdks.add(key)
                provider = KNOWN_AI_PACKAGES[pkg_lower]
                rel = str(fpath.relative_to(repo_path))
                components.append(
                    AIComponent(
                        name=pkg_lower,
                        version=version,
                        component_type=AIComponentType.SDK,
                        provider=provider,
                        ecosystem=ecosystem,
                        source=f"code:{rel}",
                        purl=_make_purl(ecosystem, pkg_lower, version),
                    )
                )

    # --- 2. Scan source files for model= assignments ---
    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        for m in MODEL_ASSIGNMENT_PATTERN.finditer(content):
            model_name = m.group(1)
            if model_name in seen_models:
                continue
            seen_models.add(model_name)
            provider = _infer_model_provider(model_name)
            rel = str(fpath.relative_to(repo_path))
            components.append(
                AIComponent(
                    name=model_name,
                    version="",
                    component_type=AIComponentType.MODEL,
                    provider=provider,
                    ecosystem="ai",
                    source=f"code:{rel}",
                    purl=_make_purl("ai", f"{provider}/{model_name}"),
                )
            )

    return components


# ---------------------------------------------------------------------------
# Cloud scanning
# ---------------------------------------------------------------------------




# -------------------------------------------------------------------------
# Vulnerability check + CycloneDX output + code-only orchestrator
# -------------------------------------------------------------------------

def check_ai_component_vulnerabilities(
    components: list[AIComponent],
) -> list[dict]:
    """Cross-reference SDK components against known vulnerable versions.

    Returns a list of vulnerability dicts for components matching
    constraints in VULNERABLE_SDK_VERSIONS.
    """
    vulns: list[dict] = []
    for comp in components:
        if comp.component_type != AIComponentType.SDK:
            continue
        if comp.name not in VULNERABLE_SDK_VERSIONS:
            continue
        for vuln_entry in VULNERABLE_SDK_VERSIONS[comp.name]:
            if _version_matches_constraint(comp.version, vuln_entry["constraint"]):
                vulns.append(
                    {
                        "package": comp.name,
                        "version": comp.version,
                        "constraint": vuln_entry["constraint"],
                        "cve": vuln_entry["cve"],
                        "description": vuln_entry["description"],
                        "severity": "medium",
                    }
                )
    return vulns


# ---------------------------------------------------------------------------
# CycloneDX output
# ---------------------------------------------------------------------------


def generate_ai_sbom(
    components: list[AIComponent],
    account_id: str = "code-scan",
    vulnerabilities: list[dict] | None = None,
) -> dict:
    """Produce a CycloneDX 1.5 JSON dict from discovered AI components.

    Returns a dict matching the CycloneDX 1.5 specification, with
    Whitney-specific properties on each component.
    """
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Map component types to CycloneDX types
    type_map = {
        AIComponentType.SDK: "library",
        AIComponentType.MODEL: "framework",
        AIComponentType.CLOUD_SERVICE: "service",
    }

    cdx_components = []
    for comp in components:
        entry: dict = {
            "type": type_map.get(comp.component_type, "library"),
            "name": comp.name,
            "version": comp.version or "latest",
            "purl": comp.purl,
            "properties": [
                {"name": "whitney:component_type", "value": comp.component_type.value},
                {"name": "whitney:provider", "value": comp.provider},
                {"name": "whitney:ecosystem", "value": comp.ecosystem},
                {"name": "whitney:source", "value": comp.source},
            ],
        }
        cdx_components.append(entry)

    cdx_vulns = []
    for i, vuln in enumerate(vulnerabilities or []):
        cdx_vulns.append(
            {
                "id": vuln.get("cve", f"WHITNEY-AI-{i + 1}"),
                "description": vuln["description"],
                "affects": [{"ref": vuln["package"]}],
                "ratings": [{"severity": vuln.get("severity", "medium")}],
                "properties": [
                    {"name": "whitney:package", "value": vuln["package"]},
                    {"name": "whitney:version", "value": vuln["version"]},
                    {"name": "whitney:constraint", "value": vuln.get("constraint", "")},
                ],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:whitney:{account_id}:{timestamp}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Whitney",
                    "name": "Whitney AI SBOM Scanner",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": f"ai-inventory-{account_id}",
                "version": "1.0.0",
            },
        },
        "components": cdx_components,
        "vulnerabilities": cdx_vulns,
    }


# ---------------------------------------------------------------------------
# Convenience orchestrators
# ---------------------------------------------------------------------------


def scan_ai_sbom_code_only(repo_path: str | Path) -> dict:
    """Code-only scan: discover AI SDKs and models from a repository."""
    components = scan_code_for_ai_components(repo_path)
    vulns = check_ai_component_vulnerabilities(components)
    return generate_ai_sbom(components, account_id="code-scan", vulnerabilities=vulns)


