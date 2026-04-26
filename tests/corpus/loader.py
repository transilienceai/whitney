"""Corpus loader for Whitney prompt-injection fixtures.

Walks `corpus/prompt_injection/{positives,negatives}/*.yaml`, parses each
sidecar, validates the schema, and returns a list of `Fixture` objects.
Every fixture must have a matching `.py` file with the same stem.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CORPUS_ROOT = Path(__file__).parent / "prompt_injection"
LICENSE_ALLOWLIST_PATH = Path(__file__).parent / "_licenses_allowlist.txt"

REQUIRED_FIELDS: set[str] = {
    "fixture_id",
    "category",
    "source_type",
    "vuln_subtype",
    "verdict",
    "expected_check_id",
    "expected_severity",
    "defense_present",
    "source",
    "license",
}

# Optional top-level fields that are valid in a sidecar but not required.
# Any sidecar field outside REQUIRED_FIELDS ∪ OPTIONAL_FIELDS is schema drift
# and is rejected by test_no_undocumented_top_level_sidecar_fields.
OPTIONAL_FIELDS: frozenset[str] = frozenset({
    "adversarial_pair",
    "adversarial_construction",
    "source_url",
    "source_commit",
    "source_lines",
    "labeled_by",
    "labeled_at",
    "reasoning",
})

# The Phase A source-type taxonomy. Size of this set must match the
# "N source types" claim in README.md / docs/SCANNER.md (enforced by
# test_readme_source_type_count_matches_taxonomy in test_doc_integrity.py).
# Update this constant when the taxonomy changes — the README claim follows
# from it, not vice versa.
KNOWN_SOURCE_TYPES: frozenset[str] = frozenset({
    # Direct
    "direct_http",
    "direct_cli",
    "direct_voice",
    # Indirect — fetched
    "indirect_rag",
    "indirect_web_fetch",
    "indirect_file_upload",
    "indirect_email",
    "indirect_search",
    # Indirect — agent ecosystem
    "indirect_tool_response",
    "indirect_mcp",
    "indirect_a2a",
    # Indirect — stored
    "indirect_db_stored",
    "indirect_memory_stored",
    # Cross-modal
    "cross_modal_image_ocr",
    "cross_modal_unicode",
    "cross_modal_audio",
})


@dataclass
class Fixture:
    fixture_id: str
    category: str
    source_type: str
    vuln_subtype: str
    verdict: str  # "positive" (TP expected) | "negative" (TN expected)
    expected_check_id: str
    expected_severity: str  # critical | high | medium | low | info
    defense_present: list[dict[str, Any]]
    adversarial_pair: str
    adversarial_construction: str | None
    source: str
    source_url: str
    source_commit: str
    license: str
    reasoning: str
    py_path: Path
    yaml_path: Path


def load_allowed_licenses() -> set[str]:
    text = LICENSE_ALLOWLIST_PATH.read_text(encoding="utf-8")
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def _parse_fixture(yaml_path: Path) -> Fixture:
    with yaml_path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ValueError(
            f"{yaml_path.name}: missing required fields: {sorted(missing)}"
        )

    py_path = yaml_path.with_suffix(".py")
    if not py_path.exists():
        raise FileNotFoundError(
            f"{yaml_path.name}: no matching .py file at {py_path}"
        )

    if data["verdict"] not in ("positive", "negative"):
        raise ValueError(
            f"{yaml_path.name}: verdict must be 'positive' or 'negative', "
            f"got {data['verdict']!r}"
        )

    return Fixture(
        fixture_id=str(data["fixture_id"]),
        category=str(data["category"]),
        source_type=str(data["source_type"]),
        vuln_subtype=str(data["vuln_subtype"]),
        verdict=str(data["verdict"]),
        expected_check_id=str(data["expected_check_id"]),
        expected_severity=str(data["expected_severity"]).lower(),
        defense_present=list(data.get("defense_present") or []),
        adversarial_pair=str(data.get("adversarial_pair") or ""),
        adversarial_construction=data.get("adversarial_construction"),
        source=str(data["source"]),
        source_url=str(data.get("source_url") or ""),
        source_commit=str(data.get("source_commit") or ""),
        license=str(data["license"]),
        reasoning=str(data.get("reasoning") or ""),
        py_path=py_path,
        yaml_path=yaml_path,
    )


def load_corpus(corpus_root: Path = CORPUS_ROOT) -> list[Fixture]:
    """Load every fixture under `corpus_root/{positives,negatives}/`."""
    fixtures: list[Fixture] = []
    for verdict_dir in ("positives", "negatives"):
        base = corpus_root / verdict_dir
        if not base.exists():
            continue
        for yaml_path in sorted(base.glob("*.yaml")):
            fixtures.append(_parse_fixture(yaml_path))
    return fixtures
