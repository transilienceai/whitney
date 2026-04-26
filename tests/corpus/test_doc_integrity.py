"""Doc-integrity tests: every numeric claim in README/DIFFERENTIAL/SCANNER
must be backed by an AST count of the source-of-truth artifact.

Per CLAUDE.md principle #1: "Numbers in docs are tests waiting to be
written. Every 'X checks' / 'Y templates' / 'N tests' claim in any
README is a regression waiting to happen."

These tests intentionally produce actionable failure messages (CLAUDE.md
principle #9) — the assertion text says exactly what file, what line,
and what number to write.

Historical narrative (DIFFERENTIAL trajectory tables, dated post-mortems,
strikethrough lines) is sacred per CLAUDE.md principle #11 — these tests
deliberately do NOT verify those rows.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest
import yaml

from tests.corpus.loader import (
    KNOWN_SOURCE_TYPES,
    OPTIONAL_FIELDS,
    REQUIRED_FIELDS,
    load_corpus,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
README_MD = REPO_ROOT / "README.md"
SCANNER_MD = REPO_ROOT / "docs" / "SCANNER.md"
DIFFERENTIAL_MD = REPO_ROOT / "tests" / "corpus" / "DIFFERENTIAL.md"
CORPUS_README = REPO_ROOT / "tests" / "corpus" / "README.md"
RULES_DIR = REPO_ROOT / "whitney" / "rules"


# --- helpers --------------------------------------------------------------


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _line_of(text: str, needle: str) -> int:
    """Return 1-indexed line number of the first line containing *needle*."""
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    return -1


def _count_leaf_patterns(node) -> int:
    """Recursively count leaf `pattern: <string>` entries anywhere in a
    Semgrep rule fragment. Handles top-level lists, dicts, and nested
    `pattern-either`/`patterns` constructs."""
    n = 0
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                n += 1
            else:
                n += _count_leaf_patterns(v)
    elif isinstance(node, list):
        for item in node:
            n += _count_leaf_patterns(item)
    return n


def _find_rule(rules_path: Path, rule_id: str) -> dict | None:
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    for rule in data.get("rules", []):
        if rule.get("id") == rule_id:
            return rule
    return None


# --- fixtures -------------------------------------------------------------


@pytest.fixture(scope="module")
def fixtures():
    return load_corpus()


@pytest.fixture(scope="module")
def taint_rule():
    rule = _find_rule(RULES_DIR / "prompt_injection_taint.yaml",
                      "code-prompt-injection-risk")
    assert rule is not None, (
        "whitney/rules/prompt_injection_taint.yaml does not contain a "
        "rule with id=code-prompt-injection-risk"
    )
    return rule


# --- README fixture-count claim ------------------------------------------


def test_readme_fixture_count_matches_corpus(fixtures):
    """README.md must agree with the actual fixture file count."""
    text = _read(README_MD)
    # Match: "**N hand-labelled fixtures** (X positives + Y negatives)"
    pat = re.compile(
        r"\*\*(\d+)\s+hand-labelled\s+fixtures\*\*\s*\((\d+)\s+positives\s*\+\s*(\d+)\s+negatives\)",
        re.IGNORECASE,
    )
    m = pat.search(text)
    assert m, (
        "README.md does not contain the canonical fixture-count claim "
        "of the form '**N hand-labelled fixtures** (P positives + N negatives)'. "
        "Either restore the claim or update this test."
    )
    claimed_total, claimed_pos, claimed_neg = (int(m.group(i)) for i in (1, 2, 3))

    actual_pos = sum(1 for f in fixtures if f.verdict == "positive")
    actual_neg = sum(1 for f in fixtures if f.verdict == "negative")
    actual_total = actual_pos + actual_neg

    line = _line_of(text, m.group(0))
    assert (claimed_total, claimed_pos, claimed_neg) == (actual_total, actual_pos, actual_neg), (
        f"README.md:{line}: claim says "
        f"'{claimed_total} hand-labelled fixtures ({claimed_pos} positives + "
        f"{claimed_neg} negatives)', actual is "
        f"{actual_total} fixtures ({actual_pos} positives + {actual_neg} negatives). "
        f"Update README.md to '**{actual_total} hand-labelled fixtures** "
        f"({actual_pos} positives + {actual_neg} negatives)'."
    )


def test_differential_corpus_header_matches(fixtures):
    """DIFFERENTIAL.md TL;DR header must agree with actual fixture count."""
    text = _read(DIFFERENTIAL_MD)
    # Match: "**Corpus**: N fixtures, P positives + N negatives, ..."
    pat = re.compile(
        r"\*\*Corpus\*\*:\s*(\d+)\s+fixtures,\s*(\d+)\s+positives\s*\+\s*(\d+)\s+negatives",
        re.IGNORECASE,
    )
    m = pat.search(text)
    assert m, (
        "DIFFERENTIAL.md does not contain the canonical Corpus header line. "
        "Either restore the header or update this test."
    )
    claimed_total, claimed_pos, claimed_neg = (int(m.group(i)) for i in (1, 2, 3))

    actual_pos = sum(1 for f in fixtures if f.verdict == "positive")
    actual_neg = sum(1 for f in fixtures if f.verdict == "negative")
    actual_total = actual_pos + actual_neg

    line = _line_of(text, m.group(0))
    assert (claimed_total, claimed_pos, claimed_neg) == (actual_total, actual_pos, actual_neg), (
        f"tests/corpus/DIFFERENTIAL.md:{line}: header says "
        f"'{claimed_total} fixtures, {claimed_pos} positives + {claimed_neg} negatives', "
        f"actual is {actual_total} fixtures ({actual_pos} positives + {actual_neg} negatives). "
        f"Update header to '**Corpus**: {actual_total} fixtures, "
        f"{actual_pos} positives + {actual_neg} negatives, ...'"
    )


# --- README source-type taxonomy claim -----------------------------------


def test_readme_source_type_count_matches_taxonomy():
    """README.md, docs/SCANNER.md, and tests/corpus/README.md all reference a
    source-type count. Each occurrence must equal len(KNOWN_SOURCE_TYPES).

    Tests the *taxonomy size*, not the number of types with ≥1 fixture.
    cross_modal_audio is in the taxonomy but currently has 0 fixtures —
    docs are allowed to qualify coverage as "15 of 16 source types".

    Only counts as a taxonomy claim if the number has an explicit lead-in
    that signals taxonomy/coverage intent: "**N source types**" (bold),
    "across/spanning/of N source types", "(N source types ...)" parens,
    or yaml-comment "# ... the N source_types". This avoids false matches
    like "**Uniquely catches 5 source types** that neither competitor
    covers" — which is a Whitney-unique count, not the taxonomy size.
    """
    expected = len(KNOWN_SOURCE_TYPES)

    # "X of Y source types" — Y must equal taxonomy, X is coverage and
    # may be lower.
    pat_of = re.compile(
        r"\b(\d+)\s+of\s+(\d+)\s+source[\s_-]?types?\b",
        re.IGNORECASE,
    )
    # "**N source types**" — bold-fenced taxonomy claim.
    pat_bold = re.compile(
        r"\*\*(\d+)\s+source[\s_-]?types?\*\*",
        re.IGNORECASE,
    )
    # "across/spanning/of/the/all N source types" — taxonomy lead-in word.
    pat_leadin = re.compile(
        r"\b(?:across|spanning|of|the|all)\s+(\d+)\s+source[\s_-]?types?\b",
        re.IGNORECASE,
    )
    # "(N source types ...)" — parenthetical coverage qualifier.
    pat_parens = re.compile(
        r"\((\d+)\s+source[\s_-]?types?\b",
        re.IGNORECASE,
    )

    failures: list[str] = []
    for path in (README_MD, SCANNER_MD, CORPUS_README, DIFFERENTIAL_MD):
        if not path.exists():
            continue
        text = _read(path)
        for lineno, line in enumerate(text.splitlines(), start=1):
            # First check "X of Y" — handle separately so X isn't asserted.
            of_match = pat_of.search(line)
            if of_match:
                covered, claimed_taxonomy = int(of_match.group(1)), int(of_match.group(2))
                if claimed_taxonomy != expected:
                    failures.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno}: claims "
                        f"'{covered} of {claimed_taxonomy} source types', taxonomy "
                        f"is {expected}. Update to '{covered} of {expected} source types'."
                    )
                continue
            # Other taxonomy patterns must equal expected exactly.
            for pat, label in ((pat_bold, "bold"),
                               (pat_leadin, "lead-in"),
                               (pat_parens, "parens")):
                m = pat.search(line)
                if not m:
                    continue
                claimed = int(m.group(1))
                if claimed != expected:
                    failures.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno}: {label} "
                        f"claim '{m.group(0)}' implies {claimed} taxonomy "
                        f"size; actual is {expected}. Update to use {expected}."
                    )
                break  # one match per line is enough
    assert not failures, "Source-type count drift:\n  " + "\n  ".join(failures)


def test_corpus_source_types_subset_of_taxonomy(fixtures):
    """Every source_type used in a fixture must appear in KNOWN_SOURCE_TYPES.
    Catches fixture-side drift (typos, deprecated source_types).
    """
    used = {fx.source_type for fx in fixtures}
    unknown = used - KNOWN_SOURCE_TYPES
    assert not unknown, (
        f"Fixtures reference source_types not in KNOWN_SOURCE_TYPES: "
        f"{sorted(unknown)}. Either add them to "
        f"tests/corpus/loader.py:KNOWN_SOURCE_TYPES or correct the fixture "
        f"sidecars."
    )


# --- README rule-pattern count claim -------------------------------------


def test_rule_pattern_counts_match_readme(taint_rule):
    """README.md and docs/SCANNER.md claim '50+ pattern-sources, 25+
    pattern-sanitizers, 40+ pattern-sinks' for the taint rule. Verify
    the rule still meets each floor."""
    n_sources = _count_leaf_patterns(taint_rule.get("pattern-sources"))
    n_sanitizers = _count_leaf_patterns(taint_rule.get("pattern-sanitizers"))
    n_sinks = _count_leaf_patterns(taint_rule.get("pattern-sinks"))

    failures: list[str] = []
    if n_sources < 50:
        failures.append(
            f"prompt_injection_taint.yaml has {n_sources} leaf pattern-sources; "
            f"README/SCANNER claim '50+'. Either add patterns or revise the doc claim."
        )
    if n_sanitizers < 25:
        failures.append(
            f"prompt_injection_taint.yaml has {n_sanitizers} leaf pattern-sanitizers; "
            f"README/SCANNER claim '25+'. Either add patterns or revise the doc claim."
        )
    if n_sinks < 40:
        failures.append(
            f"prompt_injection_taint.yaml has {n_sinks} leaf pattern-sinks; "
            f"README/SCANNER claim '40+'. Either add patterns or revise the doc claim."
        )
    assert not failures, "Rule-pattern count drift:\n  " + "\n  ".join(failures)


# --- Sidecar schema integrity --------------------------------------------


def test_no_undocumented_top_level_sidecar_fields(fixtures):
    """Every sidecar's top-level keys must be a subset of the documented
    schema (REQUIRED_FIELDS ∪ OPTIONAL_FIELDS). Catches re-introduction
    of removed fields like `defense_score` and any future drift.
    """
    allowed = REQUIRED_FIELDS | OPTIONAL_FIELDS
    drift: list[str] = []
    for fx in fixtures:
        with fx.yaml_path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        extra = set(data.keys()) - allowed
        if extra:
            drift.append(f"{fx.fixture_id} ({fx.yaml_path.name}): {sorted(extra)}")
    assert not drift, (
        "Sidecars contain undocumented top-level fields. Either remove the "
        "fields from the sidecars or add them to "
        "tests/corpus/loader.py:OPTIONAL_FIELDS and document in "
        "tests/corpus/README.md schema:\n  " + "\n  ".join(drift)
    )


# --- Recognized-guardrail parity -----------------------------------------


# Canonical mapping from human-readable vendor name (as it appears in the
# main README's recognised-defences bullet list) to the canonical
# `defense_present[*].name` short-key used in TN fixture sidecars.
#
# Every entry here is a vendor that the README claims Whitney recognises.
# The integrity test below requires that each canonical name appears as
# `recognized: true` on at least one negative fixture. Drop a vendor
# from this dict only when also removing it from the main README's list
# (per CLAUDE.md "default to honesty").
RECOGNISED_VENDORS_README_TO_CANONICAL: dict[str, tuple[str, ...]] = {
    "AWS Bedrock Guardrails": ("bedrock_apply_guardrail", "bedrock_guardrail",
                                "bedrock_guardrails",
                                "bedrock_apply_guardrail_input",
                                "bedrock_invoke_model_guardrail_params"),
    "Azure AI Content Safety / Prompt Shields": ("azure_content_safety",
                                                  "azure_prompt_shields"),
    "Lakera Guard": ("lakera_guard",),
    "NeMo Guardrails": ("nemo_guardrails", "nemo_guardrails_rails_generate",
                        "nemo_guardrails_runnable_composition"),
    "DeepKeep AI firewall": ("deepkeep_ai_firewall_input_output",
                              "deepkeep_ai_firewall"),
    "OpenAI Moderation": ("openai_moderation",),
    "LLM-Guard": ("llm_guard_scan_prompt", "llm_guard"),
    "Rebuff": ("rebuff_detect_injection", "rebuff"),
    "Guardrails AI": ("guardrails_ai_detect_prompt_injection", "guardrails_ai"),
    "Correct LLM-as-judge": ("llm_as_judge_prompt_injection_detector",
                              "llm_as_judge_input_and_output",
                              "llm_as_judge_correct"),
}


def test_recognized_vendors_have_tn_fixtures(fixtures):
    """Every vendor named in the main README's "Recognised defences" section
    must appear as `recognized: true` on at least one negative fixture.

    Updating the README list without authoring a TN fixture should fail
    this test. Updating this dict without updating the README is also
    a fail (the test parses the README text — adding a non-README vendor
    here will surface as 'no occurrences in README').
    """
    text = _read(README_MD)

    # Build per-vendor TN coverage map.
    tn_vendor_names = Counter()
    for fx in fixtures:
        if fx.verdict != "negative":
            continue
        for d in fx.defense_present:
            if d.get("recognized") is True:
                tn_vendor_names[d.get("name", "")] += 1

    failures: list[str] = []
    for readme_name, canonical_aliases in RECOGNISED_VENDORS_README_TO_CANONICAL.items():
        if readme_name not in text:
            failures.append(
                f"Vendor '{readme_name}' is mapped here but not present in "
                f"README.md. Either remove from "
                f"RECOGNISED_VENDORS_README_TO_CANONICAL or restore in README."
            )
            continue
        if not any(alias in tn_vendor_names for alias in canonical_aliases):
            failures.append(
                f"Vendor '{readme_name}' is claimed in README.md but no "
                f"negative fixture has defense_present[*].name in "
                f"{list(canonical_aliases)} with recognized=true. "
                f"Either author a TN fixture or drop the vendor from the "
                f"README's recognised-defences list."
            )
    assert not failures, "Recognised-vendor parity drift:\n  " + "\n  ".join(failures)
