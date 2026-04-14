"""Corpus hygiene tests: licenses, schema integrity, adversarial pair validity.

These run as part of `pytest tests/test_whitney/corpus/` and must pass
before any fixture is added to the corpus. They gate license
contamination, broken schema, and dangling adversarial pair references.
"""
from __future__ import annotations

import pytest

from tests.test_whitney.corpus.loader import (
    CORPUS_ROOT,
    load_allowed_licenses,
    load_corpus,
)


@pytest.fixture(scope="module")
def fixtures():
    return load_corpus(CORPUS_ROOT)


def test_corpus_loads_without_error(fixtures):
    # Just loading the corpus successfully validates required fields
    # and verdict enum values. If load_corpus() returned, the schema is OK.
    assert len(fixtures) > 0, "Corpus is empty"


def test_all_fixture_licenses_on_allowlist(fixtures):
    allowed = load_allowed_licenses()
    violations = [
        (fx.fixture_id, fx.license) for fx in fixtures if fx.license not in allowed
    ]
    assert not violations, (
        f"Fixtures with licenses not on allowlist: {violations}. "
        f"Allowlist: {sorted(allowed)}"
    )


def test_every_yaml_has_matching_py(fixtures):
    missing = [fx.fixture_id for fx in fixtures if not fx.py_path.exists()]
    assert not missing, f"Fixtures missing .py files: {missing}"


def test_adversarial_pair_references_exist(fixtures):
    by_id = {fx.fixture_id: fx for fx in fixtures}
    dangling = []
    for fx in fixtures:
        if fx.adversarial_pair and fx.adversarial_pair not in by_id:
            dangling.append((fx.fixture_id, fx.adversarial_pair))
    assert not dangling, (
        f"Fixtures with dangling adversarial_pair references: {dangling}"
    )


def test_negatives_have_at_least_one_recognized_defense(fixtures):
    """TNs must have at least one defense_present entry with recognized: true.

    Under the binary defense model, verdict=negative iff a recognized
    guardrail is called on the untrusted content. A TN without any
    recognized defense is a labeling error.
    """
    violations = []
    for fx in fixtures:
        if fx.verdict != "negative":
            continue
        recognized = [d for d in fx.defense_present if d.get("recognized") is True]
        if not recognized:
            violations.append(fx.fixture_id)
    assert not violations, (
        f"Negative fixtures without any recognized defense: {violations}"
    )


def test_positives_have_zero_recognized_defenses(fixtures):
    """TPs must NOT have any defense_present entry with recognized: true.

    If a TP had a recognized defense, the binary rule says it should be
    a TN. Mixing recognized defenses on a TP is a labeling contradiction.
    """
    violations = []
    for fx in fixtures:
        if fx.verdict != "positive":
            continue
        recognized = [d for d in fx.defense_present if d.get("recognized") is True]
        if recognized:
            violations.append((fx.fixture_id, [d.get("name") for d in recognized]))
    assert not violations, (
        f"Positive fixtures with recognized defenses (contradiction): {violations}"
    )


def test_adversarial_construction_only_on_negatives(fixtures):
    """adversarial_construction field should only appear on TN fixtures."""
    violations = []
    for fx in fixtures:
        if fx.verdict == "positive" and fx.adversarial_construction is not None:
            violations.append(fx.fixture_id)
    assert not violations, (
        f"Positives with adversarial_construction field set: {violations}. "
        f"This field is only for negatives (the defended half of a pair)."
    )


def test_valid_adversarial_construction_values(fixtures):
    """adversarial_construction, if set, must be one of the allowed values."""
    allowed = {
        "fully_synthetic",
        "fully_real",
        "verbatim_tp_plus_synthetic_defense",
        "real_tp_plus_attributed_defense",
    }
    violations = []
    for fx in fixtures:
        if fx.adversarial_construction is None:
            continue
        if fx.adversarial_construction not in allowed:
            violations.append((fx.fixture_id, fx.adversarial_construction))
    assert not violations, (
        f"Invalid adversarial_construction values: {violations}. "
        f"Allowed: {sorted(allowed)}"
    )


def test_tier_2_fixtures_have_provenance(fixtures):
    """Non-synthetic fixtures must have source_url and source_commit populated."""
    violations = []
    for fx in fixtures:
        if fx.source in ("synthetic",):
            continue
        if not fx.source_url or not fx.source_commit:
            violations.append(fx.fixture_id)
    assert not violations, (
        f"Non-synthetic fixtures missing source_url or source_commit: {violations}"
    )


def test_reasoning_field_is_substantive(fixtures):
    """Every fixture must have a reasoning field of at least 100 characters."""
    violations = []
    for fx in fixtures:
        if len(fx.reasoning.strip()) < 100:
            violations.append((fx.fixture_id, len(fx.reasoning.strip())))
    assert not violations, (
        f"Fixtures with too-short reasoning fields (<100 chars): {violations}"
    )
