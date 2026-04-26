"""Phase A coverage dashboard.

Run with:

    python -m tests.corpus.coverage
    python -m tests.corpus.coverage --json /tmp/coverage.json

This is a *progress dashboard*, not a CI gate. It reports per-source-type,
per-vuln-subtype, per-vendor, and per-tier coverage against the Phase A
targets in tests/corpus/README.md (lines 286-296). Use it to track Phase A
burn-down across subsequent fixture-authoring slices.

The "reliable / directional" flag mirrors tests/corpus/eval.py:TAIL_THRESHOLD
— a cell with fewer than 15 fixtures has too wide a Wilson 95% CI for its
F1 to be a regression floor.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from tests.corpus.eval import TAIL_THRESHOLD
from tests.corpus.loader import KNOWN_SOURCE_TYPES, load_corpus
from tests.corpus.test_doc_integrity import (
    RECOGNISED_VENDORS_README_TO_CANONICAL,
)


# Phase A target table, transcribed from tests/corpus/README.md:286-296.
# Update this constant when the README's target weighting changes — the
# dashboard follows the README, not vice versa.
PHASE_A_TARGETS: dict[str, tuple[int, str]] = {
    # Common (regression-floor-grade): 5 × 20 = 100
    "direct_http":            (20, "common"),
    "indirect_rag":           (20, "common"),
    "indirect_web_fetch":     (20, "common"),
    "indirect_tool_response": (20, "common"),
    "indirect_file_upload":   (20, "common"),
    # Medium (directional-trending-real): 5 × 15 = 75
    "indirect_mcp":           (15, "medium"),
    "indirect_db_stored":     (15, "medium"),
    "indirect_email":         (15, "medium"),
    "indirect_search":        (15, "medium"),
    "cross_modal_image_ocr":  (15, "medium"),
    # Tail (directional-only): 6 × 8 = 48
    "direct_cli":              (8, "tail"),
    "direct_voice":            (8, "tail"),
    "indirect_a2a":            (8, "tail"),
    "indirect_memory_stored":  (8, "tail"),
    "cross_modal_unicode":     (8, "tail"),
    "cross_modal_audio":       (8, "tail"),
}

PHASE_A_DEFENSE_FIXTURE_TARGET = 20
PHASE_A_TIER_MIX = {  # README:296
    "synthetic": 0.25,
    "github":    0.65,
    "cve":       0.10,
    "benchmark": 0.10,  # NB: README pools cve+benchmark; tracked separately here
}
PHASE_A_ADVERSARIAL_PAIR_TARGET = 40


@dataclass
class CellRow:
    name: str
    count: int
    target: int
    tier: str

    @property
    def gap(self) -> int:
        return max(0, self.target - self.count)

    @property
    def reliability(self) -> str:
        return "reliable" if self.count >= TAIL_THRESHOLD else "directional"


def _build_per_source_type_rows(fixtures) -> list[CellRow]:
    counts = Counter(f.source_type for f in fixtures)
    rows = []
    for st, (target, tier) in PHASE_A_TARGETS.items():
        rows.append(CellRow(name=st, count=counts.get(st, 0), target=target, tier=tier))
    # Surface any fixture-side source_type not in PHASE_A_TARGETS.
    for st in sorted(set(counts) - set(PHASE_A_TARGETS)):
        rows.append(CellRow(name=f"{st} (NOT IN TARGETS)", count=counts[st],
                             target=0, tier="?"))
    return rows


def _build_per_vuln_subtype_rows(fixtures) -> list[CellRow]:
    # Subtype family targets are not in the README; we report counts only,
    # using "directional" reliability as the consistent flag.
    counts = Counter(f.vuln_subtype for f in fixtures)
    return [CellRow(name=st, count=n, target=0, tier="info")
            for st, n in sorted(counts.items())]


def _build_vendor_coverage_rows(fixtures) -> tuple[list[CellRow], dict]:
    """Per-recognized-vendor TN count vs README list."""
    tn_counts = Counter()
    for fx in fixtures:
        if fx.verdict != "negative":
            continue
        for d in fx.defense_present:
            if d.get("recognized") is True:
                tn_counts[d.get("name", "")] += 1

    rows = []
    extras = dict(tn_counts)
    summary_missing = []
    for readme_name, aliases in RECOGNISED_VENDORS_README_TO_CANONICAL.items():
        n = sum(tn_counts.get(a, 0) for a in aliases)
        rows.append(CellRow(name=readme_name, count=n, target=1, tier="vendor"))
        for a in aliases:
            extras.pop(a, None)
        if n == 0:
            summary_missing.append(readme_name)

    return rows, {"unmapped_vendor_names_in_fixtures": extras,
                  "missing_tn_for_readme_vendors": summary_missing}


def _tier_mix(fixtures) -> dict[str, int]:
    return Counter(f.source for f in fixtures)


def _adversarial_pairs(fixtures) -> tuple[int, list[str]]:
    by_id = {fx.fixture_id: fx for fx in fixtures}
    pairs = set()
    dangling = []
    for fx in fixtures:
        if not fx.adversarial_pair:
            continue
        if fx.adversarial_pair not in by_id:
            dangling.append(f"{fx.fixture_id} -> {fx.adversarial_pair}")
            continue
        pair = tuple(sorted((fx.fixture_id, fx.adversarial_pair)))
        pairs.add(pair)
    return len(pairs), dangling


def _render(console: Console, fixtures, *, json_out: Path | None) -> dict[str, Any]:
    src_rows = _build_per_source_type_rows(fixtures)
    vuln_rows = _build_per_vuln_subtype_rows(fixtures)
    vendor_rows, vendor_meta = _build_vendor_coverage_rows(fixtures)
    tier_counts = _tier_mix(fixtures)
    n_pairs, dangling = _adversarial_pairs(fixtures)

    total = len(fixtures)
    total_target = (sum(t for t, _ in PHASE_A_TARGETS.values())
                    + PHASE_A_DEFENSE_FIXTURE_TARGET)

    console.print(
        f"\n[bold]Phase A coverage[/bold]: {total} fixtures, "
        f"target ~{total_target} ({100 * total // total_target}% complete)\n"
    )

    # Per source_type
    table = Table(title="Per source_type (vs Phase A targets)")
    for col, justify in (("source_type", "left"), ("count", "right"),
                         ("target", "right"), ("gap", "right"),
                         ("tier", "left"), ("reliability", "left")):
        table.add_column(col, justify=justify)
    for row in src_rows:
        gap_color = "green" if row.gap == 0 else "yellow" if row.gap < 5 else "red"
        rel_color = "green" if row.reliability == "reliable" else "yellow"
        table.add_row(
            row.name,
            str(row.count),
            str(row.target) if row.target else "-",
            f"[{gap_color}]{row.gap}[/{gap_color}]" if row.target else "-",
            row.tier,
            f"[{rel_color}]{row.reliability}[/{rel_color}]",
        )
    console.print(table)

    # Per vuln_subtype
    table = Table(title="Per vuln_subtype")
    for col, justify in (("vuln_subtype", "left"), ("count", "right"),
                         ("reliability", "left")):
        table.add_column(col, justify=justify)
    for row in vuln_rows:
        rel_color = "green" if row.reliability == "reliable" else "yellow"
        table.add_row(row.name, str(row.count),
                      f"[{rel_color}]{row.reliability}[/{rel_color}]")
    console.print(table)

    # Vendor coverage
    table = Table(title="Recognised-vendor TN coverage (README parity)")
    for col, justify in (("vendor (README label)", "left"),
                         ("TN count", "right"),
                         ("status", "left")):
        table.add_column(col, justify=justify)
    for row in vendor_rows:
        status = ("[green]COVERED[/green]" if row.count >= 1
                  else "[red]MISSING[/red]")
        table.add_row(row.name, str(row.count), status)
    console.print(table)
    if vendor_meta["unmapped_vendor_names_in_fixtures"]:
        console.print(
            "[dim]Fixture defense_present names not mapped to a README "
            f"vendor: {vendor_meta['unmapped_vendor_names_in_fixtures']}[/dim]"
        )

    # Tier mix
    table = Table(title="Tier mix (README target: 25% synthetic / 65% github / 10% cve+benchmark)")
    for col, justify in (("tier", "left"), ("count", "right"),
                         ("share", "right"), ("target_share", "right")):
        table.add_column(col, justify=justify)
    for tier, target_share in PHASE_A_TIER_MIX.items():
        n = tier_counts.get(tier, 0)
        share = (n / total) if total else 0.0
        table.add_row(tier, str(n), f"{100*share:.1f}%", f"{100*target_share:.0f}%")
    console.print(table)

    # Adversarial pairs
    console.print(
        f"\n[bold]Adversarial pairs[/bold]: {n_pairs} unique pairs "
        f"(target {PHASE_A_ADVERSARIAL_PAIR_TARGET})"
    )
    if dangling:
        console.print("[red]Dangling adversarial_pair refs:[/red]")
        for d in dangling:
            console.print(f"  {d}")

    # Source-type taxonomy parity
    used = {fx.source_type for fx in fixtures}
    missing_in_corpus = sorted(KNOWN_SOURCE_TYPES - used)
    if missing_in_corpus:
        console.print(
            f"\n[bold]Taxonomy types with 0 fixtures:[/bold] "
            f"{missing_in_corpus}"
        )

    out = {
        "total_fixtures": total,
        "phase_a_target_total": total_target,
        "per_source_type": [
            {"source_type": r.name, "count": r.count, "target": r.target,
             "gap": r.gap, "tier": r.tier, "reliability": r.reliability}
            for r in src_rows
        ],
        "per_vuln_subtype": [
            {"vuln_subtype": r.name, "count": r.count} for r in vuln_rows
        ],
        "vendor_coverage": [
            {"vendor": r.name, "tn_count": r.count,
             "covered": r.count >= 1}
            for r in vendor_rows
        ],
        "vendor_coverage_meta": vendor_meta,
        "tier_mix": dict(tier_counts),
        "adversarial_pairs": {
            "count": n_pairs,
            "target": PHASE_A_ADVERSARIAL_PAIR_TARGET,
            "dangling": dangling,
        },
        "taxonomy_types_with_zero_fixtures": missing_in_corpus,
    }
    if json_out is not None:
        json_out.write_text(json.dumps(out, indent=2), encoding="utf-8")
        console.print(f"\nJSON report written to [cyan]{json_out}[/cyan]")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase A corpus coverage dashboard")
    parser.add_argument("--json", type=Path, default=None,
                        help="Write JSON report to this path")
    args = parser.parse_args()

    fixtures = load_corpus()
    console = Console()
    _render(console, fixtures, json_out=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
