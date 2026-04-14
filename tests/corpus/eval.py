"""Eval harness: run Whitney scanner against the labeled corpus, report metrics.

Usage:
    py -3.12 -m tests.corpus.eval
    py -3.12 -m tests.corpus.eval --json out.json

Exit code is 0 if all Phase A acceptance criteria pass, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.table import Table

from tests.corpus.loader import CORPUS_ROOT, Fixture, load_corpus

# Below this sample size, Wilson 95% CI is too wide for F1 to be
# a reliable regression floor. Cells with fewer fixtures are flagged
# as directional-only.
TAIL_THRESHOLD = 15

# Phase A acceptance criteria (from testideas.md Part 2).
ACCEPTANCE_RECALL_TARGETS: dict[str, float] = {
    "critical": 0.95,
    "high": 0.85,
    "medium": 0.70,
}
ACCEPTANCE_FP_RATE_TARGET: float = 0.15


@dataclass
class CellMetrics:
    count: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def fp_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0

    @property
    def directional(self) -> bool:
        return self.count < TAIL_THRESHOLD

    def as_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fp_rate": round(self.fp_rate, 4),
            "directional": self.directional,
        }


@dataclass
class EvalResult:
    fixture_id: str
    verdict: str
    outcome: str  # TP | FP | FN | TN
    flagged: bool
    source_type: str
    vuln_subtype: str
    severity: str
    matching_check_ids: list[str] = field(default_factory=list)


@dataclass
class EvalReport:
    overall: CellMetrics
    per_source_type: dict[str, CellMetrics]
    per_vuln_subtype: dict[str, CellMetrics]
    per_severity: dict[str, CellMetrics]
    results: list[EvalResult]

    def acceptance_check(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for sev, target in ACCEPTANCE_RECALL_TARGETS.items():
            cell = self.per_severity.get(sev, CellMetrics())
            out[f"recall_{sev}"] = {
                "target": target,
                "actual": round(cell.recall, 4),
                "pass": cell.recall >= target if cell.count > 0 else True,
                "count": cell.count,
                "directional": cell.directional,
            }
        out["fp_rate_overall"] = {
            "target": ACCEPTANCE_FP_RATE_TARGET,
            "actual": round(self.overall.fp_rate, 4),
            "pass": self.overall.fp_rate <= ACCEPTANCE_FP_RATE_TARGET,
            "count": self.overall.count,
            "directional": False,
        }
        return out

    def all_acceptance_passing(self) -> bool:
        return all(d["pass"] for d in self.acceptance_check().values())


def _default_scanner(path: Path) -> list[Any]:
    from whitney.scanner import scan_repository

    return scan_repository(path)


def run_eval(
    corpus_root: Path = CORPUS_ROOT,
    scanner_fn: Callable[[Path], list[Any]] | None = None,
) -> EvalReport:
    """Load corpus, run scanner, compute metrics.

    Fixtures are copied to a temp dir before scanning to sidestep any
    `tests/` path filters the scanner might apply. Scanner output is
    bucketed back to fixtures by filename stem (the copied file is
    named `<fixture_id>.py`).
    """
    fixtures = load_corpus(corpus_root)
    scanner = scanner_fn or _default_scanner

    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp) / "eval_fixtures"
        tmp_root.mkdir(parents=True)
        for fx in fixtures:
            dest = tmp_root / f"{fx.fixture_id}.py"
            shutil.copy(fx.py_path, dest)

        findings = scanner(tmp_root)

        # Phase C alpha's separate dataflow.py guardrail-suppression module
        # was removed in the 2026-04-13 rebuild — the suppression now lives
        # inside the Semgrep rules as `pattern-not-inside` clauses.

    by_fixture: dict[str, list[Any]] = defaultdict(list)
    for f in findings:
        details = getattr(f, "details", None) or {}
        fp = details.get("file_path", "")
        stem = Path(fp).stem if fp else ""
        if stem:
            by_fixture[stem].append(f)

    results: list[EvalResult] = []
    for fx in fixtures:
        matches = [
            f
            for f in by_fixture.get(fx.fixture_id, [])
            if getattr(f, "check_id", None) == fx.expected_check_id
        ]
        flagged = bool(matches)
        if fx.verdict == "positive":
            outcome = "TP" if flagged else "FN"
        else:
            outcome = "FP" if flagged else "TN"
        results.append(
            EvalResult(
                fixture_id=fx.fixture_id,
                verdict=fx.verdict,
                outcome=outcome,
                flagged=flagged,
                source_type=fx.source_type,
                vuln_subtype=fx.vuln_subtype,
                severity=fx.expected_severity,
                matching_check_ids=[getattr(m, "check_id", "") for m in matches],
            )
        )

    return _compute_report(results)


def _compute_report(results: list[EvalResult]) -> EvalReport:
    overall = CellMetrics()
    by_source: dict[str, CellMetrics] = defaultdict(CellMetrics)
    by_vuln: dict[str, CellMetrics] = defaultdict(CellMetrics)
    by_sev: dict[str, CellMetrics] = defaultdict(CellMetrics)

    for r in results:
        cells = (
            overall,
            by_source[r.source_type],
            by_vuln[r.vuln_subtype],
            by_sev[r.severity],
        )
        for cell in cells:
            cell.count += 1
            if r.outcome == "TP":
                cell.tp += 1
            elif r.outcome == "FP":
                cell.fp += 1
            elif r.outcome == "FN":
                cell.fn += 1
            else:
                cell.tn += 1

    return EvalReport(
        overall=overall,
        per_source_type=dict(by_source),
        per_vuln_subtype=dict(by_vuln),
        per_severity=dict(by_sev),
        results=results,
    )


def _render_cell_table(
    console: Console, title: str, cells: dict[str, CellMetrics]
) -> None:
    table = Table(title=title)
    for header, justify in [
        ("Cell", "left"),
        ("N", "right"),
        ("TP", "right"),
        ("FP", "right"),
        ("FN", "right"),
        ("TN", "right"),
        ("Precision", "right"),
        ("Recall", "right"),
        ("F1", "right"),
        ("Reliability", "left"),
    ]:
        table.add_column(header, justify=justify)

    for name in sorted(cells.keys()):
        cell = cells[name]
        rel = "directional" if cell.directional else "reliable"
        table.add_row(
            name,
            str(cell.count),
            str(cell.tp),
            str(cell.fp),
            str(cell.fn),
            str(cell.tn),
            f"{cell.precision:.2f}",
            f"{cell.recall:.2f}",
            f"{cell.f1:.2f}",
            rel,
        )
    console.print(table)


def print_report(report: EvalReport, console: Console | None = None) -> None:
    console = console or Console()
    o = report.overall
    console.print(
        f"\n[bold]Overall[/bold]: N={o.count} TP={o.tp} FP={o.fp} "
        f"FN={o.fn} TN={o.tn}"
    )
    console.print(
        f"  Precision={o.precision:.3f}  Recall={o.recall:.3f}  "
        f"F1={o.f1:.3f}  FP_Rate={o.fp_rate:.3f}"
    )

    _render_cell_table(console, "Per source_type", report.per_source_type)
    _render_cell_table(console, "Per vuln_subtype", report.per_vuln_subtype)
    _render_cell_table(console, "Per severity", report.per_severity)

    console.print("\n[bold]Acceptance criteria[/bold]:")
    for key, data in report.acceptance_check().items():
        status = "[green]PASS[/green]" if data["pass"] else "[red]FAIL[/red]"
        directional = " (directional)" if data.get("directional") else ""
        console.print(
            f"  {status} {key}: actual={data['actual']:.3f} "
            f"target={data['target']:.3f} N={data['count']}{directional}"
        )


def report_to_dict(report: EvalReport) -> dict[str, Any]:
    return {
        "overall": report.overall.as_dict(),
        "per_source_type": {
            k: v.as_dict() for k, v in report.per_source_type.items()
        },
        "per_vuln_subtype": {
            k: v.as_dict() for k, v in report.per_vuln_subtype.items()
        },
        "per_severity": {k: v.as_dict() for k, v in report.per_severity.items()},
        "results": [
            {
                "fixture_id": r.fixture_id,
                "verdict": r.verdict,
                "outcome": r.outcome,
                "flagged": r.flagged,
                "source_type": r.source_type,
                "vuln_subtype": r.vuln_subtype,
                "severity": r.severity,
                "matching_check_ids": r.matching_check_ids,
            }
            for r in report.results
        ],
        "acceptance": report.acceptance_check(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Whitney corpus eval harness")
    parser.add_argument(
        "--json", type=Path, default=None, help="Write JSON report to this path"
    )
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=CORPUS_ROOT,
        help="Corpus root directory",
    )
    args = parser.parse_args()

    console = Console()
    console.print(f"Loading corpus from [cyan]{args.corpus_root}[/cyan]...")
    report = run_eval(args.corpus_root)
    print_report(report, console)

    if args.json:
        args.json.write_text(
            json.dumps(report_to_dict(report), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"\nJSON report written to [cyan]{args.json}[/cyan]")

    return 0 if report.all_acceptance_passing() else 1


if __name__ == "__main__":
    sys.exit(main())
