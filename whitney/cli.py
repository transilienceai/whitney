"""Whitney command-line interface.

Usage:

    whitney scan <path> [--json | --table] [--severity LEVEL]
    whitney sbom <path> [--output FILE]
    whitney version

Examples:

    whitney scan ./my-repo                  # human-readable table
    whitney scan ./my-repo --json           # machine-readable JSON
    whitney sbom ./my-repo --output sbom.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from whitney import __version__
from whitney.scanner import scan_repository, SemgrepNotInstalledError


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _finding_to_dict(f: Any) -> dict:
    """Convert a Finding (or any object with .to_dict()) to a plain dict."""
    if hasattr(f, "to_dict"):
        return f.to_dict()
    if hasattr(f, "model_dump"):
        return f.model_dump()
    if hasattr(f, "__dict__"):
        return {k: v for k, v in f.__dict__.items() if not k.startswith("_")}
    return dict(f)


def _print_table(findings: list[Any]) -> None:
    """Plain-text table output. No external deps."""
    if not findings:
        print("No findings.")
        return

    rows = []
    for f in findings:
        d = _finding_to_dict(f)
        details = d.get("details", {}) or {}
        rows.append(
            {
                "severity": (
                    d.get("severity").value
                    if hasattr(d.get("severity"), "value")
                    else str(d.get("severity", ""))
                ),
                "check_id": d.get("check_id", ""),
                "file": details.get("file_path", d.get("resource_id", "")),
                "line": details.get("line_number", ""),
                "title": d.get("title", "")[:80],
            }
        )

    rows.sort(key=lambda r: _SEVERITY_ORDER.get(r["severity"], 99))

    sev_w = max(len(r["severity"]) for r in rows)
    file_w = min(60, max(len(str(r["file"])) for r in rows))
    line_w = max(len(str(r["line"])) for r in rows)

    print(f"{'SEVERITY':<{sev_w}}  {'FILE':<{file_w}}:{'LINE':<{line_w}}  TITLE")
    print("-" * (sev_w + file_w + line_w + 4 + 80))
    for r in rows:
        f_str = str(r["file"])
        if len(f_str) > file_w:
            f_str = "..." + f_str[-(file_w - 3) :]
        print(
            f"{r['severity']:<{sev_w}}  "
            f"{f_str:<{file_w}}:{str(r['line']):<{line_w}}  "
            f"{r['title']}"
        )
    print()
    print(f"{len(findings)} finding(s).")


def _write_html(path: Path, content: str) -> None:
    """Write HTML to *path*, creating parent dirs as needed. Overwrites
    without prompting (CI-friendly)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    try:
        findings = scan_repository(target)
    except SemgrepNotInstalledError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.severity:
        threshold = _SEVERITY_ORDER.get(args.severity.lower(), 99)
        findings = [
            f
            for f in findings
            if _SEVERITY_ORDER.get(
                getattr(f.severity, "value", str(f.severity)).lower(), 99
            )
            <= threshold
        ]

    if args.html:
        from whitney.html_report import render_scan_html

        html_path = Path(args.html)
        _write_html(html_path, render_scan_html(findings, target))
        print(
            f"HTML report written to {html_path} "
            f"({len(findings)} finding{'' if len(findings) == 1 else 's'})",
            file=sys.stderr,
        )

    if args.json:
        out = [_finding_to_dict(f) for f in findings]
        # Coerce enums to strings
        for d in out:
            for k, v in list(d.items()):
                if hasattr(v, "value"):
                    d[k] = v.value
        json.dump(out, sys.stdout, indent=2, default=str)
        print()
    elif not args.html:
        # Default to table only when neither --html nor --json was set;
        # if --html is set without --json, suppress the table to keep
        # stdout clean for redirect-friendly use.
        _print_table(findings)

    # Non-zero exit code if findings exist (CI-friendly).
    return 1 if findings else 0


def _cmd_sbom(args: argparse.Namespace) -> int:
    from whitney.sbom import enrich_with_osv, scan_ai_sbom_code_only

    target = Path(args.path)
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    sbom = scan_ai_sbom_code_only(target)
    if args.enrich:
        print("Enriching SBOM via OSV.dev...", file=sys.stderr)
        sbom = enrich_with_osv(sbom)
        n_v = len(sbom.get("vulnerabilities", []))
        print(
            f"  {n_v} vulnerabilit{'y' if n_v == 1 else 'ies'} after enrichment.",
            file=sys.stderr,
        )

    if args.html:
        from whitney.html_report import render_sbom_html

        html_path = Path(args.html)
        _write_html(html_path, render_sbom_html(sbom))
        print(
            f"HTML SBOM written to {html_path} "
            f"({len(sbom.get('components', []))} components, "
            f"{len(sbom.get('vulnerabilities', []))} vulns)",
            file=sys.stderr,
        )

    output_path = Path(args.output) if args.output else None
    if output_path:
        output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        print(
            f"SBOM JSON written to {output_path} "
            f"({len(sbom.get('components', []))} components)",
            file=sys.stderr,
        )
    elif not args.html:
        # Stream JSON to stdout only when neither --output nor --html
        # was given (the default behaviour pre-v0.2).
        json.dump(sbom, sys.stdout, indent=2)
        print()
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"whitney {__version__}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="whitney",
        description="Open-source static AI security scanner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a repository for AI security issues.")
    p_scan.add_argument("path", help="Directory or file to scan.")
    p_scan.add_argument("--json", action="store_true", help="Output JSON instead of a table.")
    p_scan.add_argument(
        "--html",
        metavar="PATH",
        help=(
            "Write a self-contained HTML report to this path. "
            "Suppresses the default table output unless --json is also set."
        ),
    )
    p_scan.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Only show findings at or above this severity.",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_sbom = sub.add_parser("sbom", help="Generate an AI dependency SBOM.")
    p_sbom.add_argument("path", help="Directory to scan.")
    p_sbom.add_argument("--output", "-o", help="Write CycloneDX JSON to this file.")
    p_sbom.add_argument(
        "--html",
        metavar="PATH",
        help=(
            "Write a self-contained HTML SBOM report to this path. "
            "Suppresses the default JSON-to-stdout unless --output is set."
        ),
    )
    p_sbom.add_argument(
        "--enrich",
        action="store_true",
        help=(
            "Cross-reference SDK components against the OSV.dev "
            "vulnerability database. Network call, results cached daily."
        ),
    )
    p_sbom.set_defaults(func=_cmd_sbom)

    p_ver = sub.add_parser("version", help="Print Whitney version.")
    p_ver.set_defaults(func=_cmd_version)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
