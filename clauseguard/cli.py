"""
ClauseGuard CLI — analyze a contract file from the command line.

Examples
--------
    python -m clauseguard.cli path/to/contract.txt
    python -m clauseguard.cli contract.txt --json
    python -m clauseguard.cli contract.txt --html report.html

Zero dependencies. Works on Python 3.8+.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import analyze
from .report import build_html


SEV_LABEL = {1: "WATCH", 2: "CAUTION", 3: "HIGH"}


def _print_console(result) -> None:
    print("=" * 68)
    print("ClauseGuard — Contract Risk Report")
    print("=" * 68)
    print(f"Words analyzed : {result.word_count}")
    print(f"Overall risk   : {result.risk_band} (score {result.risk_score})")
    print("-" * 68)
    if not result.findings:
        print("No high-risk clause patterns detected. (Still read it yourself!)")
    for f in sorted(result.findings, key=lambda x: -x.severity):
        print(f"\n[{SEV_LABEL[f.severity]}] {f.title}  (x{f.occurrences})")
        print(f"  Category : {f.category}")
        print(f"  Found    : …{f.matched_text}…")
        print(f"  Why     : {f.explanation}")
        print(f"  Tip      : {f.tip}")
    if result.missing_standard_clauses:
        print("\nMissing standard clauses:")
        for c in result.missing_standard_clauses:
            print(f"  - {c}")
    print("\n" + result.summary)
    print("=" * 68)
    print("Disclaimer: ClauseGuard is a screening tool, not legal advice.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline contract risk analyzer (zero dependencies)."
    )
    parser.add_argument("path", help="Path to a .txt/.md contract file")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--html", metavar="FILE", help="Write an HTML report")
    args = parser.parse_args(argv)

    p = Path(args.path)
    if not p.exists():
        print(f"ERROR: file not found: {args.path}", file=sys.stderr)
        return 2
    text = p.read_text(encoding="utf-8", errors="replace")

    try:
        result = analyze(text)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_console(result)

    if args.html:
        Path(args.html).write_text(build_html(result, p.name), encoding="utf-8")
        print(f"\nHTML report written to {args.html}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
