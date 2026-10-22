#!/usr/bin/env python3
"""php2shellscan — PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure scanner.

Usage:
  python -m php2shellscan https://example.com [https://other ...]
  python -m php2shellscan -f targets.txt -o report.json --json-only

Only authorized testing against systems you own or have permission to assess.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .probes import scan_targets
from .report import render_json, render_table, verdict


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shellscan",
        description="Exposure scanner for PHP2Shell "
                    "(CVE-2026-109618 / CVE-2026-109619, pre-auth RCE in "
                    "core PHP, patched 2026-10-21).",
    )
    p.add_argument("targets", nargs="*", help="URL(s) or host[:port] to scan")
    p.add_argument("-f", "--targets-file", help="file with one target per line")
    p.add_argument("-t", "--timeout", type=float, default=8.0,
                   help="per-request timeout seconds (default 8)")
    p.add_argument("-c", "--concurrency", type=int, default=8,
                   help="parallel workers (default 8)")
    p.add_argument("--passive", action="store_true",
                   help="fingerprint/version only; skip active probes")
    p.add_argument("--assume-vulnerable", action="store_true",
                   help="when PHP is detected but its version is hidden, "
                        "report 'assumed_vulnerable' instead of 'unknown' "
                        "(all >= 5.4 pre-advisory builds are affected)")
    p.add_argument("-o", "--output", help="write JSON report to file")
    p.add_argument("--json-only", action="store_true",
                   help="print JSON to stdout instead of the table")
    p.add_argument("-V", "--version", action="version",
                   version=f"php2shellscan {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    targets = list(args.targets)
    if args.targets_file:
        with open(args.targets_file, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh
                        if ln.strip() and not ln.startswith("#")]
    if not targets:
        build_parser().error("no targets given (positional args or -f FILE)")

    results = scan_targets(targets, timeout=args.timeout,
                           active=not args.passive,
                           concurrency=args.concurrency)
    verdicts = [verdict(r, assume_vulnerable=args.assume_vulnerable)
                for r in results]

    report = render_json(verdicts, results=results)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")

    if args.json_only:
        print(report)
    else:
        print(render_table(verdicts))
        for v in verdicts:
            if v["verdict"] in ("vulnerable", "assumed_vulnerable"):
                print(f"\n[{v['target']}] {v['summary']}")
                for rec in v["recommendations"]:
                    print(f"  - {rec}")
        if args.output:
            print(f"\nJSON report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
