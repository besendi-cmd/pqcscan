from __future__ import annotations

import argparse
import glob
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .baseline import apply_baseline, load_baseline, write_baseline
from .cbom import to_cbom
from .report import to_json, to_sarif, to_text
from .rules import ALL_RULES, SEVERITIES
from .scanner import scan


def _write(path: str, content: str) -> None:
    Path(path).write_text(content + "\n")


def _baseline_excludes(args) -> list[str]:
    root = Path(args.path).resolve()
    excludes = []
    for path in (args.baseline, args.write_baseline):
        if path:
            try:
                excludes.append(glob.escape(Path(path).resolve().relative_to(root).as_posix()))
            except ValueError:
                pass
    return excludes


def cmd_scan(args) -> int:
    result = scan(args.path, excludes=args.exclude + _baseline_excludes(args), min_severity=args.min_severity)
    known = None
    if args.baseline:
        try:
            known = load_baseline(args.baseline)
        except (OSError, ValueError) as e:
            print(f"pqcscan: cannot read baseline: {e}", file=sys.stderr)
            return 2
    if args.write_baseline:
        n = write_baseline(result, args.write_baseline)
        print(f"Wrote baseline with {n} findings to {args.write_baseline}", file=sys.stderr)
    inventory = replace(result, findings=list(result.findings))
    if known is not None:
        apply_baseline(result, known)
    if args.format == "text":
        color = sys.stdout.isatty() and not args.no_color and not args.output
        report = to_text(result, color=color)
    else:
        report = to_cbom(inventory) if args.format == "cbom" else {"json": to_json, "sarif": to_sarif}[args.format](result)
    if args.output:
        _write(args.output, report)
    else:
        print(report)
    if args.sarif:
        _write(args.sarif, to_sarif(result))
    if args.json:
        _write(args.json, to_json(result))
    if args.cbom:
        _write(args.cbom, to_cbom(inventory))
    if args.fail_on != "none" and result.at_or_above(args.fail_on):
        return 1
    return 0


def cmd_rules(args) -> int:
    for r in ALL_RULES.values():
        print(f"{r.id}  {r.severity:<8}  {r.threat:<9}  {r.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pqcscan", description="Find quantum-vulnerable cryptography in a codebase.")
    p.add_argument("--version", action="version", version=f"pqcscan {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a directory or file")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("-f", "--format", choices=["text", "json", "sarif", "cbom"], default="text")
    s.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    s.add_argument("--sarif", metavar="FILE", help="also write a SARIF report (for GitHub Code Scanning)")
    s.add_argument("--json", metavar="FILE", help="also write a JSON report")
    s.add_argument("--cbom", metavar="FILE", help="also write a CycloneDX 1.6 cryptographic bill of materials")
    s.add_argument("--baseline", metavar="FILE", help="only report findings that are not in this baseline file")
    s.add_argument("--write-baseline", metavar="FILE", help="record all current findings as the baseline")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip matching paths (repeatable)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this severity")
    s.add_argument("--fail-on", choices=SEVERITIES + ("none",), default="none",
                   help="exit with code 1 if any finding is at or above this severity")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=cmd_scan)

    sub.add_parser("rules", help="list detection rules").set_defaults(func=cmd_rules)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
