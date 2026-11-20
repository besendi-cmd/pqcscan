from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .baseline import apply_baseline, load_baseline, write_baseline
from .cbom import to_cbom
from .report import to_json, to_sarif, to_text
from .rules import ALL_RULES, SEVERITIES
from .scanner import scan


def _write(path: str, content: str) -> None:
    Path(path).write_text(content + "\n")


def cmd_scan(args) -> int:
    result = scan(args.path, excludes=args.exclude, min_severity=args.min_severity)
    if args.write_baseline:
        n = write_baseline(result, args.write_baseline)
        print(f"Wrote baseline with {n} findings to {args.write_baseline}", file=sys.stderr)
    if args.upload:
        from .upload import UploadError, upload
        token = os.environ.get("PQCSCAN_TOKEN")
        if not token:
            print("pqcscan: set PQCSCAN_TOKEN to the dashboard upload token", file=sys.stderr)
            return 2
        try:
            uploaded = upload(result, args.upload, token, repo=args.repo_name)
        except UploadError as e:
            print(f"pqcscan: upload failed: {e}", file=sys.stderr)
            return 2
        print(f"Uploaded scan to {uploaded.get('url', args.upload)}", file=sys.stderr)
    if args.baseline:
        try:
            apply_baseline(result, load_baseline(args.baseline))
        except (OSError, ValueError) as e:
            print(f"pqcscan: cannot read baseline: {e}", file=sys.stderr)
            return 2
    if args.format == "text":
        color = sys.stdout.isatty() and not args.no_color and not args.output
        report = to_text(result, color=color)
    else:
        report = {"json": to_json, "sarif": to_sarif, "cbom": to_cbom}[args.format](result)
    if args.output:
        _write(args.output, report)
    else:
        print(report)
    if args.sarif:
        _write(args.sarif, to_sarif(result))
    if args.json:
        _write(args.json, to_json(result))
    if args.cbom:
        _write(args.cbom, to_cbom(result))
    if args.fail_on != "none" and result.at_or_above(args.fail_on):
        return 1
    return 0


def cmd_rules(args) -> int:
    for r in ALL_RULES.values():
        print(f"{r.id}  {r.severity:<8}  {r.threat:<9}  {r.title}")
    return 0


def cmd_serve(args) -> int:
    try:
        import uvicorn

        from .dashboard.app import create_app
    except ImportError:
        print("pqcscan: the dashboard needs extra packages: pip install 'pqcscan[dashboard]'", file=sys.stderr)
        return 2
    token = os.environ.get("PQCSCAN_DASHBOARD_TOKEN")
    if not token:
        import secrets
        token = secrets.token_urlsafe(32)
        print(f"PQCSCAN_DASHBOARD_TOKEN not set; upload token for this run: {token}", file=sys.stderr)
    uvicorn.run(create_app(args.db, token), host=args.host, port=args.port, proxy_headers=True)
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
    s.add_argument("--upload", metavar="URL",
                   help="send the full scan to a pqcscan dashboard (token from $PQCSCAN_TOKEN)")
    s.add_argument("--repo-name", metavar="NAME", help="repository name for --upload (default: detected from git)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip matching paths (repeatable)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this severity")
    s.add_argument("--fail-on", choices=SEVERITIES + ("none",), default="none",
                   help="exit with code 1 if any finding is at or above this severity")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("serve", help="run the migration dashboard (uploads need $PQCSCAN_DASHBOARD_TOKEN)")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8000)
    d.add_argument("--db", default="pqcscan-dashboard.db", help="SQLite database file")
    d.set_defaults(func=cmd_serve)

    sub.add_parser("rules", help="list detection rules").set_defaults(func=cmd_rules)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
