"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .model import CRITICAL, WARN, rank
from .report import render
from .rules import Options, PayloadError, audit

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-apigw-stage-audit",
        description="Audit API Gateway REST and HTTP API stages for unsafe defaults.",
    )
    parser.add_argument("--region", help="AWS region to audit (default: the session region)")
    parser.add_argument("--profile", help="AWS profile to use")
    parser.add_argument("--api", help="audit only this API, by name or id")
    parser.add_argument(
        "--max-rate",
        type=float,
        default=10_000.0,
        help="flag a stage throttle above this rate, in rps (default: 10000)",
    )
    parser.add_argument(
        "--stale-days",
        type=int,
        default=180,
        help="flag a live deployment older than this many days (default: 180)",
    )
    parser.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text", help="output format"
    )
    parser.add_argument(
        "--fail-on",
        choices=("warn", "critical", "none"),
        default="critical",
        help="exit 1 when a finding reaches this severity (default: critical)",
    )
    parser.add_argument("--from-json", metavar="FILE", help="audit a saved payload, making no AWS calls")
    parser.add_argument("--dump-json", metavar="FILE", help="write the collected payload to FILE")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def load_payload(path: str) -> dict:
    """Read a payload file, turning every failure into a clean message."""
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise PayloadError(f"cannot read {path}: {exc.strerror or exc}") from None
    except json.JSONDecodeError as exc:
        raise PayloadError(f"{path} is not valid JSON: {exc.msg} at line {exc.lineno}") from None


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.from_json:
        try:
            payload = load_payload(args.from_json)
        except PayloadError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
    else:
        from .collect import collect  # noqa: PLC0415 - keeps boto3 optional

        try:
            payload = collect(region=args.region, profile=args.profile)
        except Exception as exc:  # noqa: BLE001 - every AWS failure is the same story here
            print(f"error: cannot read API Gateway: {exc}", file=sys.stderr)
            return EXIT_USAGE

    if args.dump_json:
        try:
            with open(args.dump_json, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError as exc:
            print(f"error: cannot write {args.dump_json}: {exc.strerror or exc}", file=sys.stderr)
            return EXIT_USAGE

    options = Options(max_rate=args.max_rate, stale_days=args.stale_days)
    try:
        report = audit(payload, options=options, api_filter=args.api)
    except PayloadError as exc:
        source = args.from_json or "collected payload"
        print(f"error: {source}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(render(report, args.format))

    if args.fail_on == "none":
        return EXIT_OK
    threshold = CRITICAL if args.fail_on == "critical" else WARN
    if rank(report.severity) >= rank(threshold):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
