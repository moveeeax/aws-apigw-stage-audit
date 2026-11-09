"""Render a Report as text, JSON or Markdown."""

from __future__ import annotations

import json

from .model import CRITICAL, OK, WARN, Report

_MARK = {CRITICAL: "CRIT", WARN: "WARN", OK: "ok"}


def _stage_label(stage) -> str:
    name = stage.api_name or stage.api_id
    return f"{name} [{stage.protocol}] / {stage.stage}"


def render_text(report: Report) -> str:
    lines = []
    header = f"API Gateway stage audit — region {report.region or 'unknown'}"
    lines.append(header)
    lines.append("=" * len(header))

    if not report.stages:
        lines.append("No API Gateway stages found.")

    for stage in report.stages:
        lines.append("")
        lines.append(f"[{_MARK[stage.severity]}] {_stage_label(stage)}")
        if not stage.findings:
            lines.append("    no findings")
            continue
        for finding in stage.findings:
            target = f" ({finding.target})" if finding.target else ""
            lines.append(f"    {_MARK[finding.severity]:>4}  {finding.code}{target}")
            lines.append(f"          {finding.detail}")
            lines.append(f"          fix: {finding.fix}")

    if report.account_findings:
        lines.append("")
        lines.append("[account]")
        for finding in report.account_findings:
            target = f" ({finding.target})" if finding.target else ""
            lines.append(f"    {_MARK[finding.severity]:>4}  {finding.code}{target}")
            lines.append(f"          {finding.detail}")
            lines.append(f"          fix: {finding.fix}")

    counts = report.counts()
    lines.append("")
    lines.append(
        f"{len(report.stages)} stage(s), {counts[CRITICAL]} critical, {counts[WARN]} warn, "
        f"{sum(1 for s in report.stages if s.severity == OK)} clean"
    )
    return "\n".join(lines)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def render_markdown(report: Report) -> str:
    counts = report.counts()
    lines = [
        f"# API Gateway stage audit — `{report.region or 'unknown'}`",
        "",
        f"{len(report.stages)} stage(s) audited — **{counts[CRITICAL]} critical**, "
        f"{counts[WARN]} warn.",
        "",
        "| Stage | Severity | Finding | Target |",
        "| --- | --- | --- | --- |",
    ]
    for stage in report.stages:
        if not stage.findings:
            lines.append(f"| `{_stage_label(stage)}` | ok | — | — |")
            continue
        for finding in stage.findings:
            lines.append(
                f"| `{_stage_label(stage)}` | {finding.severity} | `{finding.code}` | "
                f"{finding.target or '—'} |"
            )
    for finding in report.account_findings:
        lines.append(f"| _account_ | {finding.severity} | `{finding.code}` | {finding.target or '—'} |")

    detailed = [f for f in report.all_findings() if f.severity == CRITICAL]
    if detailed:
        lines += ["", "## Critical findings", ""]
        for finding in detailed:
            lines.append(f"- **`{finding.code}`** {finding.detail}")
            lines.append(f"  - fix: {finding.fix}")
    return "\n".join(lines)


RENDERERS = {"text": render_text, "json": render_json, "markdown": render_markdown}


def render(report: Report, fmt: str) -> str:
    try:
        return RENDERERS[fmt](report)
    except KeyError:
        raise ValueError(f"unknown format: {fmt}") from None
