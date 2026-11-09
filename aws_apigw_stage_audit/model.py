"""Severity ordering and the finding record every rule produces."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

OK = "ok"
WARN = "warn"
CRITICAL = "critical"

SEVERITIES = (OK, WARN, CRITICAL)
_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def rank(severity: str) -> int:
    """Numeric order of a severity, so callers can compare them."""
    try:
        return _RANK[severity]
    except KeyError:
        raise ValueError(f"unknown severity: {severity!r}") from None


def worst(severities: Iterable[str]) -> str:
    """Highest severity in the iterable, or `ok` when it is empty."""
    highest = OK
    for severity in severities:
        if rank(severity) > rank(highest):
            highest = severity
    return highest


@dataclass(frozen=True)
class Finding:
    """One problem with one stage, carrying the fix that closes it.

    `code` is stable and meant to be grepped in CI logs; `target` narrows the
    finding inside the stage (a method, a custom domain, an API key).
    """

    code: str
    severity: str
    detail: str
    fix: str
    target: str = ""

    def __post_init__(self) -> None:
        rank(self.severity)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "target": self.target,
            "detail": self.detail,
            "fix": self.fix,
        }


@dataclass
class StageReport:
    """Every finding for one stage, plus the identity needed to go fix it."""

    api_id: str
    api_name: str
    protocol: str
    stage: str
    findings: list

    @property
    def severity(self) -> str:
        return worst(f.severity for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "api_id": self.api_id,
            "api_name": self.api_name,
            "protocol": self.protocol,
            "stage": self.stage,
            "severity": self.severity,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Report:
    """The whole run: one entry per stage, plus account-wide findings."""

    region: str
    stages: list
    account_findings: list

    @property
    def severity(self) -> str:
        return worst(
            [s.severity for s in self.stages] + [f.severity for f in self.account_findings]
        )

    def counts(self) -> dict:
        counts = dict.fromkeys(SEVERITIES, 0)
        for finding in self.all_findings():
            counts[finding.severity] += 1
        return counts

    def all_findings(self) -> list:
        findings = []
        for stage in self.stages:
            findings.extend(stage.findings)
        findings.extend(self.account_findings)
        return findings

    def to_dict(self) -> dict:
        counts = self.counts()
        return {
            "region": self.region,
            "severity": self.severity,
            "summary": {
                "stages": len(self.stages),
                "stages_clean": sum(1 for s in self.stages if s.severity == OK),
                "findings": len(self.all_findings()),
                "critical": counts[CRITICAL],
                "warn": counts[WARN],
            },
            "stages": [s.to_dict() for s in self.stages],
            "account_findings": [f.to_dict() for f in self.account_findings],
        }
