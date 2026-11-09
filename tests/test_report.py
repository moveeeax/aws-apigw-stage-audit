import json

import pytest

from aws_apigw_stage_audit.model import CRITICAL, OK, WARN, Finding, worst
from aws_apigw_stage_audit.report import render
from aws_apigw_stage_audit.rules import audit


def test_worst_picks_the_highest_severity():
    assert worst([]) == OK
    assert worst([OK, WARN]) == WARN
    assert worst([WARN, CRITICAL, OK]) == CRITICAL


def test_finding_rejects_an_unknown_severity():
    with pytest.raises(ValueError):
        Finding(code="x", severity="fatal", detail="d", fix="f")


def test_text_output_shows_every_fix(messy):
    text = render(audit(messy), "text")
    assert "fix:" in text
    assert text.count("CRIT") >= 4
    assert "region eu-central-1" in text


def test_text_output_on_a_clean_account(clean):
    text = render(audit(clean), "text")
    assert "no findings" in text
    assert "1 stage(s), 0 critical, 0 warn, 1 clean" in text


def test_text_output_with_no_stages():
    text = render(audit({}), "text")
    assert "No API Gateway stages found." in text


def test_json_round_trips(messy):
    data = json.loads(render(audit(messy), "json"))
    assert data["summary"]["findings"] == len(audit(messy).all_findings())
    for stage in data["stages"]:
        for finding in stage["findings"]:
            assert set(finding) == {"code", "severity", "target", "detail", "fix"}


def test_markdown_lists_clean_stages_too(clean):
    md = render(audit(clean), "markdown")
    assert "| ok | — | — |" in md
    assert "## Critical findings" not in md


def test_unknown_format_raises():
    with pytest.raises(ValueError):
        render(audit({}), "yaml")
