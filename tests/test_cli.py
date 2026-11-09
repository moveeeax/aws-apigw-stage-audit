import json

import pytest

from aws_apigw_stage_audit.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_from_json_reproduces_a_full_run_offline(capsys, fixtures_dir):
    code, out, err = run(capsys, "--from-json", str(fixtures_dir / "messy.json"), "--fail-on", "none")
    assert code == EXIT_OK
    assert err == ""
    assert "legacy-partner-api" in out
    assert "events-ingest" in out
    assert "no-throttling" in out
    assert "orphan-key" in out


def test_fail_on_critical_exits_one_when_critical(capsys, fixtures_dir):
    code, _, _ = run(capsys, "--from-json", str(fixtures_dir / "messy.json"), "--fail-on", "critical")
    assert code == EXIT_FINDINGS


def test_fail_on_critical_exits_zero_on_a_clean_account(capsys, fixtures_dir):
    code, out, _ = run(capsys, "--from-json", str(fixtures_dir / "clean.json"), "--fail-on", "critical")
    assert code == EXIT_OK
    assert "no findings" in out


def test_fail_on_warn_catches_a_warn_only_account(capsys, fixtures_dir):
    payload = str(fixtures_dir / "warn_only.json")
    assert run(capsys, "--from-json", payload, "--fail-on", "critical")[0] == EXIT_OK
    assert run(capsys, "--from-json", payload, "--fail-on", "warn")[0] == EXIT_FINDINGS


def test_fail_on_none_always_exits_zero(capsys, fixtures_dir):
    code, _, _ = run(capsys, "--from-json", str(fixtures_dir / "messy.json"), "--fail-on", "none")
    assert code == EXIT_OK


def test_missing_payload_file_exits_two_with_a_message(capsys, tmp_path):
    code, out, err = run(capsys, "--from-json", str(tmp_path / "nope.json"))
    assert code == EXIT_USAGE
    assert "error:" in err
    assert "Traceback" not in err
    assert out == ""


def test_invalid_json_exits_two_with_a_message(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    code, _, err = run(capsys, "--from-json", str(bad))
    assert code == EXIT_USAGE
    assert "not valid JSON" in err
    assert "Traceback" not in err


def test_malformed_payload_shape_exits_two_with_a_message(capsys, fixtures_dir):
    code, _, err = run(capsys, "--from-json", str(fixtures_dir / "malformed.json"))
    assert code == EXIT_USAGE
    assert "rest_apis must be a list" in err
    assert "Traceback" not in err


def test_json_output_is_parseable_and_shaped_for_jq(capsys, fixtures_dir):
    code, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "messy.json"), "--format", "json", "--fail-on", "none"
    )
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["severity"] == "critical"
    criticals = [s for s in data["stages"] if s["severity"] == "critical"]
    assert [s["stage"] for s in criticals] == ["prod", "sandbox", "$default"]
    assert data["stages"][0]["findings"][0]["fix"]


def test_markdown_output_has_a_table_and_critical_section(capsys, fixtures_dir):
    _, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "messy.json"), "--format", "markdown", "--fail-on", "none"
    )
    assert out.startswith("# API Gateway stage audit")
    assert "| Stage | Severity | Finding | Target |" in out
    assert "## Critical findings" in out


def test_dump_json_writes_the_payload_back(capsys, fixtures_dir, tmp_path):
    out_file = tmp_path / "dump.json"
    code, _, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "messy.json"),
        "--dump-json",
        str(out_file),
        "--fail-on",
        "none",
    )
    assert code == EXIT_OK
    assert json.loads(out_file.read_text(encoding="utf-8"))["region"] == "eu-central-1"


def test_max_rate_is_honoured_from_the_cli(capsys, fixtures_dir):
    _, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "clean.json"),
        "--max-rate",
        "100",
        "--fail-on",
        "none",
    )
    assert "throttle-above-ceiling" in out


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0


def test_unknown_flag_exits_two(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--nope"])
    assert excinfo.value.code == EXIT_USAGE


def test_no_aws_calls_are_needed_for_from_json(capsys, fixtures_dir, monkeypatch):
    """boto3 is not installed in CI's test job; --from-json must never import it."""
    import builtins

    real_import = builtins.__import__

    def guard(name, *args, **kwargs):
        if name == "boto3" or name.startswith("boto3."):
            raise AssertionError("--from-json must not import boto3")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guard)
    code, _, _ = run(capsys, "--from-json", str(fixtures_dir / "clean.json"))
    assert code == EXIT_OK
