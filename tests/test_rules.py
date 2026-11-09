import copy
import datetime as dt

import pytest

from aws_apigw_stage_audit.model import CRITICAL, OK, WARN
from aws_apigw_stage_audit.rules import ACCOUNT_RATE_QUOTA, Options, PayloadError, audit


def codes(report, stage_name=None):
    out = []
    for stage in report.stages:
        if stage_name and stage.stage != stage_name:
            continue
        out.extend(f.code for f in stage.findings)
    return out


def finding(report, code, stage_name=None):
    for stage in report.stages:
        if stage_name and stage.stage != stage_name:
            continue
        for f in stage.findings:
            if f.code == code:
                return f
    return None


def stage_by_name(report, name):
    for stage in report.stages:
        if stage.stage == name:
            return stage
    raise AssertionError(f"no stage {name} in report")


# --------------------------------------------------------------------------- #
# the clean baseline
# --------------------------------------------------------------------------- #


def test_clean_payload_has_no_findings(clean):
    report = audit(clean)
    assert report.stages, "fixture should produce one stage"
    assert codes(report) == []
    assert report.account_findings == []
    assert report.severity == OK


def test_clean_payload_summary(clean):
    data = audit(clean).to_dict()
    assert data["summary"]["stages"] == 1
    assert data["summary"]["stages_clean"] == 1
    assert data["summary"]["critical"] == 0
    assert data["region"] == "eu-central-1"


# --------------------------------------------------------------------------- #
# throttling
# --------------------------------------------------------------------------- #


def test_unthrottled_rest_stage_is_critical_and_names_the_account_quota(messy):
    report = audit(messy)
    f = finding(report, "no-throttling", "prod")
    assert f is not None
    assert f.severity == CRITICAL
    assert str(ACCOUNT_RATE_QUOTA) in f.detail
    assert "throttlingRateLimit" in f.fix


def test_explicit_rate_and_burst_is_not_flagged(clean):
    assert "no-throttling" not in codes(audit(clean))


def test_usage_plan_only_throttle_is_warn_not_critical(messy):
    """The sandbox stage has no stage throttle but a usage plan covers it."""
    report = audit(messy)
    assert "no-throttling" not in codes(report, "sandbox")
    f = finding(report, "throttle-only-in-usage-plan", "sandbox")
    assert f is not None
    assert f.severity == WARN
    assert "50" in f.detail


def test_throttle_above_ceiling_is_warn(clean):
    payload = copy.deepcopy(clean)
    payload["rest_apis"][0]["stages"][0]["methodSettings"]["*/*"]["throttlingRateLimit"] = 9000
    report = audit(payload, options=Options(max_rate=1000))
    f = finding(report, "throttle-above-ceiling")
    assert f is not None and f.severity == WARN
    assert "9000" in f.detail


def test_zero_is_not_mistaken_for_unset(clean):
    """A throttle of 0 blocks everything, but it is set — never 'no-throttling'."""
    payload = copy.deepcopy(clean)
    payload["rest_apis"][0]["stages"][0]["methodSettings"]["*/*"]["throttlingRateLimit"] = 0
    payload["rest_apis"][0]["stages"][0]["methodSettings"]["*/*"]["throttlingBurstLimit"] = 0
    assert "no-throttling" not in codes(audit(payload))


# --------------------------------------------------------------------------- #
# access logging
# --------------------------------------------------------------------------- #


def test_access_logging_unset_is_warn_and_fix_names_the_fields(messy):
    report = audit(messy)
    f = finding(report, "access-logging-disabled", "prod")
    assert f is not None
    assert f.severity == WARN
    assert "destinationArn" in f.fix
    assert "accessLogSettings.format" in f.fix
    assert "$context.requestId" in f.fix
    assert "$context.status" in f.fix


def test_access_log_format_missing_fields_is_warn(messy):
    report = audit(messy)
    f = finding(report, "access-log-format-incomplete", "sandbox")
    assert f is not None and f.severity == WARN
    assert "$context.requestId" in f.detail
    assert "$context.status" in f.detail


def test_complete_access_log_format_is_accepted(clean):
    found = codes(audit(clean))
    assert "access-logging-disabled" not in found
    assert "access-log-format-incomplete" not in found


# --------------------------------------------------------------------------- #
# method and route authorization
# --------------------------------------------------------------------------- #


def test_open_rest_method_is_critical_and_names_method_and_path(messy):
    report = audit(messy)
    f = finding(report, "open-method", "prod")
    assert f is not None
    assert f.severity == CRITICAL
    assert f.target == "GET /partners/{id}"
    assert "/partners/{id}" in f.detail


def test_method_behind_an_authorizer_is_ok(clean):
    assert "open-method" not in codes(audit(clean))


def test_api_key_required_counts_as_protection(messy):
    """DELETE is authorizationType NONE but apiKeyRequired, so it is not reported."""
    report = audit(messy)
    targets = [f.target for f in stage_by_name(report, "prod").findings if f.code == "open-method"]
    assert "DELETE /partners/{id}" not in targets


def test_options_preflight_is_not_reported(messy):
    report = audit(messy)
    all_targets = [f.target for f in report.all_findings()]
    assert not [t for t in all_targets if t.startswith("OPTIONS")]


def test_http_route_without_authorizer_is_critical(messy):
    report = audit(messy)
    f = finding(report, "http-route-no-authorizer", "$default")
    assert f is not None
    assert f.severity == CRITICAL
    assert f.target == "POST /events"


def test_http_route_with_jwt_authorizer_is_ok(messy):
    report = audit(messy)
    targets = [f.target for f in report.all_findings() if f.code == "http-route-no-authorizer"]
    assert "GET /health" not in targets


# --------------------------------------------------------------------------- #
# cache, TLS, endpoint type
# --------------------------------------------------------------------------- #


def test_unencrypted_cache_is_critical(messy):
    f = finding(audit(messy), "cache-unencrypted", "prod")
    assert f is not None and f.severity == CRITICAL
    assert "cacheDataEncrypted" in f.fix


def test_encrypted_cache_is_ok(clean):
    assert "cache-unencrypted" not in codes(audit(clean))


def test_stale_tls_policy_is_warn_and_names_the_domain(messy):
    f = finding(audit(messy), "stale-tls-policy", "prod")
    assert f is not None and f.severity == WARN
    assert f.target == "partners.example.com"
    assert "TLS_1_0" in f.detail


def test_edge_domain_is_warn(messy):
    f = finding(audit(messy), "edge-endpoint", "prod")
    assert f is not None and f.severity == WARN


def test_mtls_with_execute_api_endpoint_enabled_is_critical(messy):
    f = finding(audit(messy), "mtls-bypassable", "prod")
    assert f is not None and f.severity == CRITICAL
    assert "disableExecuteApiEndpoint" in f.fix


def test_mtls_is_ok_when_the_default_endpoint_is_disabled(messy):
    payload = copy.deepcopy(messy)
    payload["rest_apis"][0]["disableExecuteApiEndpoint"] = True
    assert "mtls-bypassable" not in codes(audit(payload))


def test_tls_1_3_is_accepted(messy):
    payload = copy.deepcopy(messy)
    payload["domain_names"][0]["securityPolicy"] = "TLS_1_3"
    assert "stale-tls-policy" not in codes(audit(payload))


# --------------------------------------------------------------------------- #
# observability, hygiene, account-level
# --------------------------------------------------------------------------- #


def test_logging_off_and_metrics_and_xray_are_each_reported(messy):
    found = codes(audit(messy), "prod")
    assert "execution-logging-off" in found
    assert "detailed-metrics-disabled" in found
    assert "xray-disabled" in found


def test_error_only_logging_is_reported_on_production_stages(clean):
    payload = copy.deepcopy(clean)
    payload["rest_apis"][0]["stages"][0]["methodSettings"]["*/*"]["loggingLevel"] = "ERROR"
    assert "execution-logging-errors-only" in codes(audit(payload))


def test_error_only_logging_is_tolerated_outside_production(clean):
    payload = copy.deepcopy(clean)
    stage = payload["rest_apis"][0]["stages"][0]
    stage["stageName"] = "dev"
    stage["methodSettings"]["*/*"]["loggingLevel"] = "ERROR"
    assert "execution-logging-errors-only" not in codes(audit(payload))


def test_missing_waf_is_warn(messy):
    assert "no-waf" in codes(audit(messy), "prod")


def test_client_cert_tag_without_a_certificate_is_warn(messy):
    f = finding(audit(messy), "client-cert-unset", "prod")
    assert f is not None and f.severity == WARN


def test_client_cert_present_is_ok(messy):
    assert "client-cert-unset" not in codes(audit(messy), "sandbox")


def test_canary_left_on_is_warn(messy):
    f = finding(audit(messy), "canary-left-on", "prod")
    assert f is not None and f.severity == WARN
    assert "10" in f.detail


def test_stale_deployment_uses_the_configured_window(clean):
    payload = copy.deepcopy(clean)
    payload["rest_apis"][0]["stages"][0]["createdDate"] = "2024-01-01T00:00:00+00:00"
    now = dt.datetime(2026, 11, 9, tzinfo=dt.UTC)
    assert "stale-deployment" in codes(audit(payload, options=Options(stale_days=180, now=now)))
    assert "stale-deployment" not in codes(audit(payload, options=Options(stale_days=5000, now=now)))


def test_unparseable_deployment_date_is_ignored(clean):
    payload = copy.deepcopy(clean)
    payload["rest_apis"][0]["stages"][0]["createdDate"] = "whenever"
    assert "stale-deployment" not in codes(audit(payload))


def test_api_key_with_no_usage_plan_is_an_account_finding(messy):
    report = audit(messy)
    account = {f.code: f for f in report.account_findings}
    assert "api-key-no-usage-plan" in account
    assert account["api-key-no-usage-plan"].target == "orphan-key"
    assert account["api-key-no-usage-plan"].severity == WARN


# --------------------------------------------------------------------------- #
# filtering, severity rollup, payload validation
# --------------------------------------------------------------------------- #


def test_api_filter_selects_by_name_and_by_id(messy):
    by_name = audit(messy, api_filter="events-ingest")
    assert [s.stage for s in by_name.stages] == ["$default"]
    by_id = audit(messy, api_filter="zz9plural")
    assert sorted(s.stage for s in by_id.stages) == ["prod", "sandbox"]


def test_api_filter_skips_account_findings(messy):
    assert audit(messy, api_filter="events-ingest").account_findings == []


def test_stage_severity_is_the_worst_finding(messy, warn_only):
    report = audit(messy)
    assert stage_by_name(report, "prod").severity == CRITICAL
    assert report.severity == CRITICAL

    mild = audit(warn_only)
    assert mild.severity == WARN
    assert sorted(codes(mild)) == ["detailed-metrics-disabled", "xray-disabled"]


def test_api_level_methods_are_reported_on_every_stage(messy):
    """Methods belong to the API, not the stage, so an open method taints all stages."""
    report = audit(messy)
    assert "open-method" in codes(report, "prod")
    assert "open-method" in codes(report, "sandbox")
    assert stage_by_name(report, "sandbox").severity == CRITICAL


def test_report_counts_match_the_findings(messy):
    report = audit(messy)
    counts = report.counts()
    assert counts[CRITICAL] + counts[WARN] == len(report.all_findings())
    assert counts[CRITICAL] >= 4


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "nope",
        {"rest_apis": {"id": "x"}},
        {"rest_apis": [{"id": "x", "stages": "prod"}]},
        {"http_apis": [{"apiId": "x", "stages": 3}]},
        {"api_keys": "key1"},
    ],
)
def test_bad_payload_shapes_raise_payload_error(payload):
    with pytest.raises(PayloadError):
        audit(payload)


def test_empty_payload_is_valid_and_empty(clean):
    report = audit({})
    assert report.stages == []
    assert report.severity == OK
