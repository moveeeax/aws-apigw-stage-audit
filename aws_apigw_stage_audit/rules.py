"""The rule engine.

Input is the plain-dict payload produced by `collect` (or loaded from a file
with `--from-json`), so every rule here is testable without AWS credentials.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .model import CRITICAL, WARN, Finding, Report, StageReport

#: AWS applies this account-wide limit when a stage sets no throttle of its own.
ACCOUNT_RATE_QUOTA = 10_000

#: Stage names that make a missing safeguard an incident rather than a nit.
PRODUCTION_STAGE_NAMES = frozenset({"prod", "production", "prd", "live", "default", "$default"})

#: Minimum TLS policy we accept on a custom domain.
ACCEPTED_TLS_POLICIES = frozenset({"TLS_1_2", "TLS_1_3"})

#: Access log format fields without which the log cannot answer "what broke".
REQUIRED_LOG_FIELDS = ("$context.requestId", "$context.status")

#: Tag that marks an API as expecting a backend client certificate.
CLIENT_CERT_TAG = "apigw:require-client-cert"

_UNSET_THROTTLE = (None, "", -1, -1.0)


@dataclass(frozen=True)
class Options:
    """Thresholds that a caller may reasonably disagree with."""

    max_rate: float = 10_000.0
    stale_days: int = 180
    now: dt.datetime = None  # type: ignore[assignment]

    def clock(self) -> dt.datetime:
        return self.now or dt.datetime.now(dt.UTC)


class PayloadError(ValueError):
    """The payload is not a shape this tool can audit."""


# --------------------------------------------------------------------------- #
# payload helpers
# --------------------------------------------------------------------------- #


def _require_dict(value, where: str) -> dict:
    if not isinstance(value, dict):
        raise PayloadError(f"{where} must be an object, got {type(value).__name__}")
    return value


def _require_list(value, where: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PayloadError(f"{where} must be a list, got {type(value).__name__}")
    return value


def validate_payload(payload) -> dict:
    """Check the payload shape up front so rules never guess at types."""
    payload = _require_dict(payload, "payload")
    for key in ("rest_apis", "http_apis", "domain_names", "api_keys", "usage_plans"):
        _require_list(payload.get(key), key)
    for api in payload["rest_apis"] if payload.get("rest_apis") else []:
        _require_dict(api, "rest_apis[]")
        _require_list(api.get("stages"), "rest_apis[].stages")
    for api in payload["http_apis"] if payload.get("http_apis") else []:
        _require_dict(api, "http_apis[]")
        _require_list(api.get("stages"), "http_apis[].stages")
    return payload


def _is_unset(value) -> bool:
    return value in _UNSET_THROTTLE


def _is_production(stage_name: str) -> bool:
    name = (stage_name or "").lower()
    return name in PRODUCTION_STAGE_NAMES or name.startswith("prod")


def _parse_time(value):
    if not value:
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def _tls_rank(policy: str) -> str:
    return (policy or "").upper()


# --------------------------------------------------------------------------- #
# indexes built once and shared by every rule
# --------------------------------------------------------------------------- #


class Index:
    """Joins stages to the usage plans and custom domains that cover them."""

    def __init__(self, payload: dict):
        self.usage_plans: dict = {}
        for plan in payload.get("usage_plans") or []:
            throttle = plan.get("throttle") or {}
            for api_stage in plan.get("apiStages") or []:
                key = (api_stage.get("apiId"), api_stage.get("stage"))
                self.usage_plans.setdefault(key, []).append(
                    {"id": plan.get("id"), "name": plan.get("name"), "throttle": throttle}
                )

        self.domains: dict = {}
        for domain in payload.get("domain_names") or []:
            for mapping in domain.get("mappings") or []:
                key = (mapping.get("apiId"), mapping.get("stage"))
                self.domains.setdefault(key, []).append(domain)

    def plans_for(self, api_id: str, stage: str) -> list:
        return self.usage_plans.get((api_id, stage), [])

    def domains_for(self, api_id: str, stage: str) -> list:
        return self.domains.get((api_id, stage), [])

    def plan_throttle(self, api_id: str, stage: str):
        """Tightest usage-plan rate covering this stage, or None."""
        rates = [
            plan["throttle"].get("rateLimit")
            for plan in self.plans_for(api_id, stage)
            if not _is_unset(plan["throttle"].get("rateLimit"))
        ]
        return min(rates) if rates else None


# --------------------------------------------------------------------------- #
# shared stage rules
# --------------------------------------------------------------------------- #


def _access_log_findings(stage: dict) -> list:
    settings = stage.get("accessLogSettings") or {}
    destination = settings.get("destinationArn")
    if not destination:
        return [
            Finding(
                code="access-logging-disabled",
                severity=WARN,
                detail="No access log destination, so there is no request record when this stage breaks.",
                fix=(
                    "Set accessLogSettings.destinationArn to a CloudWatch Logs group ARN and "
                    "accessLogSettings.format to a JSON format including $context.requestId and $context.status."
                ),
            )
        ]

    fmt = settings.get("format") or ""
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in fmt]
    if missing:
        return [
            Finding(
                code="access-log-format-incomplete",
                severity=WARN,
                detail=f"Access log format is missing {', '.join(missing)}, so logged requests cannot be correlated.",
                fix=f"Add {', '.join(missing)} to accessLogSettings.format.",
            )
        ]
    return []


def _tls_and_endpoint_findings(api: dict, stage: dict, index: Index) -> list:
    findings = []
    for domain in index.domains_for(api.get("id"), stage.get("stageName")):
        name = domain.get("domainName", "?")
        policy = _tls_rank(domain.get("securityPolicy"))
        if policy and policy not in ACCEPTED_TLS_POLICIES:
            findings.append(
                Finding(
                    code="stale-tls-policy",
                    severity=WARN,
                    target=name,
                    detail=f"Custom domain {name} still negotiates {policy}.",
                    fix=f"Run update-domain-name on {name} to set securityPolicy to TLS_1_2.",
                )
            )
        endpoint_types = [t.upper() for t in (domain.get("endpointTypes") or [])]
        if "EDGE" in endpoint_types:
            findings.append(
                Finding(
                    code="edge-endpoint",
                    severity=WARN,
                    target=name,
                    detail=(
                        f"Custom domain {name} is an EDGE endpoint, so it carries CloudFront "
                        "latency and a separate certificate in us-east-1."
                    ),
                    fix=f"Recreate {name} with endpointConfiguration.types=[REGIONAL] unless you need the CDN.",
                )
            )
        mtls = domain.get("mutualTlsAuthentication") or {}
        if mtls.get("truststoreUri") and not api.get("disableExecuteApiEndpoint", False):
            findings.append(
                Finding(
                    code="mtls-bypassable",
                    severity=CRITICAL,
                    target=name,
                    detail=(
                        f"{name} requires mutual TLS, but the default execute-api endpoint for "
                        f"{api.get('id')} is still enabled, so a client can skip mTLS entirely."
                    ),
                    fix="Set disableExecuteApiEndpoint to true on the API so only the custom domain is reachable.",
                )
            )
    return findings


def _client_cert_findings(api: dict, stage: dict) -> list:
    tags = api.get("tags") or {}
    expects = str(tags.get(CLIENT_CERT_TAG, "")).lower() in ("1", "true", "yes")
    if expects and not stage.get("clientCertificateId"):
        return [
            Finding(
                code="client-cert-unset",
                severity=WARN,
                detail=(
                    f"API is tagged {CLIENT_CERT_TAG}, but the stage presents no client "
                    "certificate to the backend, so the backend cannot verify the caller is API Gateway."
                ),
                fix=(
                    "Create a client certificate and set clientCertificateId on the stage, "
                    "then trust it at the backend."
                ),
            )
        ]
    return []


def _stale_deployment_finding(stage: dict, options: Options) -> list:
    created = _parse_time(stage.get("deploymentCreatedDate") or stage.get("createdDate"))
    if created is None:
        return []
    age_days = (options.clock() - created).days
    if age_days > options.stale_days:
        return [
            Finding(
                code="stale-deployment",
                severity=WARN,
                detail=f"Live deployment {stage.get('deploymentId', '?')} is {age_days} days old.",
                fix="Redeploy the stage so it matches the current API definition, or delete the stage.",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# REST API stages
# --------------------------------------------------------------------------- #


def _rest_method_settings(stage: dict) -> dict:
    return (stage.get("methodSettings") or {}).get("*/*", {}) or {}


def _rest_throttle_findings(api: dict, stage: dict, index: Index, options: Options) -> list:
    defaults = _rest_method_settings(stage)
    rate = defaults.get("throttlingRateLimit")
    burst = defaults.get("throttlingBurstLimit")
    plan_rate = index.plan_throttle(api.get("id"), stage.get("stageName"))

    if _is_unset(rate) or _is_unset(burst):
        if plan_rate is not None:
            return [
                Finding(
                    code="throttle-only-in-usage-plan",
                    severity=WARN,
                    detail=(
                        f"Stage sets no default throttle; the only limit is a usage plan at "
                        f"{plan_rate} rps, which applies per API key and not to unkeyed traffic."
                    ),
                    fix="Set methodSettings['*/*'] throttlingRateLimit and throttlingBurstLimit on the stage as well.",
                )
            ]
        return [
            Finding(
                code="no-throttling",
                severity=CRITICAL,
                detail=(
                    "No stage throttle and no usage plan, so this stage inherits only the "
                    f"account quota of {ACCOUNT_RATE_QUOTA} rps shared with every other API in the account."
                ),
                fix=(
                    "Set methodSettings['*/*'].throttlingRateLimit and throttlingBurstLimit via "
                    "update-stage, sized to the backend rather than the account."
                ),
            )
        ]

    if rate > options.max_rate:
        return [
            Finding(
                code="throttle-above-ceiling",
                severity=WARN,
                detail=f"Stage throttle is {rate} rps, above the {options.max_rate} rps ceiling for this audit.",
                fix=f"Lower throttlingRateLimit to {options.max_rate} rps or raise --max-rate deliberately.",
            )
        ]
    return []


def _rest_logging_findings(stage: dict) -> list:
    findings = []
    defaults = _rest_method_settings(stage)
    level = (defaults.get("loggingLevel") or "OFF").upper()
    production = _is_production(stage.get("stageName", ""))

    if level == "OFF":
        findings.append(
            Finding(
                code="execution-logging-off",
                severity=WARN,
                detail="Execution logging is OFF, so integration and mapping failures leave no trace.",
                fix="Set methodSettings['*/*'].loggingLevel to INFO (ERROR at minimum) via update-stage.",
            )
        )
    elif level == "ERROR" and production:
        findings.append(
            Finding(
                code="execution-logging-errors-only",
                severity=WARN,
                detail=(
                    f"Production stage {stage.get('stageName')} logs at ERROR only, so "
                    "successful-but-wrong requests are invisible."
                ),
                fix="Raise methodSettings['*/*'].loggingLevel to INFO on production stages.",
            )
        )

    if not defaults.get("metricsEnabled", False):
        findings.append(
            Finding(
                code="detailed-metrics-disabled",
                severity=WARN,
                detail="Detailed CloudWatch metrics are off, so per-method latency and 5XX rates do not exist.",
                fix="Set methodSettings['*/*'].metricsEnabled to true.",
            )
        )

    if not stage.get("tracingEnabled", False):
        findings.append(
            Finding(
                code="xray-disabled",
                severity=WARN,
                detail="X-Ray tracing is disabled, so a slow request cannot be attributed to a downstream call.",
                fix="Set tracingEnabled to true on the stage.",
            )
        )
    return findings


def _rest_cache_findings(stage: dict) -> list:
    defaults = _rest_method_settings(stage)
    caching = stage.get("cacheClusterEnabled", False) or defaults.get("cachingEnabled", False)
    if caching and not defaults.get("cacheDataEncrypted", False):
        return [
            Finding(
                code="cache-unencrypted",
                severity=CRITICAL,
                detail=(
                    "Response caching is on with cacheDataEncrypted false, so response "
                    "bodies sit unencrypted at rest."
                ),
                fix="Set methodSettings['*/*'].cacheDataEncrypted to true, then flush the stage cache.",
            )
        ]
    return []


def _rest_method_findings(api: dict, stage: dict) -> list:
    findings = []
    for method in api.get("methods") or []:
        http_method = method.get("httpMethod", "?")
        path = method.get("path", "?")
        if http_method.upper() == "OPTIONS":
            continue  # CORS preflight is unauthenticated by design
        authorization = (method.get("authorizationType") or "NONE").upper()
        if authorization == "NONE" and not method.get("apiKeyRequired", False):
            findings.append(
                Finding(
                    code="open-method",
                    severity=CRITICAL,
                    target=f"{http_method} {path}",
                    detail=(
                        f"{http_method} {path} has authorizationType NONE and "
                        "apiKeyRequired false, so it is open to the internet."
                    ),
                    fix=(
                        f"Attach an authorizer to {http_method} {path}, or set "
                        "apiKeyRequired and put the key behind a usage plan."
                    ),
                )
            )
    return findings


def _rest_waf_finding(stage: dict) -> list:
    if not stage.get("webAclArn"):
        return [
            Finding(
                code="no-waf",
                severity=WARN,
                detail="No WAF web ACL is associated with the stage.",
                fix="Associate a WAFv2 web ACL with the stage ARN, at minimum the AWS managed common rule set.",
            )
        ]
    return []


def _canary_finding(stage: dict) -> list:
    canary = stage.get("canarySettings") or {}
    percent = canary.get("percentTraffic") or 0
    if percent:
        return [
            Finding(
                code="canary-left-on",
                severity=WARN,
                detail=(
                    f"Canary settings still route {percent}% of traffic to deployment "
                    f"{canary.get('deploymentId', '?')}."
                ),
                fix=(
                    "Promote the canary with update-stage --patch-operations "
                    "op=replace,path=/canarySettings, or delete it."
                ),
            )
        ]
    return []


def audit_rest_stage(api: dict, stage: dict, index: Index, options: Options) -> StageReport:
    findings = []
    findings += _rest_throttle_findings(api, stage, index, options)
    findings += _rest_method_findings(api, stage)
    findings += _rest_cache_findings(stage)
    findings += _access_log_findings(stage)
    findings += _rest_logging_findings(stage)
    findings += _rest_waf_finding(stage)
    findings += _tls_and_endpoint_findings(api, stage, index)
    findings += _client_cert_findings(api, stage)
    findings += _canary_finding(stage)
    findings += _stale_deployment_finding(stage, options)
    return StageReport(
        api_id=api.get("id", ""),
        api_name=api.get("name", ""),
        protocol="REST",
        stage=stage.get("stageName", ""),
        findings=findings,
    )


# --------------------------------------------------------------------------- #
# HTTP / WebSocket API stages
# --------------------------------------------------------------------------- #


def _http_route_findings(api: dict) -> list:
    findings = []
    for route in api.get("routes") or []:
        route_key = route.get("routeKey", "?")
        if route_key.upper().startswith("OPTIONS "):
            continue
        authorization = (route.get("authorizationType") or "NONE").upper()
        if authorization == "NONE" and not route.get("apiKeyRequired", False):
            findings.append(
                Finding(
                    code="http-route-no-authorizer",
                    severity=CRITICAL,
                    target=route_key,
                    detail=f"Route {route_key} has authorizationType NONE, so anyone who finds the URL can call it.",
                    fix=f"Attach a JWT or Lambda authorizer to {route_key} with update-route.",
                )
            )
    return findings


def _http_stage_findings(api: dict, stage: dict, index: Index, options: Options) -> list:
    findings = []
    settings = stage.get("defaultRouteSettings") or {}
    rate = settings.get("throttlingRateLimit")
    burst = settings.get("throttlingBurstLimit")

    if _is_unset(rate) or _is_unset(burst):
        findings.append(
            Finding(
                code="no-throttling",
                severity=CRITICAL,
                detail=(
                    "defaultRouteSettings sets no throttle, so this stage inherits only the "
                    f"account quota of {ACCOUNT_RATE_QUOTA} rps shared account-wide."
                ),
                fix="Set defaultRouteSettings.throttlingRateLimit and throttlingBurstLimit with update-stage.",
            )
        )
    elif rate > options.max_rate:
        findings.append(
            Finding(
                code="throttle-above-ceiling",
                severity=WARN,
                detail=f"Stage throttle is {rate} rps, above the {options.max_rate} rps ceiling for this audit.",
                fix=f"Lower throttlingRateLimit to {options.max_rate} rps or raise --max-rate deliberately.",
            )
        )

    if not settings.get("detailedMetricsEnabled", False):
        findings.append(
            Finding(
                code="detailed-metrics-disabled",
                severity=WARN,
                detail="detailedMetricsEnabled is false, so there are no per-route metrics.",
                fix="Set defaultRouteSettings.detailedMetricsEnabled to true.",
            )
        )

    findings += _access_log_findings(stage)
    findings += _tls_and_endpoint_findings(api, stage, index)
    findings += _stale_deployment_finding(stage, options)
    return findings


def audit_http_stage(api: dict, stage: dict, index: Index, options: Options) -> StageReport:
    findings = _http_stage_findings(api, stage, index, options)
    findings += _http_route_findings(api)
    return StageReport(
        api_id=api.get("apiId") or api.get("id", ""),
        api_name=api.get("name", ""),
        protocol=(api.get("protocolType") or "HTTP").upper(),
        stage=stage.get("stageName", ""),
        findings=findings,
    )


# --------------------------------------------------------------------------- #
# account-wide rules
# --------------------------------------------------------------------------- #


def audit_api_keys(payload: dict) -> list:
    findings = []
    for key in payload.get("api_keys") or []:
        if not (key.get("usagePlans") or []):
            name = key.get("name") or key.get("id", "?")
            findings.append(
                Finding(
                    code="api-key-no-usage-plan",
                    severity=WARN,
                    target=name,
                    detail=f"API key {name} belongs to no usage plan, so it grants access with no quota or throttle.",
                    fix=f"Attach {name} to a usage plan with create-usage-plan-key, or delete the key.",
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #


def audit(payload: dict, options: Options = None, api_filter: str = None) -> Report:
    """Run every rule over the payload and return the full report."""
    payload = validate_payload(payload)
    options = options or Options()
    index = Index(payload)
    stages = []

    def wanted(api: dict) -> bool:
        if not api_filter:
            return True
        return api_filter in (api.get("name"), api.get("id"), api.get("apiId"))

    for api in payload.get("rest_apis") or []:
        if not wanted(api):
            continue
        for stage in api.get("stages") or []:
            stages.append(audit_rest_stage(api, stage, index, options))

    for api in payload.get("http_apis") or []:
        if not wanted(api):
            continue
        for stage in api.get("stages") or []:
            stages.append(audit_http_stage(api, stage, index, options))

    account_findings = [] if api_filter else audit_api_keys(payload)
    return Report(
        region=payload.get("region", ""),
        stages=stages,
        account_findings=account_findings,
    )
