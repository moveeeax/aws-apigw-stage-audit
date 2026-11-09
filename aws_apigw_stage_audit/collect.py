"""Read the live API Gateway configuration into the plain-dict payload.

`boto3` is imported inside the functions on purpose: the rule engine and the
whole test suite run on fixtures, so nothing here is needed to audit a saved
payload with `--from-json`.
"""

from __future__ import annotations

import datetime as dt


def _json_safe(value):
    """Datetimes out of botocore are not JSON-serialisable; everything else is."""
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.UTC).isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def _paginate(client, operation: str, result_key: str, **kwargs):
    """Yield every item of a paginated call, falling back to position paging."""
    if client.can_paginate(operation):
        for page in client.get_paginator(operation).paginate(**kwargs):
            yield from page.get(result_key, [])
        return
    response = getattr(client, operation)(**kwargs)
    yield from response.get(result_key, [])


def _collect_rest_methods(apigw, api_id: str) -> list:
    """Walk the resource tree once, with methods embedded, and flatten it."""
    methods = []
    for resource in _paginate(apigw, "get_resources", "items", restApiId=api_id, embed=["methods"]):
        path = resource.get("path", "/")
        for http_method, detail in (resource.get("resourceMethods") or {}).items():
            methods.append(
                {
                    "path": path,
                    "httpMethod": http_method,
                    "authorizationType": detail.get("authorizationType", "NONE"),
                    "authorizerId": detail.get("authorizerId", ""),
                    "apiKeyRequired": bool(detail.get("apiKeyRequired", False)),
                }
            )
    return methods


def _collect_rest(session, region: str) -> tuple:
    apigw = session.client("apigateway", region_name=region)
    apis = []
    for api in _paginate(apigw, "get_rest_apis", "items"):
        api_id = api["id"]
        stages = []
        for stage in apigw.get_stages(restApiId=api_id).get("item", []):
            stages.append(
                {
                    "stageName": stage.get("stageName"),
                    "deploymentId": stage.get("deploymentId"),
                    "createdDate": stage.get("createdDate"),
                    "lastUpdatedDate": stage.get("lastUpdatedDate"),
                    "accessLogSettings": stage.get("accessLogSettings") or {},
                    "methodSettings": stage.get("methodSettings") or {},
                    "cacheClusterEnabled": bool(stage.get("cacheClusterEnabled", False)),
                    "tracingEnabled": bool(stage.get("tracingEnabled", False)),
                    "webAclArn": stage.get("webAclArn", ""),
                    "clientCertificateId": stage.get("clientCertificateId", ""),
                    "canarySettings": stage.get("canarySettings") or {},
                }
            )
        apis.append(
            {
                "id": api_id,
                "name": api.get("name", ""),
                "endpointTypes": (api.get("endpointConfiguration") or {}).get("types", []),
                "disableExecuteApiEndpoint": bool(api.get("disableExecuteApiEndpoint", False)),
                "tags": api.get("tags") or {},
                "stages": stages,
                "methods": _collect_rest_methods(apigw, api_id),
            }
        )

    usage_plans = []
    for plan in _paginate(apigw, "get_usage_plans", "items"):
        usage_plans.append(
            {
                "id": plan.get("id"),
                "name": plan.get("name", ""),
                "throttle": plan.get("throttle") or {},
                "apiStages": plan.get("apiStages") or [],
            }
        )

    plan_keys = {}
    for plan in usage_plans:
        for item in _paginate(apigw, "get_usage_plan_keys", "items", usagePlanId=plan["id"]):
            plan_keys.setdefault(item.get("id"), []).append(plan["name"])

    api_keys = []
    for key in _paginate(apigw, "get_api_keys", "items"):
        api_keys.append(
            {
                "id": key.get("id"),
                "name": key.get("name", ""),
                "enabled": bool(key.get("enabled", False)),
                "usagePlans": plan_keys.get(key.get("id"), []),
            }
        )

    domains = []
    for domain in _paginate(apigw, "get_domain_names", "items"):
        name = domain["domainName"]
        mappings = [
            {"apiId": m.get("restApiId"), "stage": m.get("stage"), "basePath": m.get("basePath")}
            for m in _paginate(apigw, "get_base_path_mappings", "items", domainName=name)
        ]
        domains.append(
            {
                "domainName": name,
                "securityPolicy": domain.get("securityPolicy", ""),
                "endpointTypes": (domain.get("endpointConfiguration") or {}).get("types", []),
                "mutualTlsAuthentication": domain.get("mutualTlsAuthentication") or {},
                "mappings": mappings,
            }
        )

    return apis, usage_plans, api_keys, domains


def _collect_http(session, region: str) -> tuple:
    apiv2 = session.client("apigatewayv2", region_name=region)
    apis = []
    for api in _paginate(apiv2, "get_apis", "Items"):
        api_id = api["ApiId"]
        stages = []
        for stage in _paginate(apiv2, "get_stages", "Items", ApiId=api_id):
            stages.append(
                {
                    "stageName": stage.get("StageName"),
                    "deploymentId": stage.get("DeploymentId", ""),
                    "createdDate": stage.get("CreatedDate"),
                    "accessLogSettings": {
                        "destinationArn": (stage.get("AccessLogSettings") or {}).get("DestinationArn", ""),
                        "format": (stage.get("AccessLogSettings") or {}).get("Format", ""),
                    },
                    "defaultRouteSettings": {
                        "detailedMetricsEnabled": bool(
                            (stage.get("DefaultRouteSettings") or {}).get("DetailedMetricsEnabled", False)
                        ),
                        "throttlingRateLimit": (stage.get("DefaultRouteSettings") or {}).get("ThrottlingRateLimit"),
                        "throttlingBurstLimit": (stage.get("DefaultRouteSettings") or {}).get("ThrottlingBurstLimit"),
                    },
                    "autoDeploy": bool(stage.get("AutoDeploy", False)),
                }
            )
        routes = []
        for route in _paginate(apiv2, "get_routes", "Items", ApiId=api_id):
            routes.append(
                {
                    "routeKey": route.get("RouteKey", ""),
                    "authorizationType": route.get("AuthorizationType", "NONE"),
                    "authorizerId": route.get("AuthorizerId", ""),
                    "apiKeyRequired": bool(route.get("ApiKeyRequired", False)),
                }
            )
        apis.append(
            {
                "apiId": api_id,
                "name": api.get("Name", ""),
                "protocolType": api.get("ProtocolType", "HTTP"),
                "disableExecuteApiEndpoint": bool(api.get("DisableExecuteApiEndpoint", False)),
                "tags": api.get("Tags") or {},
                "stages": stages,
                "routes": routes,
            }
        )

    domains = []
    for domain in _paginate(apiv2, "get_domain_names", "Items"):
        name = domain["DomainName"]
        configs = domain.get("DomainNameConfigurations") or [{}]
        mappings = [
            {"apiId": m.get("ApiId"), "stage": m.get("Stage"), "basePath": m.get("ApiMappingKey")}
            for m in _paginate(apiv2, "get_api_mappings", "Items", DomainName=name)
        ]
        domains.append(
            {
                "domainName": name,
                "securityPolicy": configs[0].get("SecurityPolicy", ""),
                "endpointTypes": [configs[0].get("EndpointType", "REGIONAL")],
                "mutualTlsAuthentication": {
                    "truststoreUri": (domain.get("MutualTlsAuthentication") or {}).get("TruststoreUri", "")
                },
                "mappings": mappings,
            }
        )

    return apis, domains


def collect(region: str = None, profile: str = None) -> dict:
    """Build the audit payload from the live account."""
    import boto3  # noqa: PLC0415 - optional at runtime, never needed for --from-json

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    region = region or session.region_name
    if not region:
        raise RuntimeError("no region: pass --region or set AWS_DEFAULT_REGION")

    rest_apis, usage_plans, api_keys, rest_domains = _collect_rest(session, region)
    http_apis, http_domains = _collect_http(session, region)

    payload = {
        "region": region,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "rest_apis": rest_apis,
        "http_apis": http_apis,
        "domain_names": rest_domains + http_domains,
        "api_keys": api_keys,
        "usage_plans": usage_plans,
    }
    return _json_safe(payload)
