# aws-apigw-stage-audit

[![ci](https://github.com/moveeeax/aws-apigw-stage-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-apigw-stage-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audits API Gateway REST and HTTP API stages for the settings that only matter once traffic
arrives: access logging off, no throttling so one client can drain the account quota, detailed
metrics and X-Ray disabled, cache enabled without encryption, a stale TLS policy or an EDGE
endpoint on a custom domain, methods and routes with no authorizer, and API keys attached to no
usage plan. It prints the stage, the finding and the fix, and exits non-zero in CI.

A stage that returns `200` looks finished. The console never asks for a throttle, so there is
none, and the account-level 10000 rps is the only thing between one broken retry loop and every
other API in the account going down with it.

## How it works

API Gateway spreads its configuration across the API, the stage, the method and the custom
domain, and the dangerous defaults live in different places on purpose. The tool reads all of it
in one pass — `get_rest_apis` + `get_stages` + `get_resources(embed=["methods"])` for REST,
`get_apis` + `get_stages` + `get_routes` for HTTP and WebSocket, plus domain names, usage plans
and API keys — flattens it into one plain-dict payload, and runs the rules over that payload.

Because the payload is the only input to the rule engine, `--dump-json` and `--from-json` give
you a full offline replay, and the whole test suite runs on JSON fixtures with no AWS credentials
and no mocking library.

### Rules

| Code | Severity | What it means |
| --- | --- | --- |
| `no-throttling` | critical | No stage throttle and no usage plan: the stage inherits only the 10000 rps account quota. |
| `open-method` | critical | REST method with `authorizationType NONE` and `apiKeyRequired false`. |
| `http-route-no-authorizer` | critical | HTTP API route with no authorizer. |
| `cache-unencrypted` | critical | Caching on with `cacheDataEncrypted false`. |
| `mtls-bypassable` | critical | Domain requires mutual TLS while the default `execute-api` endpoint is still enabled. |
| `throttle-only-in-usage-plan` | warn | Only a usage plan limits the stage, so unkeyed traffic is unlimited. |
| `throttle-above-ceiling` | warn | Stage throttle above `--max-rate`. |
| `access-logging-disabled` | warn | No access log destination, so the first outage is debugged by guessing. |
| `access-log-format-incomplete` | warn | Log format missing `$context.requestId` or `$context.status`. |
| `execution-logging-off` | warn | `loggingLevel` is `OFF`. |
| `execution-logging-errors-only` | warn | `ERROR`-only logging on a production-named stage. |
| `detailed-metrics-disabled` | warn | No per-method or per-route CloudWatch metrics. |
| `xray-disabled` | warn | No tracing, so slow requests cannot be attributed. |
| `no-waf` | warn | No WAFv2 web ACL on the stage. |
| `stale-tls-policy` | warn | Custom domain below `TLS_1_2`. |
| `edge-endpoint` | warn | `EDGE` custom domain where `REGIONAL` was probably intended. |
| `client-cert-unset` | warn | API tagged `apigw:require-client-cert` with no `clientCertificateId`. |
| `canary-left-on` | warn | Canary still routing a non-zero traffic percentage. |
| `stale-deployment` | warn | Live deployment older than `--stale-days`. |
| `api-key-no-usage-plan` | warn | API key in no usage plan: access with no quota. |

`OPTIONS` methods and `OPTIONS` routes are skipped — CORS preflight is unauthenticated by design.

## Install

```sh
pip install git+https://github.com/moveeeax/aws-apigw-stage-audit
# reading a live account also needs boto3:
pip install "aws-apigw-stage-audit[aws] @ git+https://github.com/moveeeax/aws-apigw-stage-audit"
```

## Usage

```sh
aws-apigw-stage-audit --region eu-central-1
aws-apigw-stage-audit --api checkout-api --fail-on critical
aws-apigw-stage-audit --format json | jq '.stages[] | select(.severity=="critical")'
aws-apigw-stage-audit --from-json examples/prod.json --format markdown
```

A real run against the bundled example payload:

```console
$ aws-apigw-stage-audit --from-json examples/prod.json
API Gateway stage audit — region eu-central-1
=============================================

[CRIT] legacy-partner-api [REST] / prod
    CRIT  no-throttling
          No stage throttle and no usage plan, so this stage inherits only the account quota of 10000 rps shared with every other API in the account.
          fix: Set methodSettings['*/*'].throttlingRateLimit and throttlingBurstLimit via update-stage, sized to the backend rather than the account.
    CRIT  open-method (GET /partners/{id})
          GET /partners/{id} has authorizationType NONE and apiKeyRequired false, so it is open to the internet.
          fix: Attach an authorizer to GET /partners/{id}, or set apiKeyRequired and put the key behind a usage plan.
    CRIT  cache-unencrypted
          Response caching is on with cacheDataEncrypted false, so response bodies sit unencrypted at rest.
          fix: Set methodSettings['*/*'].cacheDataEncrypted to true, then flush the stage cache.
...
[account]
    WARN  api-key-no-usage-plan (orphan-key)
          API key orphan-key belongs to no usage plan, so it grants access with no quota or throttle.
          fix: Attach orphan-key to a usage plan with create-usage-plan-key, or delete the key.

3 stage(s), 7 critical, 14 warn, 0 clean
$ echo $?
1
```

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--region` | session region | Region to audit. |
| `--profile` | default | AWS profile. |
| `--api` | all | Audit one API, by name or id. Skips account-level findings. |
| `--max-rate` | `10000` | Flag a stage throttle above this rate, in rps. |
| `--stale-days` | `180` | Flag a live deployment older than this. |
| `--format` | `text` | `text`, `json` or `markdown`. |
| `--fail-on` | `critical` | `warn`, `critical` or `none`. |
| `--from-json` | — | Audit a saved payload, making no AWS calls. |
| `--dump-json` | — | Write the collected payload to a file. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Nothing at or above `--fail-on`. |
| `1` | At least one finding reached `--fail-on`. |
| `2` | Bad flags, an unreadable or malformed payload, or AWS could not be read. |

### In CI

```yaml
- name: Audit API Gateway stages
  run: aws-apigw-stage-audit --region eu-central-1 --fail-on critical --format markdown >> "$GITHUB_STEP_SUMMARY"
```

## IAM

Read-only, and all of it is covered by the AWS managed `AmazonAPIGatewayAdministrator` read
actions — or this minimal set:

```json
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Action": ["apigateway:GET"], "Resource": "arn:aws:apigateway:*::/*" }]
}
```

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest
```

`examples/prod.json` is the same payload the test suite uses, so a new rule gets a fixture and a
test before it gets a line in the table above.

## License

MIT — see [LICENSE](LICENSE).
