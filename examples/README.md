# examples

`prod.json` is a payload in exactly the shape `--dump-json` writes and `--from-json` reads: one
REST API with a neglected `prod` stage and a usage-plan-only `sandbox` stage, one HTTP API with an
unthrottled `$default` stage and an open route, an `EDGE` custom domain on `TLS_1_0` with mutual
TLS that can be bypassed, and an API key in no usage plan.

```sh
aws-apigw-stage-audit --from-json examples/prod.json                     # exits 1
aws-apigw-stage-audit --from-json examples/prod.json --format markdown
aws-apigw-stage-audit --from-json examples/prod.json --fail-on none      # exits 0
```

To capture your own:

```sh
aws-apigw-stage-audit --region eu-central-1 --dump-json my-account.json --fail-on none
aws-apigw-stage-audit --from-json my-account.json --format json | jq '.summary'
```

The payload contains no credentials and no response bodies — only API Gateway configuration — but
it does name your APIs, stages, domains and API key names, so treat it like any other inventory
dump.
