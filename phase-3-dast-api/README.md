# Phase 3 — DAST and API security (weeks 8–14)

**Objective:** every API Gateway route authenticated, validated, throttled and behind WAF (OWASP API Top 10, 2023);
DAST on every staging deploy (passive) and nightly (active, authenticated).

## Contents

| Path | What it is |
|---|---|
| `terraform/modules/waf-api` | WAFv2 ACL: IP reputation, anonymous IP, known-bad inputs, common, SQLi (COUNT→BLOCK promotion), body-size limit, rate limit 2000/5 min, pen-test label, logging with redaction |
| `terraform/stacks/fms-waf` | Firewall Manager policies pushing the ACL to every API GW stage / ALB / CloudFront in the target OUs |
| `serverless/serverless.hardened.yml` | Reference service: Cognito authorizer + scopes, validators, JSON access logs, X-Ray, usage plan throttling, reserved concurrency, per-function IAM, generic gateway responses, KMS, VPC |
| `serverless/private-api.snippet.yml` | Admin routes on a private API restricted to a VPC endpoint (IAM auth) |
| `serverless/src/authz.py` + `tests/test_authz.py` | BOLA/BFLA helpers + SSRF guard; tests every service copies |
| `serverless/schemas/order-query.json` | Request model example (bounded, `additionalProperties: false`) |
| `pipelines/templates/api-lint.yml` | Spectral OWASP + house rules gate |
| `pipelines/templates/dast-zap.yml` | ZAP baseline (per deploy) / API scan (nightly, Cognito token) |
| `pipelines/dast-nightly.yml`, `pipelines/nuclei-weekly.yml` | Schedules |
| `configs/zap-rules.conf`, `configs/.spectral.yaml` | Tuned rule sets |
| `scripts/export_api_inventory.py` | Org-wide API/route inventory, OpenAPI export, coverage KPI, Nuclei targets |
| `scripts/get_cognito_token.py` | Short-lived DAST token from Secrets Manager config |

## OWASP API Top 10 (2023) → control map

| Risk | Control | Where |
|---|---|---|
| API1 BOLA | `assert_owner` on every object fetch + tests; Semgrep `kf-missing-owner-check`; ZAP + pen test | `serverless/src/authz.py` |
| API2 Broken authentication | Cognito/JWT authorizer, short TTL, no API keys as auth (Spectral `kf-no-api-key-auth`) | `serverless.hardened.yml`, `.spectral.yaml` |
| API3 Property-level authz | Request models with `additionalProperties: false`, response allow-lists | `schemas/` |
| API4 Resource consumption | Usage plan throttle/quota, WAF rate rule, reserved concurrency, `maxItems`/`maximum` | WAF module, serverless |
| API5 Function-level authz | Scopes per route; admin on private API | `private-api.snippet.yml` |
| API6 Sensitive business flows | Rate rule + Bot Control on public sites; per-flow quotas | WAF module (extend) |
| API7 SSRF | `validate_outbound_url`, Network Firewall egress allow-list | `authz.py`, ARCHITECTURE §5 |
| API8 Misconfiguration | TLS 1.2 domain, restricted CORS, generic gateway responses, no execution logging of bodies | serverless |
| API9 Inventory | `export_api_inventory.py`, `x-owner` / `x-data-classification` in spec, Config rule WAF-on-stage | scripts, Spectral |
| API10 Unsafe consumption | Validate 3rd-party responses, timeouts, secrets in Secrets Manager | code review checklist |

## WAF promotion (COUNT → BLOCK)

1. Deploy `fms-waf` with `remediation_enabled = false` (audit) → review non-compliant stages in FMS.
2. Set `remediation_enabled = true` for Dev OU, all groups in COUNT.
3. After 7 days, run the FP query below per rule group; promote groups with FP rate < 0.1% by removing them from `count_rule_groups`.
4. Repeat for Stage, then Prod (CAB).

Athena (WAF logs in Log Archive, table `waf_logs`):

```sql
SELECT rg.rulegroupid,
       r.ruleid,
       count(*)                                         AS would_block,
       count(DISTINCT httprequest.clientip)              AS distinct_ips,
       approx_percentile(cardinality(httprequest.headers), 0.5) AS p50_headers
FROM waf_logs
CROSS JOIN UNNEST(rulegrouplist) AS t(rg)
CROSS JOIN UNNEST(rg.nonterminatingmatchingrules) AS u(r)
WHERE from_unixtime(timestamp/1000) > now() - interval '7' day
  AND r.action = 'COUNT'
GROUP BY 1, 2
ORDER BY would_block DESC;
```

Cross-check top rules against API GW access logs (status 2xx for the same `requestId`) — legitimate traffic
that would be blocked becomes a scoped-down exclusion in the ACL, with a ticket.

## Acceptance tests

```bash
# No authorizer anywhere
python scripts/export_api_inventory.py --coverage          # exit 0 required
# Unauthenticated call rejected
curl -s -o /dev/null -w '%{http_code}\n' https://api-stage.example.com/dw/orders/123     # 401
# Rate limit
hey -n 3000 -c 50 https://api-stage.example.com/dw/health | grep '\[429\]'
# SQLi blocked at the edge (after promotion)
curl -s -o /dev/null -w '%{http_code}\n' "https://api-stage.example.com/dw/orders?id=1%27%20OR%201=1--"  # 403
# Unknown property rejected by validator
curl -s -H "Authorization: Bearer $T" -d '{"fromDate":"2026-01-01","toDate":"2026-01-02","isAdmin":true}' \
  https://api-stage.example.com/dw/orders                   # 400
```

## Exit criteria

- [ ] 100% routes behind an authorizer and WAF (inventory coverage = 100%)
- [ ] OpenAPI lint gate enforced
- [ ] Nightly DAST running; zero untriaged HIGH in DefectDojo
- [ ] WAF in BLOCK for all groups in Prod

## Rollback

Add the group back to `count_rule_groups` (or `remediation_enabled = false`) and apply.
