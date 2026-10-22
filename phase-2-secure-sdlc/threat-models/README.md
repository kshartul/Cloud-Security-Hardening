# Threat models (P2.1)

One model per tier-1 service, stored **in the service repo** at `docs/threat-model/<service>.json`
(OWASP Threat Dragon v2 format) — this folder holds the template, the STRIDE prompt sheet and the
first three models produced in workshops.

| Service | Model | Status | Review cadence |
|---|---|---|---|
| omni-dw-api-services | `omni-dw-api-services.md` | Draft for workshop | Each major release / annually |
| omni-warehouse-management-systems (WMS Lambdas) | *workshop week 6* | Planned | Each major release |
| omni-datawarehouse-backend-services | *workshop week 6* | Planned | Each major release |

## Workshop format (90 min)

1. **Scope (10 min)** — data flow diagram: actors, trust boundaries, data stores, flows.
2. **STRIDE per element (50 min)** — use `stride-prompts.md`.
3. **Rate (15 min)** — likelihood × impact → High/Medium/Low.
4. **Mitigate (15 min)** — map each threat to an existing control (link to repo path) or create a Jira story in `SECVULN` with label `threat-model`.

## Definition of done

- DFD with trust boundaries saved in Threat Dragon JSON.
- Every High threat has a mitigation ticket or a documented existing control.
- Security champion and AppSec engineer listed as reviewers.
- Model linked from the service README.
