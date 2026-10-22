# Jira project SECVULN — configuration (P4.4)

## Issue types

| Type | Use |
|---|---|
| Vulnerability | One per finding (or grouped package upgrade) — created by findings-router / DefectDojo |
| Exception | Risk acceptance request (links to Vulnerability) |
| Pentest Finding | Imported from vendor report via DefectDojo |

## Workflow

`New → Triaged → In Progress → Fixed (awaiting rescan) → Verified → Closed`
plus `→ Risk Accepted` (only via approved Exception) and `→ False Positive` (AppSec approval).
`Verified` is set **only** by automation (findings-router resolved event or DefectDojo close) — remove the
transition from human screens.

## Custom fields (map ids into the router via `jira_custom_fields`)

| Field | Type | Env var | Example |
|---|---|---|---|
| Finding ID | Short text | `JF_FINDING_ID` | arn:aws:securityhub:...:finding/... |
| CVE | Short text | `JF_CVE` | CVE-2026-12345 |
| EPSS | Number | `JF_EPSS` | 0.4312 |
| Risk score | Number | `JF_RISK` | 18.7 |
| Team | Select / short text | `JF_TEAM` | data-platform |
| Asset | Short text | — | arn:aws:lambda:...:function:getOrder |
| SLA due | Due date (built-in) | — | 2026-10-29 |

## Automation (Jira side)

* SLA breach rule: `duedate < now() AND status not in (Verified, Closed, "Risk Accepted")` → set label `sla-breach`, notify EM.
* 75% escalation (High): scheduled rule comparing created/duedate.
* Webhook on `Risk Accepted` → (optional) Lambda that writes the exception fields onto the Security Hub finding.

## Dashboards

* Team: open by priority, overdue, created vs resolved (30 d), MTTR.
* Leadership: SLA compliance %, aging buckets, top 10 overdue, open exceptions.
