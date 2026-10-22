# Phase 2 — Secure SDLC: SAST, SCA, secrets, IaC (weeks 5–10)

**Objective:** every Azure DevOps pipeline runs a security stage that fails on **new** critical/high findings,
with results in SARIF and DefectDojo.

## Contents

| Path | What it is |
|---|---|
| `pipelines/templates/security-scan.yml` | Reusable stage: Gitleaks, Semgrep (diff-aware), Bandit, Trivy SCA, Syft SBOM, Checkov, cfn-nag, Access Analyzer policy checks, SARIF publish, DefectDojo upload |
| `pipelines/azure-pipelines.sample.yml` | How an app repo (omni-dw-api-services) consumes the templates incl. Phase 3 lint and DAST |
| `configs/.checkov.yaml` | Org default Checkov config (every skip has a ticket) |
| `configs/.gitleaks.toml` | Default rules + internal token formats + allow-list for placeholders |
| `configs/semgrep/internal-rules.yml` | Custom rules: SQL concat to Redshift, Data API without params, pickle/yaml, public ACL, SSRF taint, BOLA hint, error leakage |
| `configs/.pre-commit-config.yaml` | Developer-side hooks |
| `configs/sonar-project.properties` | Sonar template + quality gate definition |
| `scripts/push_to_defectdojo.py` | Reimport every report (auto-context, close old findings = verify-by-rescan) |
| `scripts/check_iam_policies.py` | Access Analyzer validate / check-access-not-granted / check-no-new-access on CFN + TF plan |
| `threat-models/` | STRIDE workshop format, prompt sheet, template, first model (omni-dw-api-services) |
| `appsec-review-checklist.md` | Champion review checklist for IAM/auth/crypto/new routes |

## Rollout (P2.8 → P2.11)

| Week | Action | `failOnFindings` |
|---|---|---|
| 7 | Add template to tier-1 repos (omni-dw-api-services, omni-wms, omni-dw-backend) | `false` |
| 7–8 | Baseline: all findings into DefectDojo; tune `.checkov.yaml`, `.semgrepignore`, `.trivyignore` with ticket refs | `false` |
| 9 | Enforce on tier-1 `main` + PRs; branch policy "Security stage must succeed" | `true` |
| 10 | Tier-2/3 repos | `false` → `true` after 2 weeks |

**Diff-aware gating.** Semgrep uses `--baseline-commit <merge-base>`; Gitleaks scans only the PR commit range;
Trivy/Checkov fail on current state but legacy debt is suppressed via ignore files that reference DefectDojo/Jira IDs
and expire (`exp:` field in `.trivyignore`). Net effect: existing debt is tracked under Phase 4 SLAs, new debt is blocked.

### `.trivyignore` with expiry

```
# CVE-2024-XXXXX — no fix in urllib3 1.26 line; upgrade in SECVULN-311
CVE-2024-XXXXX exp:2026-12-31
```

## Branch policies (P2.10)

* `main`: min 1 reviewer, build validation = app pipeline (includes Security stage), comment resolution required.
* Required reviewer group `security-champions` for paths: `serverless.yml`, `**/iam*.tf`, `**/kms*.tf`, `src/**/auth*`, `openapi/**`.
* Pipeline YAML changes (`azure-pipelines*.yml`) need platform team reviewer.

## Acceptance tests

| Test PR | Expected |
|---|---|
| Adds `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"` | fails at *Secrets* |
| Adds `cursor.execute(f"select * from t where id={event['id']}")` | fails at *SAST (Semgrep)* |
| Pins `requests==2.19.0` | fails at *SCA (Trivy)* |
| Adds `aws_s3_bucket` without encryption/versioning/BPA | fails at *IaC (Checkov)* |
| Adds `iamRoleStatements` with `Action: iam:PassRole, Resource: '*'` | fails at *IAM policy validation* |
| Touches only README while `main` has legacy medium findings | passes |

## Exit criteria

- [ ] 100% tier-1 repos run the stage on `main` with gates enforced
- [ ] Gitleaks full-history scan done; all real secrets rotated
- [ ] SBOM produced for every release, ingested by Dependency-Track
- [ ] Threat models for 3 tier-1 services with mitigation tickets

## Rollback

`failOnFindings: false` in the consuming pipeline (or a template tag that defaults to false) — one-line change.
