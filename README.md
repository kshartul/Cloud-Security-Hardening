# aws-security-hardening

Implementation repository for the **AWS Security Hardening Plan** (Oct 22, 2026 · Shartul Kumar).
It turns the 24-week, 7-phase plan into deployable code: Terraform for every AWS security
control, reusable Azure DevOps security templates, scanner configuration, Lambda/Step Functions
for vulnerability routing and auto-remediation, and the runbooks/standards that auditors ask for.

Target estate: Lambda, API Gateway, Serverless Framework v3, Terraform, DMS, Redshift,
deployed through Azure DevOps. Home region `ap-south-1`.

## Start here

| Read | Why |
|---|---|
| [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) | The detailed, week-by-week execution plan: work packages, owners, dependencies, acceptance tests, rollback, risks |
| [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md) | Target-state architecture, account model, data flows (with diagrams) |
| [`docs/architecture/aws-security-architecture.svg`](docs/architecture/aws-security-architecture.svg) | One-page architecture diagram |
| [`docs/DEPLOYMENT_ORDER.md`](docs/DEPLOYMENT_ORDER.md) | Exact apply order, which account/role runs each stack |
| [`docs/standards/`](docs/standards/) | Vulnerability Management Standard, Secure SDLC Standard, suppression register, Checkov baseline |
| [`docs/runbooks/`](docs/runbooks/) | Control Tower enrolment, break-glass, 4 IR runbooks |

## Repository layout

```
aws-security-hardening/
├── docs/
│   ├── IMPLEMENTATION_PLAN.md          # master plan (WBS, timeline, RACI, KPIs, risks)
│   ├── DEPLOYMENT_ORDER.md             # stack-by-stack apply sequence
│   ├── architecture/                   # ARCHITECTURE.md + SVG + Mermaid
│   ├── standards/                      # vulnerability mgmt standard, secure SDLC standard, tagging standard
│   └── runbooks/                       # IR runbooks per finding type
├── phase-0-foundation/                 # Organizations, Control Tower, SCPs, Identity Center, org CloudTrail, KMS, account defaults
├── phase-1-detection/                  # Security Hub (central config), GuardDuty, Config, Inspector, Macie, Detective, Access Analyzer, FMS
├── phase-2-secure-sdlc/                # ADO security-scan template, Semgrep/Checkov/Gitleaks/Trivy/Bandit configs, pre-commit, threat models
├── phase-3-dast-api/                   # WAF module, hardened serverless.yml, Spectral/ZAP/Nuclei, API inventory
├── phase-4-vuln-mgmt/                  # EventBridge → findings-router Lambda (EPSS/KEV → Jira), exception expiry, DefectDojo
├── phase-5-pentest/                    # RoE + scope templates, time-boxed tester role, self-assessment (Prowler/ScoutSuite/Stratus)
├── phase-6-integration/                # Security Lake, SIEM detections, Chatbot, SOAR auto-remediation Lambdas + Step Functions
├── pipelines/                          # Azure DevOps pipelines that deploy THIS repo (plan → scan → approve → apply)
└── Makefile                            # local helpers: fmt, validate, scan, test
```

Every phase folder has its own `README.md` with: objective, prerequisites, what to deploy,
how to verify, exit criteria, and rollback.

## Conventions

* **Terraform** ≥ 1.10, AWS provider `~> 5.70`. State in S3 with native lockfile locking (`use_lockfile`) in the Security Tooling account,
  one state key per stack (`<phase>/<stack>/terraform.tfstate`).
* **Cross-account access**: pipelines assume `arn:aws:iam::<acct>:role/SecurityPipelineDeploy`
  via ADO OIDC workload identity federation — no long-lived keys.
* **Tags (mandatory)**: `owner`, `team`, `service`, `environment`, `data-classification`, `exposure`
  (`internet|internal`), `criticality` (`tier-1|tier-2|tier-3`). Tags drive Jira routing and risk scoring.
* **Placeholders**: values like `111111111111`, `o-xxxxxxxxxx`, `r-xxxx` must be replaced in `*.tfvars`.

## Quick start (local)

```bash
make fmt validate        # terraform fmt/validate all stacks (no AWS calls)
make scan                # checkov + gitleaks + semgrep on this repo
make test                # pytest for Lambda code
```

## What has been verified in this repo

* All 34 Terraform files parse and are `fmt`-clean; Checkov: 464 checks pass, remaining items accepted in `docs/standards/checkov-baseline.md`.
* `terraform validate` / `plan` need provider downloads and real account IDs — run `make validate` and the pipeline in your environment.
* 26 unit tests pass (BOLA/BFLA/SSRF helpers, risk scoring + SLA, playbook decision logic).
* Custom Semgrep rules compile and fire on a vulnerable sample (SQLi, Data API, pickle, yaml, SSRF, public ACL, BOLA hint, error leakage, hard-coded ARN).
* All YAML/JSON (pipelines, Spectral, Step Functions ASL) parse.

## Owner

Cloud/DevOps Platform — Shartul Kumar (github: kshartul)
