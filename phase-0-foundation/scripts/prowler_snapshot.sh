#!/usr/bin/env bash
# P0.1 — one-off posture snapshot of every account with Prowler v4 (before any change).
# Run from the Security Tooling account with a role that can assume ProwlerAudit everywhere.
set -euo pipefail

ROLE_NAME="${ROLE_NAME:-ProwlerAudit}"
OUT_DIR="${OUT_DIR:-./prowler-baseline-$(date +%Y%m%d)}"
REGIONS="${REGIONS:-ap-south-1 us-east-1}"
mkdir -p "$OUT_DIR"

pip install --quiet "prowler>=4,<6"

ACCOUNTS=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].Id' --output text)

for acct in $ACCOUNTS; do
  echo ">>> $acct"
  # shellcheck disable=SC2086
  prowler aws \
    --role "arn:aws:iam::${acct}:role/${ROLE_NAME}" \
    --filter-region $REGIONS \
    --compliance cis_3.0_aws aws_foundational_security_best_practices_aws \
    --output-formats csv html json-ocsf \
    --output-directory "$OUT_DIR/$acct" \
    --ignore-exit-code-3 || echo "WARN: prowler failed for $acct"
done

echo "Snapshot written to $OUT_DIR — attach the HTML summaries to Jira epic SEC-P0."
