#!/usr/bin/env bash
# Vendor AWS sample conformance-pack templates at a pinned commit so plans are reproducible.
# Template file names change over time — the script fails if any name is missing so you can
# update locals.conformance_packs in modules/security-baseline/config.tf.
set -euo pipefail

REPO="https://raw.githubusercontent.com/awslabs/aws-config-rules"
COMMIT="${COMMIT:-master}"   # pin to a commit SHA after first review
DEST="$(dirname "$0")/../conformance-packs"
mkdir -p "$DEST"

PACKS=(
  "Operational-Best-Practices-for-CIS-AWS-v3.0.yaml"
  "Operational-Best-Practices-for-Serverless.yaml"
  "Operational-Best-Practices-for-Amazon-Redshift.yaml"
  "Operational-Best-Practices-for-Amazon-S3.yaml"
  "Operational-Best-Practices-for-KMS.yaml"
  "Operational-Best-Practices-for-API-Gateway.yaml"
)

missing=0
for p in "${PACKS[@]}"; do
  if curl -fsSL "$REPO/$COMMIT/aws-config-conformance-packs/$p" -o "$DEST/$p"; then
    echo "ok   $p"
  else
    echo "MISS $p  — check the current name in awslabs/aws-config-rules/aws-config-conformance-packs" >&2
    missing=1
  fi
done
exit $missing
