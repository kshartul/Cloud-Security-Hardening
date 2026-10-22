#!/usr/bin/env python3
"""
Upload every scanner report in a directory to DefectDojo using reimport-scan
(auto-creates product/engagement, closes findings that are no longer reported =
verify-by-rescan).

Environment:
  DD_URL      e.g. https://defectdojo.security.internal
  DD_API_KEY  API v2 token (from ADO Key Vault-linked variable group)

Usage:
  push_to_defectdojo.py --reports ./security --product omni-dw-api-services \
      --engagement CI-main --build-id 1234 --commit abc123 --branch main
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

import requests

# file name -> DefectDojo scan_type
SCAN_TYPES = {
    "gitleaks.sarif": "SARIF",
    "semgrep.sarif": "SARIF",
    "bandit.sarif": "SARIF",
    "trivy.sarif": "SARIF",
    "checkov.sarif": "SARIF",
    "cfn-nag.sarif": "SARIF",
    "zap-report.xml": "ZAP Scan",
    "nuclei.jsonl": "Nuclei Scan",
    "sbom.cdx.json": "CycloneDX Scan",
    "iam-policy-findings.json": "Generic Findings Import",
    "spectral.sarif": "SARIF",
}

# test_title lets DefectDojo keep separate tests per tool within one engagement
TEST_TITLES = {k: k.split(".")[0] for k in SCAN_TYPES}


def reimport(session: requests.Session, base: str, path: pathlib.Path, args) -> None:
    data = {
        "product_name": args.product,
        "product_type_name": args.product_type,
        "engagement_name": args.engagement,
        "test_title": TEST_TITLES[path.name],
        "scan_type": SCAN_TYPES[path.name],
        "auto_create_context": "true",
        "deduplication_on_engagement": "true",
        "close_old_findings": "true",          # verify-by-rescan
        "close_old_findings_product_scope": "false",
        "minimum_severity": "Low",
        "active": "true",
        "verified": "false",
        "build_id": args.build_id,
        "commit_hash": args.commit,
        "branch_tag": args.branch,
        "source_code_management_uri": args.repo_uri or "",
        "group_by": "component_name" if path.name == "trivy.sarif" else "",
    }
    data = {k: v for k, v in data.items() if v not in ("", None)}
    with path.open("rb") as fh:
        r = session.post(f"{base}/api/v2/reimport-scan/", data=data,
                         files={"file": (path.name, fh)}, timeout=120)
    if r.status_code >= 300:
        raise RuntimeError(f"{path.name}: HTTP {r.status_code} {r.text[:300]}")
    body = r.json()
    stats = body.get("statistics", {}).get("after", {}).get("total", {})
    print(f"✓ {path.name:28s} test={body.get('test')} active={stats.get('active', '?')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True)
    ap.add_argument("--product", required=True)
    ap.add_argument("--product-type", default="Omni Platform")
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--build-id", default="")
    ap.add_argument("--commit", default="")
    ap.add_argument("--branch", default="")
    ap.add_argument("--repo-uri", default=os.getenv("BUILD_REPOSITORY_URI", ""))
    args = ap.parse_args()

    base = os.environ.get("DD_URL", "").rstrip("/")
    key = os.environ.get("DD_API_KEY", "")
    if not base or not key:
        print("DD_URL / DD_API_KEY not set — skipping upload")
        return 0

    s = requests.Session()
    s.headers["Authorization"] = f"Token {key}"
    failures = 0
    for path in sorted(pathlib.Path(args.reports).glob("*")):
        if path.name not in SCAN_TYPES or path.stat().st_size == 0:
            continue
        try:
            reimport(s, base, path, args)
        except Exception as exc:  # keep uploading the rest
            failures += 1
            print(f"✗ {exc}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
