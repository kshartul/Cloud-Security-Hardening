#!/usr/bin/env python3
"""
P1.6 — Macie org setup that Terraform does not cover:
  * enable automated sensitive data discovery for all members
  * create a one-time priority classification job for data lake / DW staging buckets
    (selected by tag), using managed + custom identifiers

Run in the Security Tooling (Macie delegated admin) account.
"""
from __future__ import annotations

import argparse
import datetime as dt

import boto3


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default="ap-south-1")
    ap.add_argument("--tag-key", default="data-classification")
    ap.add_argument("--tag-values", nargs="+", default=["confidential", "restricted"])
    ap.add_argument("--account-ids", nargs="+", required=True, help="Accounts that own DW/data-lake buckets")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    macie = boto3.client("macie2", region_name=a.region)

    if not a.dry_run:
        macie.update_automated_discovery_configuration(status="ENABLED", autoEnableOrganizationMembers="ALL")
    print("automated discovery: ENABLED (ALL members)")

    custom_ids = [c["id"] for c in macie.list_custom_data_identifiers()["items"] if c["name"].startswith("kf-")]

    job = {
        "clientToken": f"priority-dw-{dt.date.today():%Y%m%d}",
        "name": f"priority-dw-staging-{dt.date.today():%Y%m%d}",
        "jobType": "ONE_TIME",
        "managedDataIdentifierSelector": "RECOMMENDED",
        "customDataIdentifierIds": custom_ids,
        "samplingPercentage": 100,
        "s3JobDefinition": {
            "bucketCriteria": {
                "includes": {
                    "and": [
                        {"simpleCriterion": {"comparator": "EQ", "key": "ACCOUNT_ID", "values": a.account_ids}},
                        {"tagCriterion": {"comparator": "EQ",
                                          "tagValues": [{"key": a.tag_key, "value": v} for v in a.tag_values]}},
                    ]
                }
            }
        },
    }
    if a.dry_run:
        print(job)
        return
    res = macie.create_classification_job(**job)
    print(f"created job {res['jobId']}")


if __name__ == "__main__":
    main()
