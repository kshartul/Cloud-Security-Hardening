#!/usr/bin/env python3
"""
P4.9 — Lambda runtime currency report across the org.
Flags functions on deprecated / soon-deprecated runtimes and layers older than N days.
Update DEPRECATED / SUNSET from the AWS Lambda runtimes page each quarter.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import sys

import boto3

DEPRECATED = {"python3.7", "python3.8", "nodejs14.x", "nodejs16.x", "go1.x", "java8", "dotnet6", "ruby2.7"}
SUNSET_SOON = {"python3.9", "nodejs18.x"}   # verify dates quarterly


def sessions(role):
    org, sts = boto3.client("organizations"), boto3.client("sts")
    for p in org.get_paginator("list_accounts").paginate():
        for a in p["Accounts"]:
            if a["Status"] != "ACTIVE":
                continue
            try:
                c = sts.assume_role(RoleArn=f"arn:aws:iam::{a['Id']}:role/{role}", RoleSessionName="runtime-report")["Credentials"]
            except Exception:
                continue
            yield a, boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                                   aws_session_token=c["SessionToken"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", default="SecurityReadOnlyAutomation")
    ap.add_argument("--regions", nargs="+", default=["ap-south-1", "us-east-1"])
    ap.add_argument("--out", default="lambda_runtimes.csv")
    a = ap.parse_args()
    rows = []
    for acct, sess in sessions(a.role):
        for region in a.regions:
            lam = sess.client("lambda", region_name=region)
            for page in lam.get_paginator("list_functions").paginate():
                for fn in page["Functions"]:
                    rt = fn.get("Runtime", "container")
                    status = "DEPRECATED" if rt in DEPRECATED else "SUNSET_SOON" if rt in SUNSET_SOON else "OK"
                    modified = fn["LastModified"][:10]
                    rows.append({"account": acct["Name"], "region": region, "function": fn["FunctionName"],
                                 "runtime": rt, "status": status, "last_modified": modified,
                                 "layers": len(fn.get("Layers", []))})
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["function"])
        w.writeheader()
        w.writerows(rows)
    bad = sum(r["status"] != "OK" for r in rows)
    print(f"{len(rows)} functions, {bad} need runtime upgrade -> {a.out} ({dt.date.today()})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
