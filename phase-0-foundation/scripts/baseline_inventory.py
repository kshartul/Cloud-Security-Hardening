#!/usr/bin/env python3
"""
P0.1 — Baseline inventory across the organization.

Assumes a read-only role (default: SecurityReadOnly via OrganizationAccountAccessRole-style
cross-account role) in every active account and reports:
  * IAM users with console passwords, access keys, key age, MFA status
  * Public S3 buckets (policy status), public EBS snapshots, public AMIs
  * Lambda function URLs with AuthType NONE
  * Regions with any EC2/Lambda footprint (to drive the region-deny SCP)

Usage:
  python baseline_inventory.py --role-name ProwlerAudit --regions ap-south-1 us-east-1 \
      --out inventory.json
  python baseline_inventory.py --check-console-users      # exit 1 if any non-break-glass console user
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.exceptions import ClientError

BREAK_GLASS_PREFIX = "breakglass-"


def assume(account_id: str, role_name: str) -> boto3.Session:
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
        RoleSessionName="baseline-inventory",
        DurationSeconds=3600,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def iam_users(sess: boto3.Session) -> list[dict]:
    iam = sess.client("iam")
    out = []
    now = dt.datetime.now(dt.timezone.utc)
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]
            console = True
            try:
                iam.get_login_profile(UserName=name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    console = False
                else:
                    raise
            keys = []
            for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])["AccessKeyLastUsed"]
                keys.append({
                    "id_suffix": k["AccessKeyId"][-4:],
                    "status": k["Status"],
                    "age_days": (now - k["CreateDate"]).days,
                    "last_used": str(last.get("LastUsedDate", "never")),
                    "last_service": last.get("ServiceName"),
                })
            mfa = bool(iam.list_mfa_devices(UserName=name)["MFADevices"])
            out.append({"user": name, "console": console, "mfa": mfa, "keys": keys,
                        "break_glass": name.startswith(BREAK_GLASS_PREFIX)})
    return out


def public_s3(sess: boto3.Session) -> list[str]:
    s3 = sess.client("s3")
    public = []
    for b in s3.list_buckets().get("Buckets", []):
        try:
            st = s3.get_bucket_policy_status(Bucket=b["Name"])["PolicyStatus"]
            if st.get("IsPublic"):
                public.append(b["Name"])
        except ClientError:
            continue  # no policy
    return public


def regional(sess: boto3.Session, region: str) -> dict:
    ec2 = sess.client("ec2", region_name=region)
    lam = sess.client("lambda", region_name=region)
    owner = sess.client("sts").get_caller_identity()["Account"]
    res: dict = {"region": region}
    snaps = ec2.describe_snapshots(OwnerIds=[owner], RestorableByUserIds=["all"]).get("Snapshots", [])
    res["public_snapshots"] = [s["SnapshotId"] for s in snaps]
    amis = ec2.describe_images(Owners=["self"], Filters=[{"Name": "is-public", "Values": ["true"]}]).get("Images", [])
    res["public_amis"] = [i["ImageId"] for i in amis]
    open_urls, fn_count = [], 0
    for page in lam.get_paginator("list_functions").paginate():
        for fn in page["Functions"]:
            fn_count += 1
            try:
                for cfg in lam.list_function_url_configs(FunctionName=fn["FunctionName"])["FunctionUrlConfigs"]:
                    if cfg["AuthType"] == "NONE":
                        open_urls.append(fn["FunctionName"])
            except ClientError:
                pass
    res["lambda_count"] = fn_count
    res["lambda_urls_no_auth"] = open_urls
    res["instances"] = sum(len(r["Instances"]) for r in ec2.describe_instances()["Reservations"])
    return res


def scan_account(acct: dict, role: str, regions: list[str]) -> dict:
    try:
        sess = assume(acct["Id"], role)
        return {
            "account_id": acct["Id"],
            "account_name": acct["Name"],
            "iam_users": iam_users(sess),
            "public_s3": public_s3(sess),
            "regions": [regional(sess, r) for r in regions],
        }
    except ClientError as e:
        return {"account_id": acct["Id"], "account_name": acct["Name"], "error": str(e)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role-name", default="ProwlerAudit")
    ap.add_argument("--regions", nargs="+", default=["ap-south-1", "us-east-1"])
    ap.add_argument("--out", default="inventory.json")
    ap.add_argument("--check-console-users", action="store_true")
    args = ap.parse_args()

    org = boto3.client("organizations")
    accounts = [a for p in org.get_paginator("list_accounts").paginate() for a in p["Accounts"] if a["Status"] == "ACTIVE"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda a: scan_account(a, args.role_name, args.regions), accounts))

    with open(args.out, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    console_users = [
        f'{r["account_name"]}:{u["user"]}'
        for r in results for u in r.get("iam_users", []) if u["console"] and not u["break_glass"]
    ]
    keys = sum(len(u["keys"]) for r in results for u in r.get("iam_users", []))
    print(f"accounts={len(results)} console_users={len(console_users)} access_keys={keys} -> {args.out}")

    if args.check_console_users and console_users:
        print("Console users outside break-glass:\n  " + "\n  ".join(console_users))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
