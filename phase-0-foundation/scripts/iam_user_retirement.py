#!/usr/bin/env python3
"""
P0.10 — Retire IAM users and access keys in waves (extends the IAM username standardization tooling).

Wave model (per account):
  plan       -> CSV of every user/key with last-used service and a proposed action
  deactivate -> set keys Inactive + delete login profile (reversible), tag user retire-after=<date>
  reactivate -> undo a deactivation for a named user (rollback)
  delete     -> after the grace period: delete keys, detach policies, delete user

Break-glass users (prefix "breakglass-") are always skipped.

Usage:
  python iam_user_retirement.py plan --profile mgmt-readonly --account 123456789012 --out wave1.csv
  python iam_user_retirement.py deactivate --csv wave1.csv --grace-days 14 --dry-run
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import sys

import boto3
from botocore.exceptions import ClientError

SKIP_PREFIX = "breakglass-"


def session(profile: str | None, account: str | None, role: str) -> boto3.Session:
    base = boto3.Session(profile_name=profile) if profile else boto3.Session()
    if not account:
        return base
    c = base.client("sts").assume_role(
        RoleArn=f"arn:aws:iam::{account}:role/{role}", RoleSessionName="iam-retirement"
    )["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                         aws_session_token=c["SessionToken"])


def plan(iam, out: str) -> None:
    rows = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]
            if name.startswith(SKIP_PREFIX):
                continue
            keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"] or [None]
            for k in keys:
                last = {}
                if k:
                    last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])["AccessKeyLastUsed"]
                svc = last.get("ServiceName", "N/A")
                action = "migrate-to-oidc" if svc in ("sts", "lambda", "cloudformation", "s3") else "deactivate"
                rows.append({
                    "user": name,
                    "access_key_id": k["AccessKeyId"] if k else "",
                    "key_status": k["Status"] if k else "",
                    "last_used": str(last.get("LastUsedDate", "never")),
                    "last_service": svc,
                    "proposed_action": action,
                    "owner": "",  # fill in before deactivation
                })
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["user"])
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows -> {out}")


def deactivate(iam, csv_path: str, grace_days: int, dry_run: bool) -> None:
    retire_after = (dt.date.today() + dt.timedelta(days=grace_days)).isoformat()
    with open(csv_path) as fh:
        for row in csv.DictReader(fh):
            user = row["user"]
            if user.startswith(SKIP_PREFIX) or row.get("proposed_action") == "keep":
                continue
            print(f"{'[dry-run] ' if dry_run else ''}deactivate {user} key={row['access_key_id'][-4:] if row['access_key_id'] else '-'}")
            if dry_run:
                continue
            if row["access_key_id"]:
                iam.update_access_key(UserName=user, AccessKeyId=row["access_key_id"], Status="Inactive")
            try:
                iam.delete_login_profile(UserName=user)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise
            iam.tag_user(UserName=user, Tags=[{"Key": "retire-after", "Value": retire_after},
                                              {"Key": "retired-by", "Value": "security-program"}])


def reactivate(iam, user: str) -> None:
    for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
        iam.update_access_key(UserName=user, AccessKeyId=k["AccessKeyId"], Status="Active")
    iam.untag_user(UserName=user, TagKeys=["retire-after", "retired-by"])
    print(f"reactivated keys for {user} (console password must be reset manually)")


def delete(iam, dry_run: bool) -> None:
    today = dt.date.today().isoformat()
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            tags = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=u["UserName"])["Tags"]}
            if "retire-after" not in tags or tags["retire-after"] > today:
                continue
            name = u["UserName"]
            print(f"{'[dry-run] ' if dry_run else ''}delete {name}")
            if dry_run:
                continue
            for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=name, AccessKeyId=k["AccessKeyId"])
            for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]:
                iam.detach_user_policy(UserName=name, PolicyArn=p["PolicyArn"])
            for p in iam.list_user_policies(UserName=name)["PolicyNames"]:
                iam.delete_user_policy(UserName=name, PolicyName=p)
            for g in iam.list_groups_for_user(UserName=name)["Groups"]:
                iam.remove_user_from_group(UserName=name, GroupName=g["GroupName"])
            for m in iam.list_mfa_devices(UserName=name)["MFADevices"]:
                iam.deactivate_mfa_device(UserName=name, SerialNumber=m["SerialNumber"])
            iam.delete_user(UserName=name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["plan", "deactivate", "reactivate", "delete"])
    ap.add_argument("--profile")
    ap.add_argument("--account")
    ap.add_argument("--role", default="SecurityPipelineDeploy")
    ap.add_argument("--out", default="iam_plan.csv")
    ap.add_argument("--csv")
    ap.add_argument("--user")
    ap.add_argument("--grace-days", type=int, default=14)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    iam = session(a.profile, a.account, a.role).client("iam")
    if a.action == "plan":
        plan(iam, a.out)
    elif a.action == "deactivate":
        deactivate(iam, a.csv, a.grace_days, a.dry_run)
    elif a.action == "reactivate":
        reactivate(iam, a.user)
    else:
        delete(iam, a.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
