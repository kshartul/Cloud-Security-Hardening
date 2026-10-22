"""Shared helpers for SOAR remediation Lambdas (Security Tooling account)."""
from __future__ import annotations

import json
import logging
import os
from functools import lru_cache

import boto3

log = logging.getLogger()
log.setLevel(os.getenv("LOG_LEVEL", "INFO"))

REMEDIATION_ROLE = os.getenv("REMEDIATION_ROLE", "SecurityAutoRemediation")
NOTIFY_TOPIC_ARN = os.getenv("NOTIFY_TOPIC_ARN", "")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
PROD_ACCOUNTS = set(filter(None, os.getenv("PROD_ACCOUNT_IDS", "").split(",")))

_sts = boto3.client("sts")
_sns = boto3.client("sns")
_sh = boto3.client("securityhub")


@lru_cache(maxsize=128)
def session_for(account_id: str, region: str) -> boto3.Session:
    c = _sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{REMEDIATION_ROLE}",
        RoleSessionName="soar-remediation",
        DurationSeconds=900,
    )["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                         aws_session_token=c["SessionToken"], region_name=region)


def first_finding(event: dict) -> dict:
    """Accepts EventBridge Security Hub events, GuardDuty events, or Step Functions input."""
    detail = event.get("detail", event)
    if "findings" in detail:
        return detail["findings"][0]
    return detail


def is_prod(account_id: str) -> bool:
    return account_id in PROD_ACCOUNTS


def notify(subject: str, message: dict) -> None:
    log.info("%s %s", subject, json.dumps(message, default=str))
    if NOTIFY_TOPIC_ARN:
        _sns.publish(TopicArn=NOTIFY_TOPIC_ARN, Subject=subject[:100], Message=json.dumps(message, indent=2, default=str))


def annotate_finding(finding: dict, text: str, resolved: bool = False) -> None:
    if not finding.get("ProductArn") or DRY_RUN:
        return
    kwargs = {
        "FindingIdentifiers": [{"Id": finding["Id"], "ProductArn": finding["ProductArn"]}],
        "Note": {"Text": text[:512], "UpdatedBy": "soar"},
    }
    if resolved:
        kwargs["Workflow"] = {"Status": "RESOLVED"}
    _sh.batch_update_findings(**kwargs)
