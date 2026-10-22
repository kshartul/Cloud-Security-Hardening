"""
exception-expiry — daily (EventBridge schedule) in Security Tooling (Phase 4, P4.7).

Risk exceptions are Security Hub findings with Workflow=SUPPRESSED and
UserDefinedFields: exception_expiry=YYYY-MM-DD, exception_ticket=SECVULN-123, approver=<name>.

* expired            -> Workflow=NEW (re-enters routing), note "exception expired", metric +1
* expiring in <=14 d -> SNS reminder to owners
* suppressed without expiry/ticket (and not an automation-rule suppression) -> NEW (invalid exception)
Publishes CloudWatch metrics Security/ExpiredExceptions and Security/OpenExceptions.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os

import boto3

log = logging.getLogger()
log.setLevel("INFO")

sh = boto3.client("securityhub")
cw = boto3.client("cloudwatch")
sns = boto3.client("sns")

REMIND_DAYS = int(os.getenv("REMIND_DAYS", "14"))
MAX_DAYS = int(os.getenv("MAX_EXCEPTION_DAYS", "90"))
AUTOMATION_AUTHORS = {"sechub-automation"}


def suppressed_findings():
    paginator = sh.get_paginator("get_findings")
    filters = {
        "WorkflowStatus": [{"Value": "SUPPRESSED", "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "SeverityLabel": [{"Value": s, "Comparison": "EQUALS"} for s in ("CRITICAL", "HIGH", "MEDIUM")],
    }
    for page in paginator.paginate(Filters=filters, PaginationConfig={"PageSize": 100}):
        yield from page["Findings"]


def reopen(f, reason):
    sh.batch_update_findings(
        FindingIdentifiers=[{"Id": f["Id"], "ProductArn": f["ProductArn"]}],
        Workflow={"Status": "NEW"},
        Note={"Text": reason[:512], "UpdatedBy": "exception-expiry"},
    )


def handler(_event, _context):
    today = dt.date.today()
    expired = expiring = invalid = open_ = 0
    reminders = []
    for f in suppressed_findings():
        udf = f.get("UserDefinedFields") or {}
        note_author = (f.get("Note") or {}).get("UpdatedBy", "")
        if note_author in AUTOMATION_AUTHORS:
            continue  # suppressed by documented automation rule, governed separately
        exp_s, ticket = udf.get("exception_expiry"), udf.get("exception_ticket")
        if not exp_s or not ticket:
            invalid += 1
            reopen(f, "Suppression without exception_expiry/exception_ticket — reopened per VM standard §6")
            continue
        exp = dt.date.fromisoformat(exp_s)
        created = dt.date.fromisoformat(udf.get("exception_approved", exp_s))
        if (exp - created).days > MAX_DAYS:
            invalid += 1
            reopen(f, f"Exception {ticket} exceeds {MAX_DAYS} days — reopened")
        elif exp < today:
            expired += 1
            reopen(f, f"Exception {ticket} expired {exp_s} — back in SLA routing")
        else:
            open_ += 1
            if (exp - today).days <= REMIND_DAYS:
                expiring += 1
                reminders.append({"ticket": ticket, "expires": exp_s, "title": f.get("Title"),
                                  "account": f.get("AwsAccountId"), "team": udf.get("team", "unassigned")})

    cw.put_metric_data(Namespace="Security", MetricData=[
        {"MetricName": "ExpiredExceptions", "Value": expired, "Unit": "Count"},
        {"MetricName": "InvalidExceptions", "Value": invalid, "Unit": "Count"},
        {"MetricName": "OpenExceptions", "Value": open_, "Unit": "Count"},
        {"MetricName": "ExpiringExceptions", "Value": expiring, "Unit": "Count"},
    ])
    if reminders and os.getenv("NOTIFY_TOPIC_ARN"):
        sns.publish(TopicArn=os.environ["NOTIFY_TOPIC_ARN"], Subject=f"{len(reminders)} security exceptions expiring",
                    Message=json.dumps(reminders, indent=2))
    result = {"expired": expired, "invalid": invalid, "open": open_, "expiring": expiring}
    log.info(json.dumps(result))
    return result
