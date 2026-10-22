"""
Step Functions .waitForTaskToken step: store the task token and ask on-call to approve.

Approval UX: in Security Hub (Security Tooling account) select the finding →
Actions → "SOAR-Approve" or "SOAR-Reject". The custom action event invokes approval_handler.py,
which resumes the execution. Teams/Slack message via SNS → AWS Chatbot carries the instructions.
"""
from __future__ import annotations

import json
import os
import time

import boto3

ddb = boto3.resource("dynamodb").Table(os.environ["APPROVAL_TABLE"])
sns = boto3.client("sns")
TTL_HOURS = int(os.getenv("APPROVAL_TTL_HOURS", "4"))


def finding_key(event: dict) -> tuple[str, dict]:
    detail = event.get("detail", event)
    if "findings" in detail:                       # Security Hub ASFF
        f = detail["findings"][0]
        return f["Id"].rstrip("/").split("/")[-1], {"title": f.get("Title"), "account": f.get("AwsAccountId"),
                                                      "resource": f["Resources"][0]["Id"]}
    # GuardDuty native event
    return detail["id"], {"title": detail.get("title"), "account": detail.get("accountId"),
                          "resource": (detail.get("resource", {}).get("instanceDetails") or {}).get("instanceId")}


def handler(event, _ctx):
    key, summary = finding_key(event["event"])
    ddb.put_item(Item={
        "finding_key": key,
        "task_token": event["token"],
        "playbook": event["playbook"],
        "requested_at": int(time.time()),
        "expires_at": int(time.time()) + TTL_HOURS * 3600,
        "summary": json.dumps(summary, default=str),
    })
    msg = {
        "version": "1.0",
        "source": "custom",
        "content": {
            "textType": "client-markdown",
            "title": f":rotating_light: Approval needed — {summary.get('title')}",
            "description": (
                f"*Account:* {summary.get('account')}\n*Resource:* {summary.get('resource')}\n"
                f"*Playbook:* `{event['playbook'].split(':')[-1]}`\n\n"
                f"Approve: Security Hub → finding `{key}` → Actions → **SOAR-Approve** (or **SOAR-Reject**).\n"
                f"Times out in {TTL_HOURS}h → escalation."
            ),
        },
    }
    sns.publish(TopicArn=os.environ["APPROVAL_TOPIC_ARN"], Message=json.dumps(msg))
    return {"requested": key}
