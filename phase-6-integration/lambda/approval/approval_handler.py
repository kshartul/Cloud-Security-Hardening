"""
Security Hub custom action "SOAR-Approve" / "SOAR-Reject" → resume the waiting Step Functions execution.
Records the approver (from the custom action event's CloudTrail-backed identity) on the finding.
"""
from __future__ import annotations

import json
import os

import boto3

ddb = boto3.resource("dynamodb").Table(os.environ["APPROVAL_TABLE"])
sfn = boto3.client("stepfunctions")
sh = boto3.client("securityhub")


def handler(event, _ctx):
    detail = event["detail"]
    action = detail.get("actionName", "")
    approve = action == "SOAR-Approve"
    results = []
    for f in detail.get("findings", []):
        key = f["Id"].rstrip("/").split("/")[-1]
        item = ddb.get_item(Key={"finding_key": key}).get("Item")
        if not item:
            results.append({"finding": key, "status": "no-pending-approval"})
            continue
        token = item["task_token"]
        if approve:
            sfn.send_task_success(taskToken=token, output=json.dumps({"approved": True, "action": action}))
        else:
            sfn.send_task_failure(taskToken=token, error="Rejected", cause=f"Rejected via {action}")
        ddb.delete_item(Key={"finding_key": key})
        sh.batch_update_findings(
            FindingIdentifiers=[{"Id": f["Id"], "ProductArn": f["ProductArn"]}],
            Note={"Text": f"SOAR {'approved' if approve else 'rejected'} via custom action", "UpdatedBy": "soar-approval"},
        )
        results.append({"finding": key, "status": "approved" if approve else "rejected"})
    return {"results": results}
