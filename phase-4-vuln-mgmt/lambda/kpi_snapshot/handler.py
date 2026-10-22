"""
kpi-snapshot — daily metrics for the program dashboard (Phase 4, P4.11).

Publishes to CloudWatch namespace "Security":
  FSBPScore (percent passed controls, FSBP standard), OpenCritical, OpenHigh,
  OverdueCritical, OverdueHigh (by UserDefinedFields.sla_due), plus per-team dimensions.
"""
from __future__ import annotations

import collections
import datetime as dt
import logging

import boto3

log = logging.getLogger()
log.setLevel("INFO")
sh = boto3.client("securityhub")
cw = boto3.client("cloudwatch")


def fsbp_score() -> float:
    passed = failed = 0
    paginator = sh.get_paginator("get_findings")
    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "ComplianceAssociatedStandardsId": [{"Value": "standards/aws-foundational-security-best-practices/v/1.0.0",
                                              "Comparison": "EQUALS"}],
        "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
    }
    seen = {}
    for page in paginator.paginate(Filters=filters, PaginationConfig={"PageSize": 100}):
        for f in page["Findings"]:
            cid = f.get("Compliance", {}).get("SecurityControlId")
            st = f.get("Compliance", {}).get("Status")
            if not cid or st not in ("PASSED", "FAILED"):
                continue
            # a control passes only if every resource passes
            seen[cid] = seen.get(cid, True) and st == "PASSED"
    passed = sum(1 for v in seen.values() if v)
    failed = len(seen) - passed
    return 100.0 * passed / (passed + failed) if (passed + failed) else 0.0


def open_findings():
    paginator = sh.get_paginator("get_findings")
    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}, {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
        "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}, {"Value": "HIGH", "Comparison": "EQUALS"}],
    }
    for page in paginator.paginate(Filters=filters, PaginationConfig={"PageSize": 100}):
        yield from page["Findings"]


def handler(_e, _c):
    today = dt.date.today().isoformat()
    counts = collections.Counter()
    for f in open_findings():
        sev = f["Severity"]["Label"]
        team = (f.get("UserDefinedFields") or {}).get("team", "unassigned")
        counts[("Open" + sev.title(), team)] += 1
        due = (f.get("UserDefinedFields") or {}).get("sla_due")
        if due and due < today:
            counts[("Overdue" + sev.title(), team)] += 1

    data = [{"MetricName": "FSBPScore", "Value": round(fsbp_score(), 2), "Unit": "Percent"}]
    totals = collections.Counter()
    for (metric, team), v in counts.items():
        totals[metric] += v
        data.append({"MetricName": metric, "Dimensions": [{"Name": "Team", "Value": team}], "Value": v, "Unit": "Count"})
    for metric, v in totals.items():
        data.append({"MetricName": metric, "Value": v, "Unit": "Count"})

    for i in range(0, len(data), 1000):
        cw.put_metric_data(Namespace="Security", MetricData=data[i:i + 1000])
    log.info({d["MetricName"]: d["Value"] for d in data if "Dimensions" not in d})
    return {"metrics": len(data)}
