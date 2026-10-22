"""Offline unit tests for playbook decision logic (no AWS calls)."""
import pathlib
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "lambda" / "remediation"))

with mock.patch("boto3.client"):
    import common  # noqa: E402
    import iam_key_deactivate  # noqa: E402
    import sg_open_ingress  # noqa: E402


@pytest.mark.parametrize("rule,expected", [
    ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}, True),
    ({"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389}, True),
    ({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535}, True),
    ({"IpProtocol": "-1"}, True),
    ({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}, False),
])
def test_admin_port_detection(rule, expected):
    assert sg_open_ingress._covers_admin(rule) is expected


def test_first_finding_accepts_eventbridge_and_sfn_shapes():
    f = {"Id": "x"}
    assert common.first_finding({"detail": {"findings": [f]}}) == f
    assert common.first_finding({"detail": {"id": "gd-1"}}) == {"id": "gd-1"}


def test_key_extraction_guardduty_shape():
    f = {"resource": {"accessKeyDetails": {"accessKeyId": "AKIAEXAMPLE", "userName": "svc"}}}
    assert iam_key_deactivate._key_and_user(f) == ("AKIAEXAMPLE", "svc")


def test_key_extraction_asff_shape():
    f = {"Resources": [{"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey/AKIAEXAMPLE2",
                        "Details": {"AwsIamAccessKey": {"PrincipalName": "ci-user"}}}]}
    assert iam_key_deactivate._key_and_user(f) == ("AKIAEXAMPLE2", "ci-user")


def test_temporary_credentials_go_to_manual(monkeypatch):
    sent = {}
    monkeypatch.setattr(iam_key_deactivate, "notify", lambda s, m: sent.update(m))
    out = iam_key_deactivate.handler(
        {"detail": {"accountId": "1", "resource": {"accessKeyDetails": {"accessKeyId": "ASIATEMP", "userName": "r"}}}}, None)
    assert out == {"action": "manual"}


def test_prod_sg_requires_approval(monkeypatch):
    monkeypatch.setattr(sg_open_ingress, "is_prod", lambda a: True)
    ev = {"detail": {"findings": [{"AwsAccountId": "999", "Resources": [{"Id": "arn:aws:ec2:ap-south-1:999:security-group/sg-1"}]}]}}
    assert sg_open_ingress.handler(ev, None) == {"action": "needs-approval", "sg": "sg-1"}
