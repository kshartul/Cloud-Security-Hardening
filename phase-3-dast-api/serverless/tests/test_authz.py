"""Unit tests that every handler test-suite should copy: BOLA, BFLA, SSRF."""
import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from authz import Forbidden, Principal, assert_owner, require_scope, validate_outbound_url  # noqa: E402


def event(sub="u-1", tenant="t-1", scope="omni-api/orders.read", groups=""):
    return {"requestContext": {"authorizer": {"claims": {
        "sub": sub, "custom:tenant_id": tenant, "scope": scope, "cognito:groups": groups}}}}


def test_owner_can_read_own_object():
    p = Principal.from_event(event())
    assert assert_owner({"tenant_id": "t-1", "owner_sub": "u-1"}, p)


def test_bola_other_user_same_tenant_denied():
    p = Principal.from_event(event(sub="u-2"))
    with pytest.raises(Forbidden):
        assert_owner({"tenant_id": "t-1", "owner_sub": "u-1"}, p)


def test_bola_other_tenant_denied_even_for_admin():
    p = Principal.from_event(event(tenant="t-2", groups="tenant-admin"))
    with pytest.raises(Forbidden):
        assert_owner({"tenant_id": "t-1", "owner_sub": "u-1"}, p)


def test_tenant_admin_reads_tenant_object():
    p = Principal.from_event(event(sub="admin", groups="tenant-admin"))
    assert assert_owner({"tenant_id": "t-1", "owner_sub": "u-1"}, p)


def test_missing_object_is_forbidden_not_error():
    with pytest.raises(Forbidden):
        assert_owner(None, Principal.from_event(event()))


def test_unauthenticated_event_rejected():
    with pytest.raises(Forbidden):
        Principal.from_event({"requestContext": {}})


def test_bfla_missing_scope():
    p = Principal.from_event(event(scope="omni-api/orders.read"))
    with pytest.raises(Forbidden):
        require_scope(p, "omni-api/orders.write")


@pytest.mark.parametrize("url", [
    "http://api.partner.example.com/x",          # not https
    "https://169.254.169.254/latest/meta-data",  # IMDS
    "https://evil.example.net/",                 # not allow-listed
])
def test_ssrf_blocked(url):
    with pytest.raises(Forbidden):
        validate_outbound_url(url)
