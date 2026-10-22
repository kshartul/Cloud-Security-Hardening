"""
Object-level authorization helpers for Lambda handlers (OWASP API1 BOLA, API5 BFLA).

Usage in a handler:

    from authz import Principal, assert_owner, require_scope, Forbidden

    def get(event, context):
        principal = Principal.from_event(event)
        require_scope(principal, "omni-api/orders.read")
        order = repo.get_order(event["pathParameters"]["id"])
        assert_owner(order, principal)          # raises Forbidden -> 404 (do not leak existence)
        return ok(order)
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlparse


class Forbidden(Exception):
    """Raised when the principal may not access the resource. Map to 404 for object access."""


@dataclass(frozen=True)
class Principal:
    sub: str
    tenant_id: str | None
    scopes: frozenset[str] = field(default_factory=frozenset)
    groups: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_event(cls, event: dict[str, Any]) -> "Principal":
        claims = (event.get("requestContext", {}).get("authorizer", {}) or {}).get("claims") or {}
        if not claims.get("sub"):
            raise Forbidden("missing authenticated principal")
        scopes = frozenset((claims.get("scope") or "").split())
        groups_raw = claims.get("cognito:groups") or ""
        groups = frozenset(groups_raw.split(",") if isinstance(groups_raw, str) else groups_raw)
        return cls(
            sub=claims["sub"],
            tenant_id=claims.get("custom:tenant_id"),
            scopes=scopes,
            groups=groups,
        )


def require_scope(principal: Principal, *needed: str) -> None:
    missing = [s for s in needed if s not in principal.scopes]
    if missing:
        raise Forbidden(f"missing scope(s): {','.join(missing)}")


def assert_owner(resource: dict[str, Any] | None, principal: Principal,
                 owner_keys: Iterable[str] = ("owner_sub",), tenant_key: str = "tenant_id") -> dict[str, Any]:
    """Allow if the resource belongs to the caller's tenant AND (caller owns it OR caller is tenant admin)."""
    if resource is None:
        raise Forbidden("not found")
    if principal.tenant_id is None or resource.get(tenant_key) != principal.tenant_id:
        raise Forbidden("tenant mismatch")
    if "tenant-admin" in principal.groups:
        return resource
    if any(resource.get(k) == principal.sub for k in owner_keys):
        return resource
    raise Forbidden("not owner")


# ---------------- SSRF guard (API7) ----------------
ALLOWED_OUTBOUND_HOSTS = frozenset({"api.partner.example.com", "hooks.example.com"})


def validate_outbound_url(url: str, allowed_hosts: frozenset[str] = ALLOWED_OUTBOUND_HOSTS) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise Forbidden("only https outbound allowed")
    host = (parsed.hostname or "").lower()
    if host not in allowed_hosts:
        raise Forbidden(f"host not allow-listed: {host}")
    for info in socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise Forbidden("resolves to non-public address")
    return url
