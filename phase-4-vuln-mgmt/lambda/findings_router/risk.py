"""
Risk scoring and SLA calculation — pure functions (unit-tested, no AWS calls).

risk = base(0-10) × KEV(1.5) × (1 + EPSS) × exposure(1.3) × data(1.2) × tier(1.2)
priority: >=15 P1 | >=10 P2 | >=5 P3 | else P4
SLA (days) per Vulnerability Management Standard §4, keyed by effective severity and exposure.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

SEVERITY_BASE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0, "INFORMATIONAL": 0.0}

# (internet_or_prod_data, internal)
SLA_DAYS = {
    "CRITICAL": (7, 15),
    "HIGH": (30, 45),
    "MEDIUM": (90, 120),
    "LOW": (180, 365),
}


@dataclass(frozen=True)
class Context:
    severity: str                 # Security Hub label
    cvss: float | None = None     # from Inspector/vendor if present
    epss: float = 0.0             # 0..1
    kev: bool = False             # CISA Known Exploited Vulnerabilities
    internet_facing: bool = False
    sensitive_data: bool = False  # data-classification in {confidential, restricted}
    tier1: bool = False
    prod: bool = False


@dataclass(frozen=True)
class Assessment:
    score: float
    priority: str
    effective_severity: str
    sla_days: int
    due_date: dt.date


def base_score(ctx: Context) -> float:
    if ctx.cvss is not None and ctx.cvss > 0:
        return min(10.0, float(ctx.cvss))
    return SEVERITY_BASE.get(ctx.severity.upper(), 0.0)


def score(ctx: Context) -> float:
    s = base_score(ctx)
    s *= 1.5 if ctx.kev else 1.0
    s *= 1.0 + max(0.0, min(1.0, ctx.epss))
    s *= 1.3 if ctx.internet_facing else 1.0
    s *= 1.2 if ctx.sensitive_data else 1.0
    s *= 1.2 if ctx.tier1 else 1.0
    return round(s, 2)


def priority(s: float) -> str:
    if s >= 15:
        return "P1"
    if s >= 10:
        return "P2"
    if s >= 5:
        return "P3"
    return "P4"


def effective_severity(ctx: Context) -> str:
    """KEV always treated as CRITICAL for SLA purposes."""
    if ctx.kev:
        return "CRITICAL"
    sev = ctx.severity.upper()
    return sev if sev in SLA_DAYS else "LOW"


def assess(ctx: Context, today: dt.date | None = None) -> Assessment:
    today = today or dt.date.today()
    s = score(ctx)
    eff = effective_severity(ctx)
    exposed = ctx.internet_facing or (ctx.prod and ctx.sensitive_data)
    days = SLA_DAYS[eff][0 if exposed else 1]
    return Assessment(score=s, priority=priority(s), effective_severity=eff, sla_days=days,
                      due_date=today + dt.timedelta(days=days))
