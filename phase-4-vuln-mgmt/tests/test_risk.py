import datetime as dt
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "lambda" / "findings_router"))

from risk import Context, assess, priority, score  # noqa: E402

TODAY = dt.date(2026, 10, 22)


def test_kev_internet_tier1_is_p1_7_days():
    a = assess(Context(severity="HIGH", cvss=8.1, epss=0.4, kev=True, internet_facing=True, tier1=True), TODAY)
    assert a.priority == "P1"
    assert a.effective_severity == "CRITICAL"
    assert a.sla_days == 7
    assert a.due_date == dt.date(2026, 10, 29)


def test_internal_high_gets_45_days():
    a = assess(Context(severity="HIGH"), TODAY)
    assert a.sla_days == 45
    assert a.priority == "P3"


def test_prod_sensitive_counts_as_exposed():
    a = assess(Context(severity="CRITICAL", prod=True, sensitive_data=True), TODAY)
    assert a.sla_days == 7


def test_score_monotonic_with_epss():
    lo = score(Context(severity="MEDIUM", epss=0.0))
    hi = score(Context(severity="MEDIUM", epss=0.9))
    assert hi > lo


def test_priority_thresholds():
    assert priority(15) == "P1"
    assert priority(10) == "P2"
    assert priority(5) == "P3"
    assert priority(4.99) == "P4"


def test_unknown_severity_falls_back_to_low_sla():
    a = assess(Context(severity="INFORMATIONAL"), TODAY)
    assert a.effective_severity == "LOW"
