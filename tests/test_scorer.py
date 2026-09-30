"""Scorer: the overall-risk formula, band thresholds, confidence blend, threat matrix.

Expected values are computed by hand from the formula in ai_engine/scorer.py:
    raw = 0.6 * max(points) + 0.4 * mean(points) + min(15, 3 * severe_count)
with points Critical 95, High 75, Medium 50, Low 25 (unknown severities 25).
"""

import math

import pytest

import config
from ai_engine import scorer


def findings(*severities, category="Encryption"):
    """Findings with the given severities, ids F001.."""
    return [
        {"finding_id": "F%03d" % (i + 1), "category": category, "severity": s}
        for i, s in enumerate(severities)
    ]


# --------------------------------------------------------------------------
# overall risk
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severities, expected",
    [
        ((), (5, "Low")),  # no findings: fixed floor
        # sample_weak: 4 High, 5 Medium, 1 Low -> 45 + 23 + 12 = 80
        (("High",) * 4 + ("Medium",) * 5 + ("Low",), (80, "Critical")),
        # sample_mixed: 4 Medium, 3 Low -> 30 + 15.71 = 45.71 -> 46
        (("Medium",) * 4 + ("Low",) * 3, (46, "Medium")),
        # test_weak: 4 High, 4 Medium -> 45 + 25 + 12 = 82
        (("High",) * 4 + ("Medium",) * 4, (82, "Critical")),
        (("Critical",), (98, "Critical")),  # 57 + 38 + 3
        (("High",), (78, "High")),  # 45 + 30 + 3: one High alone is not Critical
        (("Medium",), (50, "Medium")),
        (("Low",), (25, "Low")),
        (("Catastrophic",), (25, "Low")),  # unknown severity scores like Low
        (("High",) * 10, (90, "Critical")),  # severe bonus capped at 15
        (("Critical",) * 10, (100, "Critical")),  # 110 clamped to 100
    ],
)
def test_overall_risk(severities, expected):
    assert scorer.overall_risk(findings(*severities)) == expected


@pytest.mark.parametrize(
    "score, level",
    [(100, "Critical"), (80, "Critical"), (79, "High"), (60, "High"), (59, "Medium"),
     (35, "Medium"), (34, "Low"), (0, "Low")],
)
def test_risk_level_boundaries(score, level):
    assert scorer.risk_level(score) == level


def test_thresholds_come_from_config(monkeypatch):
    monkeypatch.setattr(
        config, "RISK_LEVEL_THRESHOLDS", (("Critical", 90), ("High", 70), ("Medium", 40))
    )
    assert scorer.risk_level(85) == "High"
    assert scorer.overall_risk(findings("High", "High", "High", "High")) == (87, "High")


def test_score_findings_adds_risk_score_without_mutating():
    original = findings("Critical", "Low", "Bogus")
    scored = scorer.score_findings(original)
    assert [f["risk_score"] for f in scored] == [95, 25, 25]
    assert all("risk_score" not in f for f in original)


# --------------------------------------------------------------------------
# AI confidence
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sessions, traffic, expected",
    [
        ([], None, 0.5),  # nothing known: neutral default
        ([{"confidence": 0.9}, {"confidence": 0.7}], None, 0.8),  # parser mean only
        ([{"confidence": 1.0}], [0.5], 0.75),  # 50/50 blend
        ([{"confidence": 0.9}, {"confidence": 0.7}], [0.6, 1.0], 0.8),
        ([{"confidence": 1 / 3}], None, 0.33),  # rounded to 2 dp
        ([{"confidence": 1.5}], None, 1.0),  # clamped
        ([{"confidence": None}, {"confidence": 0.6}], None, 0.6),  # missing ignored
    ],
)
def test_ai_confidence(sessions, traffic, expected):
    assert scorer.ai_confidence(sessions, traffic) == expected


def test_ai_confidence_ignores_nan_instead_of_reporting_certainty():
    """Regression: NaN used to survive the clamp as 1.0 (min(1.0, nan) == 1.0)."""
    sessions = [{"confidence": math.nan}, {"confidence": 0.8}]
    assert scorer.ai_confidence(sessions, [0.9]) == 0.85
    assert scorer.ai_confidence([{"confidence": math.nan}]) == 0.5
    assert scorer.ai_confidence([{"confidence": 0.8}], [math.nan]) == 0.8


def test_ai_confidence_ignores_non_numeric_and_malformed_sessions():
    sessions = [{"confidence": "high"}, {"confidence": True}, "garbage", None, {"confidence": 0.4}]
    assert scorer.ai_confidence(sessions) == 0.4


# --------------------------------------------------------------------------
# threat matrix
# --------------------------------------------------------------------------


def test_threat_matrix_groups_by_category_using_the_worst_severity():
    items = [
        {"finding_id": "F001", "category": "Encryption", "severity": "Low"},
        {"finding_id": "F002", "category": "Encryption", "severity": "High"},
        {"finding_id": "F003", "category": "Lifetime", "severity": "Low"},
    ]
    matrix = scorer.build_threat_matrix(items)
    by_category = {row["category"]: row for row in matrix}

    assert set(by_category) == {"Encryption", "Lifetime"}
    assert by_category["Encryption"]["related_findings"] == ["F001", "F002"]
    assert by_category["Encryption"]["likelihood"] == "High"  # worst of Low, High
    assert by_category["Encryption"]["impact"] == "High"
    assert by_category["Lifetime"]["likelihood"] == "Low"
    assert by_category["Lifetime"]["impact"] == "Medium"


def test_threat_matrix_sorted_by_likelihood_then_impact():
    items = [
        {"finding_id": "F1", "category": "Lifetime", "severity": "Low"},  # Low / Medium
        {"finding_id": "F2", "category": "Mode", "severity": "Medium"},  # Medium / Medium
        {"finding_id": "F3", "category": "Hash", "severity": "Medium"},  # Medium / High
        {"finding_id": "F4", "category": "Compliance", "severity": "Critical"},  # High / Medium
    ]
    order = [row["category"] for row in scorer.build_threat_matrix(items)]
    assert order == ["Compliance", "Hash", "Mode", "Lifetime"]


@pytest.mark.parametrize(
    "severity, likelihood",
    [("Critical", "High"), ("High", "High"), ("Medium", "Medium"), ("Low", "Low"), ("Odd", "Low")],
)
def test_threat_likelihood_follows_severity(severity, likelihood):
    row = scorer.build_threat_matrix(findings(severity))[0]
    assert row["likelihood"] == likelihood


def test_threat_matrix_unknown_category_and_empty():
    row = scorer.build_threat_matrix(findings("High", category="Quantum"))[0]
    assert (row["threat"], row["impact"]) == ("Other security weakness", "Medium")
    assert scorer.build_threat_matrix([]) == []
