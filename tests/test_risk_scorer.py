"""
tests/test_risk_scorer.py
Verify that extract_features returns exactly 16 numeric features.
"""

from src.tactical.risk_scorer import FEATURE_COLS, extract_features


def _sample_alert() -> dict:
    return {
        "timestamp": "2026-06-15T22:14:00+0000",
        "rule": {
            "level": 12,
            "id": "100118",
            "firedtimes": 5,
            "mitre": {"tactic": ["Collection", "Exfiltration"]},
        },
        "agent": {"id": "006"},
        "syscheck": {
            "path": "D:/Finance/Payroll/salaires_cadres.xlsx",
            "event": "modified",
        },
        "data": {"file_access_count": 120, "window_seconds": 60},
    }


def test_feature_count_is_16():
    assert len(FEATURE_COLS) == 16
    features = extract_features(_sample_alert())
    assert len(features) == 16


def test_features_match_columns():
    features = extract_features(_sample_alert())
    assert set(features.keys()) == set(FEATURE_COLS)


def test_out_of_scope_detected():
    # Agent 006 scope is d:/finance/reporting; payroll is out of scope.
    features = extract_features(_sample_alert())
    assert features["is_outside_scope"] == 1


def test_outside_business_hours_flag():
    features = extract_features(_sample_alert())  # 22:14 -> outside hours
    assert features["is_outside_business_hours"] == 1
