"""Regression checks for non-blocking Streamlit navigation."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_SOURCE = PROJECT_ROOT / "src" / "alerting" / "dashboard.py"


def test_alert_refresh_uses_a_streamlit_fragment() -> None:
    source = DASHBOARD_SOURCE.read_text(encoding="utf-8")

    assert "@st.fragment(run_every=REFRESH_SECONDS)" in source
    assert "time.sleep(" not in source
    assert "st.rerun()" not in source

