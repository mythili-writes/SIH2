"""Dashboard smoke tests: the real Streamlit script, run headlessly with AppTest.

These exist because the dashboard once shipped rendering a report shape the
engine no longer produced, and crashed on the Traffic Analysis tab.
"""

import copy
import os

import pytest
from streamlit.testing.v1 import AppTest

import frontend.pipeline as pipeline
from backend.parser import CaptureError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "frontend", "app.py")


def analyse_sample(label):
    """Run the app, pick the bundled sample whose label contains `label`, click Analyze."""
    at = AppTest.from_file(APP, default_timeout=120)
    at.run()
    at.radio[0].set_value("Use a bundled sample").run()
    at.selectbox[0].set_value(next(o for o in at.selectbox[0].options if label in o)).run()
    at.button[0].click().run()
    return at


def test_landing_page_renders():
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    assert not at.exception
    assert at.title[0].value == "IPsec VPN Security Analyser"


def expected_downloads(at):
    """Executive JSON + PDF, technical x3, plus one .conf per session needing a fix."""
    return 5 + len(at.session_state["report"]["remediation_config"])


@pytest.mark.parametrize("label", ["Weak", "Mixed", "Strong", "Test capture"])
def test_every_sample_renders_every_tab(label):
    at = analyse_sample(label)
    assert not at.exception
    assert not at.error
    assert len(at.tabs) == 8
    assert len(at.get("download_button")) == expected_downloads(at)


def test_remediation_is_shown_as_copyable_config():
    at = analyse_sample("Weak")
    snippets = [block.value for block in at.code if "conn session-S1" in block.value]
    assert snippets, "no strongSwan config block rendered"
    assert any("Download ipsec-S1.conf" == b.label for b in at.get("download_button"))


def test_bad_capture_shows_a_readable_error(monkeypatch):
    def reject(*_args, **_kwargs):
        raise CaptureError("not a pcap or pcapng file (unrecognised header 0x68656c6c)")

    monkeypatch.setattr(pipeline, "run_pipeline", reject)
    at = analyse_sample("Weak")
    assert not at.exception
    assert at.error[0].value.startswith("Could not parse this capture: not a pcap")


def test_unexpected_error_hides_internals(monkeypatch):
    def bug(*_args, **_kwargs):
        raise RuntimeError("internal detail /home/secret/path")

    monkeypatch.setattr(pipeline, "run_pipeline", bug)
    at = analyse_sample("Weak")
    assert not at.exception
    message = at.error[0].value
    assert "RuntimeError" in message and "internal detail" not in message


def test_a_broken_tab_does_not_take_down_the_others(monkeypatch):
    real = pipeline.run_pipeline

    def broken(*args, **kwargs):
        analysis, report = real(*args, **kwargs)
        report = copy.deepcopy(report)
        report["traffic_analysis"][0]["top_predictions"][0]["probability"] = "not-a-number"
        return analysis, report

    monkeypatch.setattr(pipeline, "run_pipeline", broken)
    at = analyse_sample("Weak")
    assert not at.exception
    assert len(at.error) == 1 and "Traffic Analysis" in at.error[0].value
    assert len(at.get("download_button")) == expected_downloads(at)  # later tabs still rendered


def test_inferred_values_are_visibly_caveated():
    at = analyse_sample("Weak")
    assert any("Based on inferred data" in w.value for w in at.warning)
    markdown = " ".join(m.value for m in at.markdown)
    assert "Data quality: observed vs inferred" in markdown
    assert "Observed directly" in markdown
    assert 'class="prov prov-inferred"' in markdown
