"""End to end: capture -> backend -> ai_engine, through the Python API and both CLIs."""

import json
import os
import subprocess
import sys

import pytest

from ai_engine.test_data.check_contract_a import check_contract_a
from ai_engine.test_data.check_contract_b import check_contract_b
from frontend.pipeline import run_pipeline, run_pipeline_on_bytes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The verified numbers for the bundled samples. A change here is a change to
# what the tool tells a user, and must be deliberate.
VERIFIED = {
    "weak": (80, "Critical"),
    "mixed": (46, "Medium"),
    "strong": (5, "Low"),
}


@pytest.mark.parametrize("name", sorted(VERIFIED))
def test_verified_risk_scores(sample_path, name):
    _analysis, report = run_pipeline(sample_path(name), offline=True)
    assert (report["overall_risk_score"], report["risk_level"]) == VERIFIED[name]


@pytest.mark.parametrize("name", sorted(VERIFIED))
def test_both_contracts_hold_end_to_end(sample_path, name):
    analysis, report = run_pipeline(sample_path(name), offline=True)
    assert check_contract_a(analysis) == []
    assert check_contract_b(report) == []


def test_report_content_for_the_weak_sample(sample_path):
    _analysis, report = run_pipeline(sample_path("weak"), offline=True)
    assert len(report["findings"]) == 10
    assert report["traffic_analysis"][0]["predicted_traffic_type"] == "VoIP"
    assert report["executive_report"]["top_actions"]
    assert "ESP Tunnel Mode" in report["technical_report"]["protocol_identification"]


def test_committed_sample_reports_match_the_pipeline(sample_path):
    """sample_data/*_report.json must be what the pipeline produces today."""
    for name, (score, level) in VERIFIED.items():
        with open(os.path.join(ROOT, "sample_data", "sample_%s_report.json" % name)) as fh:
            committed = json.load(fh)
        assert (committed["overall_risk_score"], committed["risk_level"]) == (score, level)
        assert check_contract_b(committed) == []


def test_upload_path_keeps_the_uploaded_name(sample_path):
    data = open(sample_path("weak"), "rb").read()
    analysis, report = run_pipeline_on_bytes(data, "my_capture.pcap")
    assert analysis["file_name"] == report["file_name"] == "my_capture.pcap"
    assert check_contract_b(report) == []


def run_cli(*args):
    """Run a CLI from the repo root; returns (exit code, stdout, stderr)."""
    done = subprocess.run(
        [sys.executable, *args], cwd=ROOT, capture_output=True, text=True, timeout=120
    )
    return done.returncode, done.stdout, done.stderr


def test_backend_and_engine_clis(tmp_path, sample_path):
    analysis_path, report_path = tmp_path / "a.json", tmp_path / "b.json"
    code, out, _err = run_cli("backend/main.py", sample_path("weak"), str(analysis_path))
    assert code == 0 and "10 finding(s)" in out

    code, out, _err = run_cli("ai_engine/main.py", str(analysis_path), str(report_path), "--offline")
    assert code == 0 and "Risk score:    80 (Critical)" in out
    assert check_contract_b(json.loads(report_path.read_text())) == []


def test_backend_cli_rejects_bad_input_without_a_traceback(tmp_path):
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"definitely not a capture" * 5)
    code, _out, err = run_cli("backend/main.py", str(junk), str(tmp_path / "out.json"))
    assert code == 2
    assert "not a pcap or pcapng file" in err
    assert "Traceback" not in err


def test_engine_cli_rejects_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    code, _out, err = run_cli("ai_engine/main.py", str(bad), str(tmp_path / "out.json"))
    assert code == 1 and "not valid JSON" in err
