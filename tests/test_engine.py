"""ai_engine: robustness of run(), explainer rule matching, the shipped traffic model."""

import copy
import json
import math
import os

import pytest

import config
from ai_engine import explainer, traffic_model
from ai_engine.main import run
from ai_engine.test_data.check_contract_b import check_contract_b

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANONICAL = os.path.join(ROOT, "ai_engine", "test_data", "test_analysis.json")


@pytest.fixture
def canonical():
    """A fresh copy of the canonical Contract A test input."""
    with open(CANONICAL, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# run(): never raises, and returns a valid Contract B for malformed input
# --------------------------------------------------------------------------


def test_canonical_input_produces_valid_contract_b(canonical):
    assert check_contract_b(run(canonical, offline=True)) == []


def test_run_does_not_modify_its_input(canonical):
    before = copy.deepcopy(canonical)
    run(canonical, offline=True)
    assert canonical == before


MALFORMED = {
    "empty dict": lambda a: a.clear(),
    "non-dict session": lambda a: a["sessions"].append("garbage"),
    "None session": lambda a: a["sessions"].append(None),
    "string confidence": lambda a: a["sessions"][0].update(confidence="high"),
    "NaN confidence": lambda a: a["sessions"][0].update(confidence=math.nan),
    "string traffic features": lambda a: a["sessions"][0].update(
        traffic_features={"packet_count": "lots"}
    ),
    "missing traffic features": lambda a: a["sessions"][0].update(traffic_features=None),
    "finding without id": lambda a: a["findings"][0].pop("finding_id"),
    "finding without category": lambda a: a["findings"][0].pop("category"),
    "finding with odd severity": lambda a: a["findings"][0].update(severity="Catastrophic"),
    "non-dict finding": lambda a: a["findings"].append(42),
    "finding without issue": lambda a: a["findings"][0].update(issue=None, evidence=None),
    "findings not a list": lambda a: a.update(findings={"a": 1}),
    "file_name None": lambda a: a.update(file_name=None),
}


@pytest.mark.parametrize("mutate", MALFORMED.values(), ids=MALFORMED.keys())
def test_malformed_input_still_yields_valid_contract_b(canonical, mutate):
    mutate(canonical)
    assert check_contract_b(run(canonical, offline=True)) == []


def test_one_bad_session_does_not_cost_the_others_their_traffic_analysis(canonical):
    canonical["sessions"].append("garbage")
    report = run(canonical, offline=True)
    assert len(report["traffic_analysis"]) == 2
    assert all(t["predicted_traffic_type"] != "Unknown" for t in report["traffic_analysis"])


def test_run_accepts_non_dict_input():
    assert check_contract_b(run(None, offline=True)) == []


# --------------------------------------------------------------------------
# explainer
# --------------------------------------------------------------------------


def test_explainer_is_offline_by_default_in_tests(canonical):
    findings, mode = explainer.explain_findings(canonical["findings"])
    assert mode == "rule"
    assert all(f["explanation"] and f["recommendation"] and f["reference"] for f in findings)


@pytest.mark.parametrize(
    "issue, evidence, expected",
    [
        ("3DES is deprecated", "encryption=3DES", "Replace 3DES"),
        ("DES is weak", "encryption=DES", "Replace DES"),  # "des" must not match "3des"
        ("DH group 2 (1024-bit) is too weak", "dh_group=2", "DH group 14"),
        (
            "IKEv1 Aggressive Mode exposes the PSK hash",
            "",
            "Main Mode",
        ),  # aggressive before ikev1/psk
        # Regression: Compliance evidence quotes the weak cipher; the issue must win.
        (
            "Negotiated cipher suite is not compliant with the approved baseline",
            "Suite 3DES-CBC/MD5/DH2 fails the baseline",
            "NIST-approved suite",
        ),
        (
            "Negotiated cipher suite is not compliant with the approved baseline",
            "Suite AES-128-CBC/SHA1/DH5 fails the baseline",
            "NIST-approved suite",
        ),
    ],
)
def test_explainer_rule_matching(issue, evidence, expected):
    text = explainer.rule_explanation({"issue": issue, "evidence": evidence})
    assert expected in text["recommendation"]


def test_explainer_falls_back_to_a_generic_explanation():
    text = explainer.rule_explanation({"category": "Quantum", "severity": "High", "issue": "odd"})
    assert "Quantum" in text["explanation"] and text["reference"]


def test_llm_failure_falls_back_to_rules(monkeypatch, canonical):
    """With a key set, a failing API call must degrade to rule text, not raise."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("AI_OFFLINE")

    def boom(_findings):
        raise ConnectionError("no network in tests")

    monkeypatch.setattr(explainer, "_ask_llm", boom)
    findings, mode = explainer.explain_findings(canonical["findings"])
    assert mode == "rule"
    assert all(f["recommendation"] for f in findings)


def test_llm_model_name_comes_from_config_or_environment(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    assert explainer._model_name() == config.LLM_DEFAULT_MODEL
    monkeypatch.setenv("ANTHROPIC_MODEL", "some-other-model")
    assert explainer._model_name() == "some-other-model"


# --------------------------------------------------------------------------
# traffic model
# --------------------------------------------------------------------------


def test_shipped_model_loads_without_retraining(monkeypatch):
    """The committed .joblib must load under the pinned scikit-learn.

    If this fails, requirements.txt and models/traffic_model.joblib disagree,
    and every user would silently get a retrained model.
    """

    def refuse(*_args, **_kwargs):
        raise AssertionError("load_model() tried to retrain the shipped model")

    monkeypatch.setattr(traffic_model, "train", refuse)
    model = traffic_model.load_model()  # a version mismatch would route into train()
    assert model is not None
    assert sorted(model.classes_) == sorted(traffic_model.CLASSES)


def test_voip_shaped_flow_is_classified_as_voip():
    session = {
        "session_id": 1,
        "traffic_features": {
            "packet_count": 110,
            "avg_packet_size": 160,
            "min_packet_size": 96,
            "max_packet_size": 220,
            "avg_inter_arrival_ms": 20,
            "duration_seconds": 2.5,
            "bytes_total": 17600,
            "upstream_ratio": 0.5,
        },
    }
    result = traffic_model.predict_sessions([session])[0]
    assert result["predicted_traffic_type"] == "VoIP"
    assert len(result["top_predictions"]) == 3


def test_low_confidence_is_reported_unknown(monkeypatch):
    monkeypatch.setattr(config, "TRAFFIC_MIN_CONFIDENCE", 1.01)
    session = {"session_id": 1, "traffic_features": {"packet_count": 50, "avg_packet_size": 400}}
    assert traffic_model.predict_sessions([session])[0]["predicted_traffic_type"] == "Unknown"


def test_session_without_traffic_is_unknown():
    result = traffic_model.predict_sessions([{"session_id": 1, "traffic_features": {}}])[0]
    assert (result["predicted_traffic_type"], result["traffic_confidence"]) == ("Unknown", 0.0)


def test_model_failure_falls_back_to_rules(monkeypatch):
    def broken(_rows):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(traffic_model, "_model_rankings", broken)
    session = {
        "session_id": 1,
        "traffic_features": {
            "packet_count": 50,
            "avg_packet_size": 150,
            "avg_inter_arrival_ms": 20,
        },
    }
    result = traffic_model.predict_sessions([session])[0]
    assert (result["predicted_traffic_type"], result["traffic_confidence"]) == ("VoIP", 0.5)
