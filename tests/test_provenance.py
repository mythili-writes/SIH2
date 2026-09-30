"""Confidence-aware uncertainty: which values were observed, which inferred, and why."""

import copy

import pytest

import pcaps
from ai_engine import report_builder
from ai_engine.main import run
from ai_engine.test_data.check_contract_a import check_contract_a
from ai_engine.test_data.check_contract_b import check_contract_b
from backend import parser, rules
from backend.main import analyze

STATUSES = {"observed", "inferred", "unknown"}


def provenance(path):
    """The field_provenance of the only session in a capture."""
    sessions = parser.parse_pcap(path)["sessions"]
    assert len(sessions) == 1
    return sessions[0]["field_provenance"], sessions[0]


def status_map(prov):
    """{field: status}."""
    return {field: entry["status"] for field, entry in prov.items()}


# --------------------------------------------------------------------------
# shape and consistency
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["weak", "mixed", "strong"])
def test_every_field_has_a_status_and_a_basis(sample_path, name):
    for session in parser.parse_pcap(sample_path(name))["sessions"]:
        prov = session["field_provenance"]
        assert set(prov) == set(parser.PROVENANCE_FIELDS)
        for field, entry in prov.items():
            assert entry["status"] in STATUSES, field
            assert entry["basis"].strip(), field


@pytest.mark.parametrize("name", ["weak", "mixed", "strong"])
def test_unknown_status_exactly_when_the_value_is_unknown(sample_path, name):
    session = parser.parse_pcap(sample_path(name))["sessions"][0]
    for field, entry in session["field_provenance"].items():
        if field == "traffic_features":
            continue
        missing = session[field] in (None, "Unknown")
        assert (entry["status"] == "unknown") == missing, field


# --------------------------------------------------------------------------
# what counts as observed and what as inferred, on crafted captures
# --------------------------------------------------------------------------


def test_values_read_from_the_ike_proposal_are_observed(tmp_path):
    transforms = [("Encryption", "3DES-CBC"), ("Hash", "MD5"), ("GroupDesc", "1024MODPgr")]
    path = pcaps.write(tmp_path / "p.pcap", [pcaps.udp500(pcaps.isakmp_phase1(transforms))])
    statuses = status_map(provenance(path)[0])
    for field in ("protocol", "exchange_mode", "encryption", "hash", "dh_group", "key_exchange"):
        assert statuses[field] == "observed", field


def test_esp_size_heuristic_mode_is_inferred(tmp_path):
    prov, session = provenance(
        pcaps.write(tmp_path / "e.pcap", [pcaps.esp(s, size=200) for s in (1, 2, 3)])
    )
    assert session["ipsec_mode"] == "Tunnel"
    assert prov["ipsec_mode"]["status"] == "inferred"
    assert "heuristic" in prov["ipsec_mode"]["basis"]


def test_ikev2_default_tunnel_mode_is_inferred_and_says_why(tmp_path):
    msg = pcaps.ikev2_sa_init(
        [pcaps.v2_transform("Encryption", 20, 256), pcaps.v2_transform("GroupDesc", 14)]
    )
    prov, _session = provenance(pcaps.write(tmp_path / "v2.pcap", [pcaps.udp500(msg)]))
    assert prov["ipsec_mode"]["status"] == "inferred"
    assert "USE_TRANSPORT_MODE" in prov["ipsec_mode"]["basis"]


def test_explicit_transport_mode_is_observed(tmp_path):
    msg = pcaps.isakmp_quick_mode([("EncapsulationMode", "Transport")])
    prov, _ = provenance(pcaps.write(tmp_path / "t.pcap", [pcaps.udp500(msg)]))
    assert prov["ipsec_mode"]["status"] == "observed"


def test_replay_protection_is_always_an_inference(tmp_path):
    good = provenance(pcaps.write(tmp_path / "g.pcap", [pcaps.esp(s) for s in (1, 2, 3)]))[0]
    bad = provenance(pcaps.write(tmp_path / "b.pcap", [pcaps.esp(s) for s in (1, 3, 2)]))[0]
    assert good["replay_protection"]["status"] == bad["replay_protection"]["status"] == "inferred"
    assert "monotonically" in good["replay_protection"]["basis"]
    assert "backwards" in bad["replay_protection"]["basis"]


def test_nat_traversal_observed_on_4500_but_only_inferred_absent(tmp_path):
    p1 = pcaps.isakmp_phase1([("Encryption", "3DES-CBC")])
    on_4500 = provenance(pcaps.write(tmp_path / "n1.pcap", [pcaps.udp4500(p1)]))[0]
    on_500 = provenance(pcaps.write(tmp_path / "n2.pcap", [pcaps.udp500(p1)]))[0]
    assert on_4500["nat_traversal"]["status"] == "observed"
    assert on_500["nat_traversal"]["status"] == "inferred"


def test_identity_exposure_observed_in_the_clear_inferred_from_protocol(tmp_path):
    clear = pcaps.isakmp_phase1(
        [("Encryption", "3DES-CBC")], exch_type=4, payloads=[pcaps.id_payload()]
    )
    exposed = provenance(pcaps.write(tmp_path / "i1.pcap", [pcaps.udp500(clear)]))[0]
    main = pcaps.isakmp_phase1([("Encryption", "3DES-CBC")], exch_type=2)
    protected = provenance(pcaps.write(tmp_path / "i2.pcap", [pcaps.udp500(main)]))[0]
    assert exposed["identity_exposed"]["status"] == "observed"
    assert protected["identity_exposed"]["status"] == "inferred"
    assert "main mode" in protected["identity_exposed"]["basis"]


def test_ikev2_lifetime_is_not_determined_with_the_reason(sample_path):
    prov = parser.parse_pcap(sample_path("strong"))["sessions"][0]["field_provenance"]
    assert prov["lifetime_seconds"]["status"] == "unknown"
    assert "IKEv2 does not negotiate lifetimes" in prov["lifetime_seconds"]["basis"]


# --------------------------------------------------------------------------
# findings inherit the certainty of the data they rest on
# --------------------------------------------------------------------------


def test_weak_sample_findings_say_which_rest_on_inference(sample_path):
    findings = {f["category"]: f for f in analyze(sample_path("weak"))["findings"]}
    assert findings["ReplayProtection"]["evidence_status"] == "inferred"
    assert findings["ReplayProtection"]["evidence_basis"].startswith("replay_protection:")
    for category in ("Encryption", "Hash", "KeyExchange", "Protocol", "MetadataExposure"):
        assert findings[category]["evidence_status"] == "observed", category


def test_finding_takes_the_weakest_status_of_the_fields_it_reads():
    session = {
        "session_id": "S1",
        "protocol": "IKEv1",
        "exchange_mode": "Aggressive",
        "field_provenance": {
            "protocol": {"status": "observed", "basis": "header"},
            "exchange_mode": {"status": "inferred", "basis": "guess"},
        },
    }
    finding = next(f for f in rules.evaluate([session]) if f["category"] == "Protocol")
    assert finding["evidence_status"] == "inferred"
    assert finding["evidence_basis"] == "exchange_mode: guess"


def test_compliance_ignores_fields_it_did_not_need():
    """AES-128-CBC fails the baseline on the cipher alone; an unknown hash must not taint it."""
    session = {
        "session_id": "S1",
        "encryption": "AES-128-CBC",
        "hash": "Unknown",
        "field_provenance": {
            "encryption": {"status": "observed", "basis": "proposal"},
            "hash": {"status": "unknown", "basis": "not seen"},
        },
    }
    compliance = next(f for f in rules.evaluate([session]) if f["category"] == "Compliance")
    assert compliance["evidence_status"] == "observed"


def test_sessions_without_provenance_still_work():
    """Contract A from another producer has no provenance; the rules must not invent it."""
    found = rules.evaluate([{"session_id": "S1", "encryption": "3DES-CBC"}])
    assert found and all("evidence_status" not in f for f in found)


# --------------------------------------------------------------------------
# into the report
# --------------------------------------------------------------------------


def test_report_carries_uncertainty_notes_and_evidence_status(sample_path):
    report = run(analyze(sample_path("strong")), offline=True)
    notes = report["technical_report"]["uncertainty_notes"]
    assert notes.startswith("Session S1: ")
    assert "ipsec_mode (packet-size heuristic" in notes
    assert "not determined: lifetime_seconds" in notes
    assert report["sessions"][0]["field_provenance"]["ipsec_mode"]["status"] == "inferred"


def test_report_marks_findings_from_producers_without_provenance_as_unknown(sample_path):
    analysis = analyze(sample_path("weak"))
    for session in analysis["sessions"]:
        session.pop("field_provenance")
    for item in analysis["findings"]:
        item.pop("evidence_status", None)
        item.pop("evidence_basis", None)
    report = run(analysis, offline=True)
    assert {f["evidence_status"] for f in report["findings"]} == {"unknown"}
    assert (
        "did not report how each value was obtained"
        in report["technical_report"]["uncertainty_notes"]
    )
    assert check_contract_b(report) == []


def test_uncertainty_notes_without_sessions():
    assert report_builder.build_uncertainty_notes([]) == report_builder.NO_SESSIONS_TEXT


def test_contracts_accept_the_new_fields_and_reject_bad_statuses(sample_path):
    analysis = analyze(sample_path("weak"))
    report = run(analysis, offline=True)
    assert check_contract_a(analysis) == []
    assert check_contract_b(report) == []

    bad = copy.deepcopy(analysis)
    bad["sessions"][0]["field_provenance"]["ipsec_mode"]["status"] = "probably"
    assert any("status='probably'" in e for e in check_contract_a(bad))

    bad_report = copy.deepcopy(report)
    bad_report["findings"][0]["evidence_status"] = "certain"
    assert any("evidence_status='certain'" in e for e in check_contract_b(bad_report))


def test_risk_scores_are_unaffected_by_provenance(sample_path):
    """Uncertainty is reported, not folded into the score: the verified numbers hold."""
    scores = {
        name: run(analyze(sample_path(name)), offline=True)["overall_risk_score"]
        for name in ("weak", "mixed", "strong")
    }
    assert scores == {"weak": 80, "mixed": 46, "strong": 5}
