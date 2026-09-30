"""Configuration fix generator (ai_engine/remediation.py): strongSwan ipsec.conf snippets."""

import copy
import re

import pytest

from ai_engine import explainer, remediation
from ai_engine.main import run
from ai_engine.test_data.check_contract_b import check_contract_b
from backend.main import analyze

IKEV1_WEAK = {
    "session_id": "S1",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "protocol": "IKEv1",
    "exchange_mode": "Aggressive",
    "encryption": "3DES-CBC",
    "hash": "MD5",
    "dh_group": 2,
    "lifetime_seconds": 172800,
}
IKEV2 = dict(IKEV1_WEAK, protocol="IKEv2", exchange_mode="IKE_SA_INIT")

SETTING = re.compile(r"^    ([a-z_]+)=(\S+)$")


def finding(category, session_id="S1", finding_id="F001"):
    """A minimal finding of the given category."""
    return {"finding_id": finding_id, "session_id": session_id, "category": category}


def settings_of(snippet):
    """{key: value} of every setting line; fails on any line that is not valid syntax."""
    found = {}
    for line in snippet.splitlines():
        if line.startswith("#") or line.startswith("    #") or line.startswith("conn "):
            continue
        match = SETTING.match(line)
        assert match, "not a valid ipsec.conf setting line: %r" % line
        key, value = match.groups()
        assert key not in found, "duplicate key %s" % key
        found[key] = value
    return found


@pytest.mark.parametrize(
    "category, expected",
    [
        ("Encryption", {"ike": remediation.TARGET_IKE, "esp": remediation.TARGET_ESP}),
        ("Hash", {"ike": remediation.TARGET_IKE, "esp": remediation.TARGET_ESP}),
        ("KeyExchange", {"ike": remediation.TARGET_IKE, "esp": remediation.TARGET_ESP}),
        ("Compliance", {"ike": remediation.TARGET_IKE, "esp": remediation.TARGET_ESP}),
        ("PFS", {"esp": remediation.TARGET_ESP}),
        ("Protocol", {"keyexchange": "ikev2", "aggressive": "no"}),
        ("MetadataExposure", {"keyexchange": "ikev2", "aggressive": "no"}),
        ("Authentication", {"leftauth": "pubkey", "rightauth": "pubkey"}),
        ("Lifetime", {"ikelifetime": "8h", "lifetime": "1h"}),
        ("Mode", {"type": "tunnel"}),
        ("ReplayProtection", {"replay_window": "32"}),
    ],
)
def test_each_category_sets_the_fixing_lines(category, expected):
    settings = settings_of(remediation.snippet_for_finding(finding(category), IKEV1_WEAK))
    assert expected.items() <= settings.items()


def test_snippet_structure():
    snippet = remediation.snippet_for_finding(finding("Encryption"), IKEV1_WEAK)
    lines = snippet.splitlines()
    assert lines[0].startswith("# strongSwan ipsec.conf: fix for F001 (Encryption)")
    assert "10.0.0.1 <-> 10.0.0.2" in lines[1]
    assert "conn session-S1" in lines
    assert all(("#" not in line) for line in lines if SETTING.match(line))  # no trailing comments


def test_crypto_fix_moves_ikev1_to_ikev2_but_leaves_ikev2_alone():
    v1 = settings_of(remediation.snippet_for_finding(finding("Hash"), IKEV1_WEAK))
    v2 = settings_of(remediation.snippet_for_finding(finding("Hash"), IKEV2))
    assert v1["keyexchange"] == "ikev2"
    assert "keyexchange" not in v2


@pytest.mark.parametrize(
    "session, expected",
    [
        (IKEV1_WEAK, "3des-md5-modp1024"),
        (
            dict(IKEV1_WEAK, encryption="AES-256-GCM", hash="SHA256", dh_group=14),
            "aes256gcm16-prfsha256-modp2048",
        ),
        (
            dict(IKEV1_WEAK, encryption="AES-128-CBC", hash="SHA1", dh_group=5),
            "aes128-sha1-modp1536",
        ),
        (dict(IKEV1_WEAK, hash="Unknown"), "3des-?-modp1024"),
        (dict(IKEV1_WEAK, encryption="Unknown", hash="Unknown", dh_group=None), None),
    ],
)
def test_observed_ike_proposal(session, expected):
    assert remediation.observed_ike_proposal(session) == expected


def test_was_comments_record_what_the_capture_showed():
    crypto = remediation.snippet_for_finding(finding("Encryption"), IKEV1_WEAK)
    lifetime = remediation.snippet_for_finding(finding("Lifetime"), IKEV1_WEAK)
    assert "# was (observed): ike=3des-md5-modp1024" in crypto
    assert "# was (observed): keyexchange=ikev1" in crypto
    assert "# was (observed): ikelifetime=172800s" in lifetime


def test_no_was_line_when_nothing_was_observed():
    blank = {"session_id": "S1", "protocol": "Unknown"}
    snippet = remediation.snippet_for_finding(finding("Encryption"), blank)
    assert "was (observed): ike=" not in snippet
    assert "was (observed): keyexchange" not in snippet


def test_unknown_category_has_no_snippet():
    assert remediation.snippet_for_finding(finding("Quantum"), IKEV1_WEAK) == ""


def test_merged_session_config():
    categories = ["Encryption", "Hash", "KeyExchange", "Compliance", "PFS", "Protocol", "Lifetime"]
    items = [finding(c, finding_id="F%03d" % i) for i, c in enumerate(categories, start=1)]
    merged = remediation.session_config(IKEV1_WEAK, items)
    settings = settings_of(merged)  # also asserts every key appears once

    union = {}
    for item in items:
        union.update(settings_of(remediation.snippet_for_finding(item, IKEV1_WEAK)))
    assert settings == union
    assert "Addresses F001, F002, F003, F004, F005, F006, F007" in merged
    # The PFS finding's own note survives the merge onto the shared esp= line.
    assert "no DH group in the ESP proposal" in merged


def test_attach_adds_snippets_without_mutating_and_skips_clean_sessions():
    findings = [finding("Mode"), finding("PFS", finding_id="F002")]
    before = copy.deepcopy(findings)
    clean = dict(IKEV2, session_id="S2")
    out, configs = remediation.attach(findings, [IKEV1_WEAK, clean])

    assert findings == before
    assert all(f["remediation_snippet"] for f in out)
    assert [c["session_id"] for c in configs] == ["S1"]


def test_conn_name_is_sanitised():
    snippet = remediation.snippet_for_finding(finding("Mode", session_id="a b:c"), {})
    assert "conn session-a_b_c" in snippet


# --------------------------------------------------------------------------
# through the whole pipeline
# --------------------------------------------------------------------------


def test_weak_sample_gets_a_fix_for_every_finding(sample_path):
    report = run(analyze(sample_path("weak")), offline=True)
    assert all(f["remediation_snippet"] for f in report["findings"])
    assert [c["session_id"] for c in report["remediation_config"]] == ["S1"]
    settings = settings_of(report["remediation_config"][0]["snippet"])
    assert settings["keyexchange"] == "ikev2"
    assert settings["replay_window"] == "32"


def test_mixed_sample_fix_includes_tunnel_mode(sample_path):
    report = run(analyze(sample_path("mixed")), offline=True)
    assert settings_of(report["remediation_config"][0]["snippet"])["type"] == "tunnel"


def test_strong_sample_needs_no_fix(sample_path):
    assert run(analyze(sample_path("strong")), offline=True)["remediation_config"] == []


def test_snippets_are_deterministic(sample_path):
    analysis = analyze(sample_path("weak"))
    first, second = run(analysis, offline=True), run(analysis, offline=True)
    assert first["remediation_config"] == second["remediation_config"]
    assert [f["remediation_snippet"] for f in first["findings"]] == [
        f["remediation_snippet"] for f in second["findings"]
    ]


def test_snippets_never_come_from_the_llm(monkeypatch, sample_path):
    """Even when Claude writes the explanations, the config comes from the rules."""
    analysis = analyze(sample_path("weak"))
    offline = run(analysis, offline=True)

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("AI_OFFLINE")
    monkeypatch.setattr(
        explainer,
        "_ask_llm",
        lambda items: {
            f["finding_id"]: {
                "explanation": "x",
                "recommendation": "use ike=anything",
                "reference": "y",
            }
            for f in items
        },
    )
    online = run(analysis)
    assert online["findings"][0]["recommendation"] == "use ike=anything"
    assert [f["remediation_snippet"] for f in online["findings"]] == [
        f["remediation_snippet"] for f in offline["findings"]
    ]


def test_contract_b_accepts_reports_with_and_without_the_new_fields(sample_path):
    report = run(analyze(sample_path("weak")), offline=True)
    assert check_contract_b(report) == []

    old_style = copy.deepcopy(report)
    old_style.pop("remediation_config")
    for item in old_style["findings"]:
        item.pop("remediation_snippet")
    assert check_contract_b(old_style) == []

    typo = copy.deepcopy(report)
    typo["findings"][0]["remediation_snipet"] = "x"
    assert any("unexpected key 'remediation_snipet'" in e for e in check_contract_b(typo))
