"""Rule engine: each rule fires on the weak value it targets, and on nothing else.

Every case starts from STRONG, a session that raises no findings, changes one
or two fields, and asserts the exact set of (category, severity) produced.
"""

import pytest

import config
from backend import rules

STRONG = {
    "session_id": "S1",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "protocol": "IKEv2",
    "exchange_mode": "IKE_SA_INIT",
    "encryption": "AES-256-GCM",
    "hash": "SHA256",
    "dh_group": 14,
    "auth_method": "RSA Digital Signature",
    "lifetime_seconds": 3600,
    "pfs_enabled": True,
    "ipsec_mode": "Tunnel",
    "replay_protection": True,
    "identity_exposed": False,
}


def findings_for(**changes):
    """{(category, severity), ...} raised for STRONG with `changes` applied."""
    session = dict(STRONG, **changes)
    return {(f["category"], f["severity"]) for f in rules.evaluate([session])}


def test_strong_session_raises_nothing():
    assert rules.evaluate([STRONG]) == []


@pytest.mark.parametrize(
    "changes, expected",
    [
        # Encryption: the cipher rule, plus Compliance when the suite leaves the baseline.
        ({"encryption": "DES-CBC"}, {("Encryption", "Critical"), ("Compliance", "Medium")}),
        ({"encryption": "NULL"}, {("Encryption", "Critical"), ("Compliance", "Medium")}),
        ({"encryption": "3DES-CBC"}, {("Encryption", "High"), ("Compliance", "Medium")}),
        ({"encryption": "AES-128-CBC"}, {("Encryption", "Low"), ("Compliance", "Medium")}),
        # AES-256-CBC with SHA-256 and DH 14 meets the baseline: only the CBC advisory.
        ({"encryption": "AES-256-CBC"}, {("Encryption", "Low")}),
        ({"encryption": "AES-128-GCM"}, set()),
        # Hash. AES-GCM is AEAD, so the suite stays compliant even with a weak PRF.
        ({"hash": "MD5"}, {("Hash", "High")}),
        ({"hash": "SHA1"}, {("Hash", "Medium")}),
        ({"hash": "SHA384"}, set()),
        # Key exchange.
        ({"dh_group": 1}, {("KeyExchange", "High")}),
        ({"dh_group": 2}, {("KeyExchange", "High")}),
        ({"dh_group": 5}, {("KeyExchange", "Medium")}),
        ({"dh_group": 19}, set()),
        # Protocol.
        ({"protocol": "IKEv1", "exchange_mode": "Main"}, {("Protocol", "Medium")}),
        ({"protocol": "IKEv1", "exchange_mode": "Aggressive"}, {("Protocol", "High")}),
        ({"exchange_mode": "Aggressive"}, set()),  # aggressive mode only exists in IKEv1
        # Authentication.
        ({"auth_method": "Pre-Shared Key"}, {("Authentication", "Medium")}),
        ({"auth_method": "ECDSA Digital Signature"}, set()),
        # PFS: only an explicit False fires; unknown (None) must not.
        ({"pfs_enabled": False}, {("PFS", "Medium")}),
        ({"pfs_enabled": None}, set()),
        # Lifetime window, boundaries inclusive of the allowed range.
        ({"lifetime_seconds": 86401}, {("Lifetime", "Low")}),
        ({"lifetime_seconds": 86400}, set()),
        ({"lifetime_seconds": 299}, {("Lifetime", "Low")}),
        ({"lifetime_seconds": 300}, set()),
        ({"lifetime_seconds": None}, set()),
        ({"lifetime_seconds": True}, set()),  # a bool is not a lifetime
        # Mode.
        ({"ipsec_mode": "Transport"}, {("Mode", "Low")}),
        ({"ipsec_mode": "Unknown"}, set()),
        # Replay protection: explicit False only.
        ({"replay_protection": False}, {("ReplayProtection", "Medium")}),
        ({"replay_protection": None}, set()),
        # Metadata exposure: explicit True only.
        ({"identity_exposed": True}, {("MetadataExposure", "Medium")}),
        ({"identity_exposed": None}, set()),
        # Unknown values never produce a finding, not even Compliance.
        ({"encryption": "Unknown"}, set()),
        ({"encryption": "Unknown", "hash": "Unknown", "dh_group": None}, set()),
    ],
)
def test_single_rule(changes, expected):
    assert findings_for(**changes) == expected


def test_weak_session_raises_every_expected_category():
    weak = {
        "protocol": "IKEv1",
        "exchange_mode": "Aggressive",
        "encryption": "3DES-CBC",
        "hash": "MD5",
        "dh_group": 2,
        "auth_method": "Pre-Shared Key",
        "lifetime_seconds": 172800,
        "pfs_enabled": False,
        "replay_protection": False,
        "identity_exposed": True,
    }
    assert findings_for(**weak) == {
        ("Encryption", "High"),
        ("Hash", "High"),
        ("KeyExchange", "High"),
        ("Protocol", "High"),
        ("Authentication", "Medium"),
        ("PFS", "Medium"),
        ("Lifetime", "Low"),
        ("ReplayProtection", "Medium"),
        ("MetadataExposure", "Medium"),
        ("Compliance", "Medium"),
    }


def test_finding_shape_and_ids():
    session = dict(STRONG, encryption="3DES-CBC", hash="MD5")
    other = dict(STRONG, session_id="S2", dh_group=2)
    found = rules.evaluate([session, other])

    assert [f["finding_id"] for f in found] == ["F%03d" % i for i in range(1, len(found) + 1)]
    for finding in found:
        assert set(finding) == {
            "finding_id",
            "session_id",
            "category",
            "issue",
            "severity",
            "evidence",
        }
        assert finding["severity"] in rules.SEVERITIES
        assert finding["category"] in rules.CATEGORIES
        assert finding["issue"] and finding["evidence"]
    assert {f["session_id"] for f in found} == {"S1", "S2"}


def test_compliance_issue_names_its_own_category():
    """Regression: the explainer keys on the issue text; it must say "compliant"."""
    found = rules.evaluate([dict(STRONG, encryption="3DES-CBC")])
    compliance = [f for f in found if f["category"] == "Compliance"]
    assert compliance and "compliant" in compliance[0]["issue"]


def test_lifetime_window_comes_from_config(monkeypatch):
    monkeypatch.setattr(config, "SA_LIFETIME_MAX_SECONDS", 3000)
    assert findings_for(lifetime_seconds=3600) == {("Lifetime", "Low")}


@pytest.mark.parametrize("sessions", [None, []])
def test_no_sessions(sessions):
    assert rules.evaluate(sessions) == []
