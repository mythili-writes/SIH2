"""Parser: crafted synthetic captures in, extracted Contract A fields out."""

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.ipsec import AH
from scapy.layers.l2 import Ether

import pcaps
from ai_engine.test_data.check_contract_a import check_contract_a
from backend import parser
from backend.main import analyze

WEAK_P1 = [
    ("Encryption", "3DES-CBC"),
    ("Hash", "MD5"),
    ("GroupDesc", "1024MODPgr"),
    ("Authentication", "PSK"),
    ("LifeType", "Seconds"),
    ("LifeDuration", 172800),
]


def only_session(path):
    """Parse a capture expected to hold exactly one session and return it."""
    analysis = parser.parse_pcap(path)
    assert len(analysis["sessions"]) == 1, analysis["sessions"]
    return analysis["sessions"][0]


# --------------------------------------------------------------------------
# IKEv1
# --------------------------------------------------------------------------


def test_ikev1_aggressive_mode_weak_session(tmp_path):
    packets = [
        pcaps.udp500(pcaps.isakmp_phase1(WEAK_P1, exch_type=4, payloads=[pcaps.id_payload()])),
        pcaps.udp500(
            pcaps.isakmp_quick_mode(
                [("EncapsulationMode", "Tunnel"), ("AuthenticationAlgorithm", "HMAC-MD5")]
            )
        ),
    ] + [pcaps.esp(seq) for seq in range(1, 6)]
    session = only_session(pcaps.write(tmp_path / "weak.pcap", packets))

    assert session["protocol"] == "IKEv1"
    assert session["exchange_mode"] == "Aggressive"
    assert session["encryption"] == "3DES-CBC"
    assert session["hash"] == "MD5"
    assert session["authentication"] == "HMAC-MD5"
    assert session["dh_group"] == 2
    assert session["key_exchange"] == "Diffie-Hellman"
    assert session["auth_method"] == "Pre-Shared Key"
    assert session["lifetime_seconds"] == 172800
    assert session["pfs_enabled"] is False  # readable quick mode, no KE payload
    assert session["identity_exposed"] is True  # ID payload sent in the clear
    assert session["nat_traversal"] is False
    assert session["ipsec_mode"] == "Tunnel"
    assert session["ipsec_protocol"] == "ESP"
    assert session["replay_protection"] is True


def test_aes_key_length_attribute_is_folded_into_the_cipher_name(tmp_path):
    transforms = [("Encryption", "AES-CBC"), ("KeyLength", 256), ("Hash", "SHA2-256")]
    session = only_session(pcaps.write(tmp_path / "a.pcap", [pcaps.udp500(pcaps.isakmp_phase1(transforms))]))
    assert session["encryption"] == "AES-256-CBC"
    assert session["hash"] == "SHA256"


def test_main_mode_identity_is_protected(tmp_path):
    packets = [
        pcaps.udp500(pcaps.isakmp_phase1(WEAK_P1, exch_type=2)),
        # Message 5: the ID payload rides in an encrypted message (flags bit 0).
        pcaps.udp500(pcaps.isakmp_phase1(WEAK_P1, exch_type=2, flags=1, payloads=[pcaps.id_payload()])),
    ]
    session = only_session(pcaps.write(tmp_path / "m.pcap", packets))
    assert session["exchange_mode"] == "Main"
    assert session["identity_exposed"] is False


@pytest.mark.parametrize(
    "quick_mode",
    [
        pcaps.isakmp_quick_mode([("EncapsulationMode", "Tunnel")], with_ke=True),
        pcaps.isakmp_quick_mode([("EncapsulationMode", "Tunnel"), ("GroupDesc", "2048MODPgr")]),
    ],
    ids=["KE payload", "DH group in proposal"],
)
def test_pfs_detected_in_quick_mode(tmp_path, quick_mode):
    packets = [pcaps.udp500(pcaps.isakmp_phase1(WEAK_P1)), pcaps.udp500(quick_mode)]
    assert only_session(pcaps.write(tmp_path / "p.pcap", packets))["pfs_enabled"] is True


def test_transport_mode_from_quick_mode_attribute(tmp_path):
    packets = [pcaps.udp500(pcaps.isakmp_quick_mode([("EncapsulationMode", "Transport")]))]
    assert only_session(pcaps.write(tmp_path / "t.pcap", packets))["ipsec_mode"] == "Transport"


# --------------------------------------------------------------------------
# IKEv2
# --------------------------------------------------------------------------

STRONG_V2 = [
    pcaps.v2_transform("Encryption", 20, key_length=256),  # AES-GCM-16ICV
    pcaps.v2_transform("PRF", 5),  # PRF_HMAC_SHA2_256
    pcaps.v2_transform("GroupDesc", 14),
]


def test_ikev2_aead_suite(tmp_path):
    session = only_session(pcaps.write(tmp_path / "v2.pcap", [pcaps.udp500(pcaps.ikev2_sa_init(STRONG_V2))]))
    assert session["protocol"] == "IKEv2"
    assert session["exchange_mode"] == "IKE_SA_INIT"
    assert session["encryption"] == "AES-256-GCM"
    assert session["hash"] == "SHA256"  # from the PRF: AEAD suites carry no integrity transform
    assert session["dh_group"] == 14
    assert session["ipsec_mode"] == "Tunnel"  # RFC 7296 default without USE_TRANSPORT_MODE
    assert session["identity_exposed"] is False  # IDi/IDr ride inside SK in IKEv2
    assert session["ipsec_protocol"] == "Unknown"  # IKE only: no data plane, no child SA


def test_ikev2_use_transport_mode_notify(tmp_path):
    msg = pcaps.ikev2_sa_init(STRONG_V2, notify=16391)
    assert only_session(pcaps.write(tmp_path / "n.pcap", [pcaps.udp500(msg)]))["ipsec_mode"] == "Transport"


def test_ikev2_identity_in_the_clear_is_exposed(tmp_path):
    msg = pcaps.ikev2_sa_init(STRONG_V2, idi=True)
    assert only_session(pcaps.write(tmp_path / "i.pcap", [pcaps.udp500(msg)]))["identity_exposed"] is True


def test_ecp_group_is_named_ecdh(tmp_path):
    transforms = [pcaps.v2_transform("Encryption", 20, 256), pcaps.v2_transform("GroupDesc", 19)]
    session = only_session(pcaps.write(tmp_path / "e.pcap", [pcaps.udp500(pcaps.ikev2_sa_init(transforms))]))
    assert (session["dh_group"], session["key_exchange"]) == (19, "ECDH")


# --------------------------------------------------------------------------
# transport, classification, data plane
# --------------------------------------------------------------------------


def test_nat_traversal_on_udp_4500(tmp_path):
    path = pcaps.write(tmp_path / "nat.pcap", [pcaps.udp4500(pcaps.isakmp_phase1(WEAK_P1))])
    analysis = parser.parse_pcap(path)
    assert analysis["packet_summary"]["ike_packets"] == 1
    assert analysis["sessions"][0]["nat_traversal"] is True


def test_packet_classification_counts(tmp_path):
    packets = [
        pcaps.udp500(pcaps.isakmp_phase1(WEAK_P1)),
        pcaps.esp(1),
        pcaps.esp(2),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=51) / AH(spi=5, seq=1),
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5353, dport=53),
        # UDP/4500 without the non-ESP marker is UDP-encapsulated ESP, not IKE.
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=4500, dport=4500) / (b"\x00\x00\x10\x01" + b"\x00\x00\x00\x03" + b"x" * 40),
    ]
    analysis = parser.parse_pcap(pcaps.write(tmp_path / "mix.pcap", packets))
    assert analysis["packet_summary"] == {
        "ike_packets": 1,
        "esp_packets": 3,
        "ah_packets": 1,
        "other_packets": 1,
    }
    assert analysis["total_packets"] == 6
    assert analysis["sessions"][0]["ipsec_protocol"] == "ESP+AH"


@pytest.mark.parametrize(
    "addresses, version",
    [((pcaps.A6, pcaps.B6), "IPv6"), ((pcaps.A, pcaps.B), "IPv4")],
)
def test_ip_version(tmp_path, addresses, version):
    packets = [pcaps.esp(1, src=addresses[0], dst=addresses[1])]
    assert parser.parse_pcap(pcaps.write(tmp_path / "v.pcap", packets))["ip_version"] == version


def test_mixed_ip_versions(tmp_path):
    packets = [pcaps.esp(1), pcaps.esp(1, src=pcaps.A6, dst=pcaps.B6)]
    analysis = parser.parse_pcap(pcaps.write(tmp_path / "x.pcap", packets))
    assert analysis["ip_version"] == "Mixed"
    assert len(analysis["sessions"]) == 2


@pytest.mark.parametrize(
    "seqs, expected",
    [
        ([1, 2, 3, 4], True),
        ([1, 2, 3, 2, 5], False),  # regression
        ([1, 2, 2, 3], False),  # repeat
        ([7], None),  # one packet proves nothing
    ],
)
def test_replay_protection_from_sequence_numbers(tmp_path, seqs, expected):
    packets = [pcaps.esp(seq) for seq in seqs]
    assert only_session(pcaps.write(tmp_path / "r.pcap", packets))["replay_protection"] is expected


def test_sequence_numbers_are_judged_per_spi(tmp_path):
    packets = [pcaps.esp(1, spi=1), pcaps.esp(1, spi=2), pcaps.esp(2, spi=1), pcaps.esp(2, spi=2)]
    assert only_session(pcaps.write(tmp_path / "s.pcap", packets))["replay_protection"] is True


def test_traffic_features_arithmetic(tmp_path):
    # A -> B 100 bytes, B -> A 200 bytes, twice; 20 ms apart.
    packets = [
        pcaps.esp(1, size=100),
        pcaps.esp(1, size=200, src=pcaps.B, dst=pcaps.A, spi=0x2002),
        pcaps.esp(2, size=100),
        pcaps.esp(2, size=200, src=pcaps.B, dst=pcaps.A, spi=0x2002),
    ]
    features = only_session(pcaps.write(tmp_path / "f.pcap", packets, step=0.02))["traffic_features"]
    assert features["packet_count"] == 4
    assert features["avg_packet_size"] == 150.0
    assert (features["min_packet_size"], features["max_packet_size"]) == (100, 200)
    assert features["avg_inter_arrival_ms"] == pytest.approx(20.0, abs=0.01)
    assert features["duration_seconds"] == pytest.approx(0.06, abs=1e-4)
    assert features["bytes_total"] == 600
    assert features["upstream_ratio"] == pytest.approx(200 / 600, abs=1e-4)  # initiator A sent 200


def test_esp_only_session_is_low_confidence_and_unknown(tmp_path):
    session = only_session(pcaps.write(tmp_path / "o.pcap", [pcaps.esp(s) for s in range(1, 4)]))
    assert session["protocol"] == "Unknown"
    assert session["encryption"] == "Unknown"
    assert session["key_exchange"] == "Unknown"
    assert session["ipsec_protocol"] == "ESP"
    assert session["confidence"] <= 0.35


# --------------------------------------------------------------------------
# the bundled samples, end to end through the backend
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["weak", "mixed", "strong"])
def test_samples_conform_to_contract_a(sample_path, name):
    assert check_contract_a(analyze(sample_path(name))) == []


def test_sample_fields(sample_path):
    weak = analyze(sample_path("weak"))["sessions"][0]
    mixed = analyze(sample_path("mixed"))
    strong = analyze(sample_path("strong"))["sessions"][0]

    assert (weak["encryption"], weak["dh_group"], weak["replay_protection"]) == ("3DES-CBC", 2, False)
    assert mixed["ip_version"] == "IPv6"
    assert mixed["sessions"][0]["ipsec_mode"] == "Transport"
    assert mixed["sessions"][0]["lifetime_seconds"] == 120
    assert (strong["encryption"], strong["authentication"], strong["pfs_enabled"]) == (
        "AES-256-GCM",
        "AEAD",
        True,
    )


def test_sample_finding_counts(sample_path):
    counts = {name: len(analyze(sample_path(name))["findings"]) for name in ("weak", "mixed", "strong")}
    assert counts == {"weak": 10, "mixed": 7, "strong": 0}
