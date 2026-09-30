"""Capture validation: bad files are rejected with a clear reason, damaged ones analysed honestly."""

import gzip
import struct

import pytest
from scapy.utils import wrpcapng

import config
import pcaps
from backend import parser
from backend.parser import CaptureError


@pytest.fixture
def good_pcap(tmp_path):
    """A small valid classic pcap: one IKE packet and five ESP packets."""
    packets = [pcaps.udp500(pcaps.isakmp_phase1([("Encryption", "3DES-CBC")]))]
    packets += [pcaps.esp(seq) for seq in range(1, 6)]
    return pcaps.write(tmp_path / "good.pcap", packets)


def reject_reason(path):
    """The CaptureError message for `path`; fails the test if it is accepted."""
    with pytest.raises(CaptureError) as info:
        parser.parse_pcap(str(path))
    return str(info.value)


def test_valid_pcap_has_no_warnings(good_pcap):
    analysis = parser.parse_pcap(good_pcap)
    assert analysis["total_packets"] == 6
    assert analysis["parse_warnings"] == []


def test_pcapng_is_accepted(tmp_path, good_pcap):
    from scapy.utils import rdpcap

    path = tmp_path / "good.pcapng"
    wrpcapng(str(path), rdpcap(good_pcap))
    assert parser.validate_capture(str(path)) == "pcapng"
    assert parser.parse_pcap(str(path))["total_packets"] == 6


@pytest.mark.parametrize(
    "content, reason",
    [
        (b"hello, this is not a capture at all" * 4, "not a pcap or pcapng file"),
        (b"", "the file is empty"),
        (gzip.compress(b"x" * 100), "gzip-compressed"),
        (b"PK\x03\x04" + b"\x00" * 60, "zip archive"),
        (b"\xd4\xc3\xb2\xa1\x02\x00", "pcap file header is truncated"),
        (b"\x0a\x0d\x0d\x0a" + b"\x00" * 20, "pcapng section header is malformed"),
    ],
)
def test_rejected_with_a_clear_reason(tmp_path, content, reason):
    path = tmp_path / "input.pcap"
    path.write_bytes(content)
    assert reason in reject_reason(path)


def test_missing_file(tmp_path):
    assert reject_reason(tmp_path / "nope.pcap") == "file not found"


def test_file_size_limit(monkeypatch, good_pcap):
    monkeypatch.setattr(config, "MAX_CAPTURE_BYTES", 100)
    assert "the limit is" in reject_reason(good_pcap)


def test_truncated_capture_analyses_the_intact_packets(tmp_path, good_pcap):
    data = open(good_pcap, "rb").read()
    path = tmp_path / "cut.pcap"
    path.write_bytes(data[:-30])  # cut the last packet short

    analysis = parser.parse_pcap(str(path))
    assert analysis["total_packets"] == 5
    assert "truncated partway through packet 6" in analysis["parse_warnings"][0]


def test_corrupt_record_length_stops_at_the_last_good_packet(tmp_path, good_pcap):
    data = bytearray(open(good_pcap, "rb").read())
    first_len = struct.unpack("<I", data[32:36])[0]
    second = 24 + 16 + first_len
    data[second + 8 : second + 12] = struct.pack("<I", 0x7FFFFFFF)
    path = tmp_path / "corrupt.pcap"
    path.write_bytes(bytes(data))

    analysis = parser.parse_pcap(str(path))
    assert analysis["total_packets"] == 1
    assert "impossible length" in analysis["parse_warnings"][0]


@pytest.mark.parametrize("fmt", ["pcap", "pcapng"])
def test_packet_limit(monkeypatch, tmp_path, good_pcap, fmt):
    from scapy.utils import rdpcap

    path = good_pcap
    if fmt == "pcapng":
        path = str(tmp_path / "good.pcapng")
        wrpcapng(path, rdpcap(good_pcap))
    monkeypatch.setattr(config, "MAX_PACKETS", 3)

    analysis = parser.parse_pcap(path)
    assert analysis["total_packets"] == 3
    assert "IPSEC_MAX_PACKETS" in analysis["parse_warnings"][0]


def test_header_only_capture(tmp_path, good_pcap):
    path = tmp_path / "empty.pcap"
    path.write_bytes(open(good_pcap, "rb").read()[:24])
    analysis = parser.parse_pcap(str(path))
    assert analysis["sessions"] == []
    assert analysis["parse_warnings"] == ["The capture contains no packets."]


def test_capture_without_ipsec_traffic(tmp_path):
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    packets = [Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53) for _ in range(3)]
    analysis = parser.parse_pcap(pcaps.write(tmp_path / "dns.pcap", packets))
    assert analysis["sessions"] == []
    assert "No IKE, ESP or AH traffic" in analysis["parse_warnings"][0]


def test_a_packet_that_fails_to_dissect_is_skipped(monkeypatch, good_pcap):
    real = parser._process_packet
    calls = {"n": 0}

    def flaky(*args):
        calls["n"] += 1
        if calls["n"] == 2:
            raise ValueError("malformed packet")
        return real(*args)

    monkeypatch.setattr(parser, "_process_packet", flaky)
    analysis = parser.parse_pcap(good_pcap)
    assert analysis["total_packets"] == 6
    assert analysis["packet_summary"]["esp_packets"] == 4  # the failed one is not counted twice
    assert "1 packet(s) could not be dissected" in analysis["parse_warnings"][0]
