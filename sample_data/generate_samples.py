#!/usr/bin/env python3
"""Craft synthetic IPsec captures for the demo pipeline.

Three captures are produced:

  sample_weak.pcap    IPv4, IKEv1 Aggressive Mode, 3DES-CBC / MD5 / DH group 2,
                      pre-shared key, 48h lifetime, PFS off, exposed identity,
                      and ESP sequence numbers that regress (replay exposure).
  sample_strong.pcap  IPv4, IKEv2, AES-256-GCM / SHA-256 PRF / DH group 14,
                      RSA signature auth, PFS on via CREATE_CHILD_SA, ESN on,
                      monotonic ESP sequence numbers.
  sample_mixed.pcap   IPv6, IKEv1 Main Mode, AES-128-CBC / SHA-1 / DH group 5,
                      RSA auth, transport mode, 120s lifetime.

These are hand-built control-plane messages, not a real negotiation: the IKE
payloads that a live peer would encrypt are written in the clear so the parser
has something to read. ESP payloads are random bytes — nothing decrypts them and
nothing needs to.
"""

import os
import random

from scapy.contrib.ikev2 import (
    IKEv2,
    IKEv2_AUTH,
    IKEv2_Encrypted,
    IKEv2_KE,
    IKEv2_Nonce,
    IKEv2_Notify,
    IKEv2_Proposal,
    IKEv2_SA,
    IKEv2_Transform,
)
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP
from scapy.layers.isakmp import (
    ISAKMP,
    ISAKMP_payload_ID,
    ISAKMP_payload_KE,
    ISAKMP_payload_Nonce,
    ISAKMP_payload_Proposal,
    ISAKMP_payload_SA,
    ISAKMP_payload_Transform,
)
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(20260929)  # reproducible captures

ETHER = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")


def _stamp(packets, start, step):
    """Assign monotonically increasing capture timestamps."""
    t = start
    for pkt in packets:
        pkt.time = t
        t += step
    return packets


def _payload(target_total, header_bytes):
    """Random ESP payload sized so the framed packet lands near target_total."""
    size = max(16, target_total - header_bytes)
    return bytes(random.getrandbits(8) for _ in range(size))


# --------------------------------------------------------------------------
# weak: IPv4 / IKEv1 Aggressive Mode
# --------------------------------------------------------------------------

def build_weak():
    initiator, responder = "10.0.0.1", "203.0.113.9"
    icookie, rcookie = b"\xa1" * 8, b"\xb2" * 8
    packets = []

    # Aggressive mode message 1: SA + KE + Nonce + ID all in one unencrypted
    # message. This is the whole problem with aggressive mode.
    p1_transform = ISAKMP_payload_Transform(
        transform_id="KEY_IKE",
        transforms=[
            ("Encryption", "3DES-CBC"),
            ("Hash", "MD5"),
            ("GroupDesc", "1024MODPgr"),
            ("Authentication", "PSK"),
            ("LifeType", "Seconds"),
            ("LifeDuration", 172800),
        ],
    )
    sa = ISAKMP_payload_SA(
        prop=ISAKMP_payload_Proposal(proto="ISAKMP", trans=p1_transform)
    )
    msg1 = (
        ISAKMP(init_cookie=icookie, resp_cookie=b"\x00" * 8, exch_type=4, flags=0, id=0)
        / sa
        / ISAKMP_payload_KE(ke=b"\x5c" * 128)
        / ISAKMP_payload_Nonce(load=b"\x77" * 20)
        / ISAKMP_payload_ID(IDtype=2, IdentData=b"branch-office-gw.corp.example")  # 2 = FQDN
    )
    packets.append(ETHER / IP(src=initiator, dst=responder) / UDP(sport=500, dport=500) / msg1)

    msg2 = (
        ISAKMP(init_cookie=icookie, resp_cookie=rcookie, exch_type=4, flags=0, id=0)
        / sa
        / ISAKMP_payload_KE(ke=b"\x3d" * 128)
        / ISAKMP_payload_Nonce(load=b"\x88" * 20)
        / ISAKMP_payload_ID(IDtype=2, IdentData=b"hq-vpn-concentrator.corp.example")
    )
    packets.append(ETHER / IP(src=responder, dst=initiator) / UDP(sport=500, dport=500) / msg2)

    # Aggressive mode message 3 (hash only).
    msg3 = ISAKMP(init_cookie=icookie, resp_cookie=rcookie, exch_type=4, flags=0, id=0)
    packets.append(ETHER / IP(src=initiator, dst=responder) / UDP(sport=500, dport=500) / msg3)

    # Quick mode: no KE payload -> PFS was never requested.
    qm_transform = ISAKMP_payload_Transform(
        transform_id=3,  # ESP_3DES
        transforms=[
            ("EncapsulationMode", "Tunnel"),
            ("AuthenticationAlgorithm", "HMAC-MD5"),
            ("LifeType", "seconds"),
            ("LifeDuration", 172800),
        ],
    )
    qm = ISAKMP(
        init_cookie=icookie, resp_cookie=rcookie, exch_type=32, flags=0, id=0x1234
    ) / ISAKMP_payload_SA(
        prop=ISAKMP_payload_Proposal(
            proto="IPSEC_ESP", SPIsize=4, SPI=b"\xde\xad\xbe\xef", trans=qm_transform
        )
    )
    packets.append(ETHER / IP(src=initiator, dst=responder) / UDP(sport=500, dport=500) / qm)
    packets.append(ETHER / IP(src=responder, dst=initiator) / UDP(sport=500, dport=500) / qm)

    _stamp(packets, 1759100000.0, 0.035)

    # ESP data plane: small uniform packets at a steady cadence (VoIP-shaped),
    # with a sequence-number regression partway through.
    spi = 0xDEADBEEF
    esp = []
    seqs = list(range(1, 21)) + list(range(15, 35))  # regression at packet 21
    t = 1759100000.5
    for index, seq in enumerate(seqs):
        src, dst = (initiator, responder) if index % 2 == 0 else (responder, initiator)
        header = 14 + 20 + 8  # Ether + IPv4 + ESP header
        pkt = ETHER / IP(src=src, dst=dst, proto=50) / ESP(
            spi=spi, seq=seq, data=_payload(150, header)
        )
        pkt.time = t
        t += 0.020
        esp.append(pkt)

    # A little unrelated noise so `other_packets` is not always zero.
    noise = [
        ETHER / IP(src=initiator, dst="8.8.8.8") / UDP(sport=34567, dport=53) / (b"\x00" * 32),
        ETHER / IP(src="8.8.8.8", dst=initiator) / UDP(sport=53, dport=34567) / (b"\x00" * 48),
    ]
    _stamp(noise, 1759100001.5, 0.01)

    return packets + esp + noise


# --------------------------------------------------------------------------
# strong: IPv4 / IKEv2
# --------------------------------------------------------------------------

def build_strong():
    initiator, responder = "192.168.50.1", "198.51.100.20"
    ispi, rspi = b"\xc1" * 8, b"\xd2" * 8
    packets = []

    # AEAD suite: AES-GCM-16ICV with a 256-bit key, SHA2-256 PRF, DH group 14.
    # No separate integrity transform, which is correct for an AEAD cipher.
    # length=12 is required whenever a key-length attribute is attached: Scapy
    # only emits `key_length` when `length > 8`, and never computes it for us.
    ike_transforms = (
        IKEv2_Transform(transform_type="Encryption", transform_id=20,
                        key_length=256, length=12)
        / IKEv2_Transform(transform_type="PRF", transform_id=5)
        / IKEv2_Transform(transform_type="GroupDesc", transform_id=14, next_payload=0)
    )
    sa_init = IKEv2_SA(
        prop=IKEv2_Proposal(proposal=1, proto="IKE", trans_nb=3, trans=ike_transforms)
    )

    msg1 = (
        IKEv2(init_SPI=ispi, resp_SPI=b"\x00" * 8, exch_type="IKE_SA_INIT", flags="Initiator")
        / sa_init
        / IKEv2_KE(group=14, ke=b"\x41" * 256)
        / IKEv2_Nonce(nonce=b"\x52" * 32)
        / IKEv2_Notify(type=16388, notify=b"\x61" * 20)  # NAT_DETECTION_SOURCE_IP
    )
    packets.append(ETHER / IP(src=initiator, dst=responder) / UDP(sport=500, dport=500) / msg1)

    msg2 = (
        IKEv2(init_SPI=ispi, resp_SPI=rspi, exch_type="IKE_SA_INIT", flags="Response")
        / sa_init
        / IKEv2_KE(group=14, ke=b"\x43" * 256)
        / IKEv2_Nonce(nonce=b"\x54" * 32)
    )
    packets.append(ETHER / IP(src=responder, dst=initiator) / UDP(sport=500, dport=500) / msg2)

    # IKE_AUTH. A real peer wraps everything after the header in an SK payload;
    # the AUTH payload is written alongside an encrypted payload here so the
    # parser can read the authentication method while still seeing that the
    # identity payloads were protected.
    msg3 = (
        IKEv2(init_SPI=ispi, resp_SPI=rspi, exch_type="IKE_AUTH", flags="Initiator", id=1)
        / IKEv2_AUTH(auth_type=1, load=b"\x71" * 128)  # RSA Digital Signature
        / IKEv2_Encrypted(load=b"\x82" * 160)
    )
    packets.append(ETHER / IP(src=initiator, dst=responder) / UDP(sport=500, dport=500) / msg3)

    msg4 = (
        IKEv2(init_SPI=ispi, resp_SPI=rspi, exch_type="IKE_AUTH", flags="Response", id=1)
        / IKEv2_AUTH(auth_type=1, load=b"\x73" * 128)
        / IKEv2_Encrypted(load=b"\x84" * 160)
    )
    packets.append(ETHER / IP(src=responder, dst=initiator) / UDP(sport=500, dport=500) / msg4)

    # CREATE_CHILD_SA carrying a fresh KE payload: this is PFS.
    child_transforms = (
        IKEv2_Transform(transform_type="Encryption", transform_id=20,
                        key_length=256, length=12)
        / IKEv2_Transform(transform_type="GroupDesc", transform_id=14)
        / IKEv2_Transform(transform_type="Extended Sequence Number", transform_id=1, next_payload=0)
    )
    child = (
        IKEv2(init_SPI=ispi, resp_SPI=rspi, exch_type="CREATE_CHILD_SA", flags="Initiator", id=2)
        / IKEv2_SA(
            prop=IKEv2_Proposal(
                proposal=1, proto="ESP", SPIsize=4, SPI=b"\xca\xfe\xf0\x0d",
                trans_nb=3, trans=child_transforms,
            )
        )
        / IKEv2_KE(group=14, ke=b"\x45" * 256)
        / IKEv2_Nonce(nonce=b"\x56" * 32)
    )
    packets.append(ETHER / IP(src=initiator, dst=responder) / UDP(sport=500, dport=500) / child)
    packets.append(ETHER / IP(src=responder, dst=initiator) / UDP(sport=500, dport=500) / child)

    _stamp(packets, 1759200000.0, 0.030)

    # ESP data plane: near-MTU packets back to back, strongly upstream —
    # a bulk transfer shape.
    spi = 0xCAFEF00D
    esp = []
    t = 1759200000.4
    for index in range(60):
        upstream = index % 7 != 0
        src, dst = (initiator, responder) if upstream else (responder, initiator)
        target = 1420 if upstream else 110
        header = 14 + 20 + 8
        pkt = ETHER / IP(src=src, dst=dst, proto=50) / ESP(
            spi=spi, seq=index + 1, data=_payload(target, header)
        )
        pkt.time = t
        t += 0.003
        esp.append(pkt)

    return packets + esp


# --------------------------------------------------------------------------
# mixed: IPv6 / IKEv1 Main Mode, transport mode
# --------------------------------------------------------------------------

def build_mixed():
    initiator, responder = "2001:db8::1", "2001:db8:100::20"
    icookie, rcookie = b"\xe5" * 8, b"\xf6" * 8
    packets = []

    p1_transform = ISAKMP_payload_Transform(
        transform_id="KEY_IKE",
        transforms=[
            ("Encryption", "AES-CBC"),
            ("KeyLength", 128),
            ("Hash", "SHA"),
            ("GroupDesc", "1536MODPgr"),
            ("Authentication", "RSA Sig"),
            ("LifeType", "Seconds"),
            ("LifeDuration", 120),
        ],
    )
    sa = ISAKMP_payload_SA(
        prop=ISAKMP_payload_Proposal(proto="ISAKMP", trans=p1_transform)
    )

    # Main mode messages 1-2: SA proposal, identities not yet sent.
    packets.append(
        ETHER / IPv6(src=initiator, dst=responder) / UDP(sport=500, dport=500)
        / (ISAKMP(init_cookie=icookie, resp_cookie=b"\x00" * 8, exch_type=2, flags=0) / sa)
    )
    packets.append(
        ETHER / IPv6(src=responder, dst=initiator) / UDP(sport=500, dport=500)
        / (ISAKMP(init_cookie=icookie, resp_cookie=rcookie, exch_type=2, flags=0) / sa)
    )
    # Messages 3-4: key exchange.
    packets.append(
        ETHER / IPv6(src=initiator, dst=responder) / UDP(sport=500, dport=500)
        / (
            ISAKMP(init_cookie=icookie, resp_cookie=rcookie, exch_type=2, flags=0)
            / ISAKMP_payload_KE(ke=b"\x31" * 192)
            / ISAKMP_payload_Nonce(load=b"\x32" * 20)
        )
    )
    packets.append(
        ETHER / IPv6(src=responder, dst=initiator) / UDP(sport=500, dport=500)
        / (
            ISAKMP(init_cookie=icookie, resp_cookie=rcookie, exch_type=2, flags=0)
            / ISAKMP_payload_KE(ke=b"\x33" * 192)
            / ISAKMP_payload_Nonce(load=b"\x34" * 20)
        )
    )
    # Messages 5-6: identities, sent with the encryption flag set. Main mode
    # protects them, so identity_exposed must come out False.
    packets.append(
        ETHER / IPv6(src=initiator, dst=responder) / UDP(sport=500, dport=500)
        / (
            ISAKMP(init_cookie=icookie, resp_cookie=rcookie, exch_type=2, flags=1)
            / ISAKMP_payload_ID(IDtype=5, IdentData=b"\x20\x01\x0d\xb8" + b"\x00" * 12)
        )
    )

    # Quick mode with a DH group (PFS on) and transport-mode encapsulation.
    qm_transform = ISAKMP_payload_Transform(
        transform_id=12,  # ESP_AES
        transforms=[
            ("EncapsulationMode", "Transport"),
            ("AuthenticationAlgorithm", "HMAC-SHA"),
            ("GroupDesc", "1536MODPgr"),
            ("KeyLength", 128),
            ("LifeType", "seconds"),
            ("LifeDuration", 120),
        ],
    )
    qm = ISAKMP(
        init_cookie=icookie, resp_cookie=rcookie, exch_type=32, flags=0, id=0x9911
    ) / ISAKMP_payload_SA(
        prop=ISAKMP_payload_Proposal(
            proto="IPSEC_ESP", SPIsize=4, SPI=b"\x0b\xad\xf0\x0d", trans=qm_transform
        )
    )
    packets.append(ETHER / IPv6(src=initiator, dst=responder) / UDP(sport=500, dport=500) / qm)

    _stamp(packets, 1759300000.0, 0.040)

    # ESP data plane: wide size spread, irregular gaps, downstream-skewed —
    # a web browsing shape. Sequence numbers are clean.
    spi = 0x0BADF00D
    esp = []
    t = 1759300000.6
    for index in range(34):
        downstream = index % 3 != 0
        src, dst = (responder, initiator) if downstream else (initiator, responder)
        target = random.choice([1380, 1200, 900, 640, 320, 180])
        header = 14 + 40 + 8  # Ether + IPv6 + ESP header
        pkt = ETHER / IPv6(src=src, dst=dst, nh=50) / ESP(
            spi=spi, seq=index + 1, data=_payload(target, header)
        )
        pkt.time = t
        t += random.uniform(0.04, 0.30)
        esp.append(pkt)

    return packets + esp


def main():
    for name, builder in (
        ("sample_weak.pcap", build_weak),
        ("sample_strong.pcap", build_strong),
        ("sample_mixed.pcap", build_mixed),
    ):
        path = os.path.join(HERE, name)
        packets = builder()
        wrpcap(path, packets)
        print("[samples] wrote %s (%d packets)" % (path, len(packets)))


if __name__ == "__main__":
    main()
