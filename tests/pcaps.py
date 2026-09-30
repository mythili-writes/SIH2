"""Small builders for synthetic captures used by the parser tests.

Each helper returns Scapy packets; write() turns a list of them into a pcap
with deterministic timestamps. They are deliberately minimal: one test, one
behaviour.
"""

import importlib.util
import os

from scapy.contrib.ikev2 import (
    IKEv2,
    IKEv2_IDi,
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
    ISAKMP_payload_Proposal,
    ISAKMP_payload_SA,
    ISAKMP_payload_Transform,
)
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

A, B = "10.0.0.1", "10.0.0.2"
A6, B6 = "2001:db8::1", "2001:db8::2"


def ip(src=A, dst=B):
    """IPv4 or IPv6 header, chosen from the address family."""
    return IPv6(src=src, dst=dst) if ":" in src else IP(src=src, dst=dst)


def isakmp_phase1(transforms, exch_type=2, flags=0, payloads=()):
    """An IKEv1 message carrying one phase 1 (ISAKMP) proposal."""
    sa = ISAKMP_payload_SA(
        prop=ISAKMP_payload_Proposal(
            proto="ISAKMP",
            trans=ISAKMP_payload_Transform(transform_id="KEY_IKE", transforms=transforms),
        )
    )
    msg = ISAKMP(init_cookie=b"\x11" * 8, resp_cookie=b"\x00" * 8, exch_type=exch_type, flags=flags)
    msg = msg / sa
    for payload in payloads:
        msg = msg / payload
    return msg


def isakmp_quick_mode(transforms, with_ke=False):
    """An IKEv1 quick mode message with one ESP proposal."""
    msg = ISAKMP(
        init_cookie=b"\x11" * 8, resp_cookie=b"\x22" * 8, exch_type=32, flags=0, id=7
    ) / ISAKMP_payload_SA(
        prop=ISAKMP_payload_Proposal(
            proto="IPSEC_ESP",
            SPIsize=4,
            SPI=b"\x00\x00\x10\x01",
            trans=ISAKMP_payload_Transform(transform_id=12, transforms=transforms),
        )
    )
    if with_ke:
        msg = msg / ISAKMP_payload_KE(ke=b"\x01" * 128)
    return msg


def id_payload(data=b"gw.example"):
    """An IKEv1 ID payload (type 2 = FQDN)."""
    return ISAKMP_payload_ID(IDtype=2, IdentData=data)


def ikev2_sa_init(transforms, notify=None, idi=False):
    """An IKEv2 IKE_SA_INIT with one IKE proposal, optionally a notify or a clear IDi."""
    chain = transforms[0]
    for transform in transforms[1:]:
        chain = chain / transform
    msg = IKEv2(init_SPI=b"\x33" * 8, resp_SPI=b"\x00" * 8, exch_type="IKE_SA_INIT")
    msg = msg / IKEv2_SA(prop=IKEv2_Proposal(proposal=1, proto="IKE", trans_nb=len(transforms), trans=chain))
    if notify is not None:
        msg = msg / IKEv2_Notify(type=notify)
    if idi:
        msg = msg / IKEv2_IDi(IDtype=2, ID=b"client.example")
    return msg


def v2_transform(kind, tid, key_length=None):
    """IKEv2 transform; a key length needs length=12 because Scapy never sizes it."""
    if key_length is None:
        return IKEv2_Transform(transform_type=kind, transform_id=tid)
    return IKEv2_Transform(transform_type=kind, transform_id=tid, key_length=key_length, length=12)


def udp500(msg, src=A, dst=B):
    """IKE on UDP/500."""
    return Ether() / ip(src, dst) / UDP(sport=500, dport=500) / msg


def udp4500(msg, src=A, dst=B):
    """IKE on UDP/4500 behind the four-byte non-ESP marker (NAT traversal)."""
    return Ether() / ip(src, dst) / UDP(sport=4500, dport=4500) / Raw(b"\x00" * 4 + bytes(msg))


def esp(seq, size=150, src=A, dst=B, spi=0x1001):
    """An ESP packet whose frame is exactly `size` bytes long."""
    header = 14 + (40 if ":" in src else 20) + 8
    nh = {"nh": 50} if ":" in src else {"proto": 50}
    layer = IPv6(src=src, dst=dst, **nh) if ":" in src else IP(src=src, dst=dst, **nh)
    return Ether() / layer / ESP(spi=spi, seq=seq, data=b"\x00" * max(0, size - header))


def write(path, packets, start=1_700_000_000.0, step=0.02):
    """Write packets with evenly spaced timestamps and return the path."""
    for index, packet in enumerate(packets):
        packet.time = start + index * step
    wrpcap(str(path), packets)
    return str(path)


def load_sample_generator():
    """Import sample_data/generate_samples.py (it is not a package) for its builders."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "sample_data", "generate_samples.py")
    spec = importlib.util.spec_from_file_location("generate_samples", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
