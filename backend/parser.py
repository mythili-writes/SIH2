"""PCAP -> Contract A session/parameter extraction.

Reads a capture with Scapy, splits packets into IKE (UDP 500/4500), ESP
(IP proto 50), AH (IP proto 51) and other, then reconstructs one logical IPsec
session per peer pair across both IPv4 and IPv6.

Design rule: never crash on a capture. Anything that cannot be determined from
the bytes on the wire is reported as "Unknown" (or None for booleans/numbers)
and lowers the session's confidence score. No key is ever omitted.

ESP payloads are encrypted and are never inspected — traffic_features are
derived purely from packet size, timing and direction.
"""

import os
import struct

from scapy.all import rdpcap
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import AH, ESP
from scapy.layers.isakmp import (
    ISAKMP,
    ISAKMP_payload_ID,
    ISAKMP_payload_KE,
    ISAKMP_payload_Proposal,
    ISAKMP_payload_SA,
    ISAKMP_payload_Transform,
)

try:
    import scapy.contrib.ikev2 as ikev2
    HAVE_IKEV2 = True
except Exception:  # pragma: no cover - contrib module should always be present
    ikev2 = None
    HAVE_IKEV2 = False

UNKNOWN = "Unknown"

IKE_PORTS = (500, 4500)

# IKEv1 ISAKMP exchange types -> human label.
IKEV1_EXCHANGE = {
    1: "Base",
    2: "Main",            # "identity protection"
    3: "Authentication Only",
    4: "Aggressive",
    5: "Informational",
    32: "Quick Mode",
    33: "New Group Mode",
}

# Scapy's DH group labels -> numeric group id.
DH_LABEL_TO_NUM = {
    "768MODPgr": 1,
    "1024MODPgr": 2,
    "EC2Ngr155": 3,
    "EC2Ngr185": 4,
    "1536MODPgr": 5,
    "2048MODPgr": 14,
    "3072MODPgr": 15,
    "4096MODPgr": 16,
    "6144MODPgr": 17,
    "8192MODPgr": 18,
    "256randECPgr": 19,
    "384randECPgr": 20,
    "521randECPgr": 21,
    "1024MODP160POSgr": 22,
    "2048MODP224POSgr": 23,
    "2048MODP256POSgr": 24,
    "192randECPgr": 25,
    "224randECPgr": 26,
    "curve25519gr": 31,
    "curve448gr": 32,
}

# IKEv1 ISAKMP encryption labels -> canonical cipher name for the rule engine.
IKEV1_ENC = {
    "DES-CBC": "DES-CBC",
    "IDEA-CBC": "IDEA-CBC",
    "Blowfish-CBC": "BLOWFISH-CBC",
    "RC5-R16-B64-CBC": "RC5-CBC",
    "3DES-CBC": "3DES-CBC",
    "CAST-CBC": "CAST-CBC",
    "AES-CBC": "AES-CBC",
    "CAMELLIA-CBC": "CAMELLIA-CBC",
}

IKEV1_HASH = {
    "MD5": "MD5",
    "SHA": "SHA1",
    "Tiger": "TIGER",
    "SHA2-256": "SHA256",
    "SHA2-384": "SHA384",
    "SHA2-512": "SHA512",
}

IKEV1_AUTH = {
    "PSK": "Pre-Shared Key",
    "DSS": "DSS Digital Signature",
    "RSA Sig": "RSA Digital Signature",
    "RSA Encryption": "RSA Encryption",
    "RSA Encryption Revised": "RSA Encryption",
    "ECDSA Sig": "ECDSA Digital Signature",
}

# IKEv1 phase-2 (IPSEC DOI) integrity labels.
IPSEC_AUTH_ALG = {
    "HMAC-MD5": "MD5",
    "HMAC-SHA": "SHA1",
    "HMAC-SHA2-256": "SHA256",
    "HMAC-SHA2-384": "SHA384",
    "HMAC-SHA2-512": "SHA512",
    "AES-XCBC-MAC": "AES-XCBC",
}

# IKEv2 transform-type 1 (encryption) ids that are AEAD and need no integrity alg.
IKEV2_AEAD = {14, 15, 16, 18, 19, 20, 25, 26, 27, 28}

IKEV2_INTEG = {
    1: "MD5",
    2: "SHA1",
    3: "DES-MAC",
    4: "MD5",
    5: "AES-XCBC",
    6: "MD5",
    7: "SHA1",
    8: "AES-CMAC",
    9: "AES-128-GMAC",
    10: "AES-192-GMAC",
    11: "AES-256-GMAC",
    12: "SHA256",
    13: "SHA384",
    14: "SHA512",
}

# Contract A "authentication": the ESP/AH integrity algorithm, named like the
# canonical test data ("HMAC-MD5", "HMAC-SHA256").
IPSEC_INTEGRITY_NAME = {
    "HMAC-MD5": "HMAC-MD5",
    "HMAC-SHA": "HMAC-SHA1",
    "HMAC-SHA2-256": "HMAC-SHA256",
    "HMAC-SHA2-384": "HMAC-SHA384",
    "HMAC-SHA2-512": "HMAC-SHA512",
    "AES-XCBC-MAC": "AES-XCBC",
}

IKEV2_INTEG_NAME = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    3: "DES-MAC",
    4: "KPDK-MD5",
    5: "AES-XCBC",
    6: "HMAC-MD5",
    7: "HMAC-SHA1",
    8: "AES-CMAC",
    9: "AES-128-GMAC",
    10: "AES-192-GMAC",
    11: "AES-256-GMAC",
    12: "HMAC-SHA256",
    13: "HMAC-SHA384",
    14: "HMAC-SHA512",
}

# An AEAD cipher (AES-GCM, AES-CCM, ChaCha20-Poly1305) carries its own integrity
# check, so no separate integrity transform is negotiated.
AEAD_INTEGRITY = "AEAD"

# DH groups on elliptic curves; every other known group is classic MODP.
ECP_GROUPS = {19, 20, 21, 25, 26, 27, 28, 29, 30, 31, 32}

NOTIFY_USE_TRANSPORT_MODE = 16391
NOTIFY_NAT_DETECTION = (16388, 16389)


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def _ip_layer(pkt):
    """Return (src, dst, protocol_number, version) for IPv4 or IPv6, or None."""
    if IP in pkt:
        ip = pkt[IP]
        return ip.src, ip.dst, int(ip.proto), 4
    if IPv6 in pkt:
        ip6 = pkt[IPv6]
        # nh may point at an extension header; walk to the final one Scapy parsed.
        return ip6.src, ip6.dst, int(ip6.nh), 6
    return None


def _pair_key(src, dst):
    """Direction-independent session key."""
    return tuple(sorted((str(src), str(dst))))


def _norm_aes(base, key_length):
    """Fold an AES key length attribute into the cipher name (AES-CBC + 256 -> AES-256-CBC)."""
    if not base.startswith("AES") or not key_length:
        return base
    if "-" in base:
        head, tail = base.split("-", 1)
        return "%s-%d-%s" % (head, key_length, tail)
    return "%s-%d" % (base, key_length)


def _ikev2_cipher_name(transform_id, key_length):
    table = ikev2.IKEv2TransformAlgorithms.get(1, {})
    label = table.get(transform_id)
    if label is None:
        return UNKNOWN
    if label.startswith("AES-GCM"):
        return "AES-%d-GCM" % (key_length or 128)
    if label.startswith("AES-CCM"):
        return "AES-%d-CCM" % (key_length or 128)
    if label in ("AES-CBC", "AES-CTR"):
        return "AES-%d-%s" % (key_length or 128, label.split("-")[1])
    if label == "Camellia-CBC":
        return "CAMELLIA-%d-CBC" % (key_length or 128)
    return label.upper()


# --------------------------------------------------------------------------
# packet classification
# --------------------------------------------------------------------------

def classify_packet(pkt):
    """Bucket a packet into 'ike' | 'esp' | 'ah' | 'other'."""
    info = _ip_layer(pkt)
    if info is None:
        return "other"
    _, _, proto, _ = info

    if proto == 50 or ESP in pkt:
        return "esp"
    if proto == 51 or AH in pkt:
        return "ah"
    if UDP in pkt:
        udp = pkt[UDP]
        if udp.sport in IKE_PORTS or udp.dport in IKE_PORTS:
            # UDP/4500 carries either IKE (behind a 4-byte zero marker) or ESP.
            if udp.sport == 4500 or udp.dport == 4500:
                payload = bytes(udp.payload)
                if len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00":
                    return "ike"
                return "esp" if payload else "other"
            return "ike"
    return "other"


def _ike_bytes(pkt):
    """Strip the UDP (and NAT-T marker) wrapper and return raw ISAKMP/IKEv2 bytes."""
    if UDP not in pkt:
        return b""
    payload = bytes(pkt[UDP].payload)
    if (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500) and payload[:4] == b"\x00\x00\x00\x00":
        payload = payload[4:]
    return payload


def _ike_version(raw):
    """IKE major version from the ISAKMP header (byte 17). 1, 2 or None."""
    if len(raw) < 18:
        return None
    return (raw[17] >> 4) or None


# --------------------------------------------------------------------------
# IKEv1 extraction
# --------------------------------------------------------------------------

def _walk(layer):
    """Yield every layer in a dissected packet, tolerating truncated payloads."""
    seen = 0
    while layer is not None and seen < 64:
        yield layer
        seen += 1
        layer = layer.payload if layer.payload else None


def _iter_proposals(sa_layer):
    """Yield the proposals hanging off an SA payload.

    Scapy stores the first proposal in the SA payload's `prop` *field*, not in
    the payload chain, and chains any further proposals underneath it. Walking
    `pkt.payload` alone therefore never reaches a transform set.
    """
    for proposal in _walk(getattr(sa_layer, "prop", None)):
        yield proposal


def _transform_attrs(transform):
    """Flatten a Scapy transform list into {attr_name: value}."""
    attrs = {}
    for item in getattr(transform, "transforms", None) or []:
        try:
            name, value = item
        except (TypeError, ValueError):
            continue
        attrs[str(name)] = value
    return attrs


def _parse_ikev1(raw, state, pkt_meta):
    """Update `state` from one IKEv1 (ISAKMP) message."""
    try:
        msg = ISAKMP(raw)
    except Exception:
        state["parse_errors"] += 1
        return

    state["protocol"] = "IKEv1"
    exch = int(getattr(msg, "exch_type", 0) or 0)
    label = IKEV1_EXCHANGE.get(exch, UNKNOWN)
    state["exchanges"].add(label)

    # Phase 1 mode is what "exchange_mode" reports; quick mode is phase 2.
    if label in ("Main", "Aggressive", "Base"):
        state["exchange_mode"] = label

    # Flags bit 0 = encryption; payloads after the header are ciphertext.
    flags = int(getattr(msg, "flags", 0) or 0)
    encrypted = bool(flags & 0x01)

    quick_mode = label == "Quick Mode"
    if quick_mode:
        state["saw_quick_mode"] = True

    saw_ke_here = False
    saw_id_here = False

    for layer in _walk(msg):
        if isinstance(layer, ISAKMP_payload_ID):
            saw_id_here = True
            if not encrypted:
                # An ID payload readable on the wire is a real identity leak.
                state["identity_exposed"] = True
                try:
                    state["identity_values"].add(repr(bytes(layer.IdentData)[:64]))
                except Exception:
                    pass
        elif isinstance(layer, ISAKMP_payload_KE):
            saw_ke_here = True
        elif isinstance(layer, ISAKMP_payload_SA):
            for proposal in _iter_proposals(layer):
                if not isinstance(proposal, ISAKMP_payload_Proposal):
                    continue
                proto = int(getattr(proposal, "proto", 1) or 1)
                if proto in (2, 3):  # PROTO_IPSEC_AH / PROTO_IPSEC_ESP
                    state["negotiated_ipsec"].add("AH" if proto == 2 else "ESP")
                for trans in _walk(getattr(proposal, "trans", None)):
                    if not isinstance(trans, ISAKMP_payload_Transform):
                        continue
                    attrs = _transform_attrs(trans)
                    if proto == 1:  # PROTO_ISAKMP -> phase 1 transform set
                        _apply_ikev1_phase1(state, attrs)
                    else:  # PROTO_IPSEC_ESP / AH -> phase 2 transform set
                        _apply_ikev1_phase2(state, attrs)

    if quick_mode and saw_ke_here:
        state["pfs_enabled"] = True
    elif quick_mode and not encrypted and state["pfs_enabled"] is None:
        # Readable quick mode with no KE payload means PFS was not requested.
        state["pfs_enabled"] = False

    if saw_id_here and encrypted and state["identity_exposed"] is None:
        state["identity_exposed"] = False

    state["ike_packets"] += 1
    if pkt_meta.get("port") == 4500:
        state["nat_traversal"] = True


def _apply_ikev1_phase1(state, attrs):
    enc = attrs.get("Encryption")
    if enc is not None:
        name = IKEV1_ENC.get(str(enc), str(enc).upper())
        state["encryption"] = _norm_aes(name, attrs.get("KeyLength"))

    hsh = attrs.get("Hash")
    if hsh is not None:
        state["hash"] = IKEV1_HASH.get(str(hsh), str(hsh).upper())

    grp = attrs.get("GroupDesc")
    if grp is not None:
        state["dh_group"] = DH_LABEL_TO_NUM.get(str(grp), grp if isinstance(grp, int) else None)

    auth = attrs.get("Authentication")
    if auth is not None:
        state["auth_method"] = IKEV1_AUTH.get(str(auth), str(auth))

    life_type = attrs.get("LifeType")
    duration = attrs.get("LifeDuration")
    if duration is not None and isinstance(duration, int):
        if life_type is None or str(life_type).lower().startswith("second"):
            state["lifetime_seconds"] = duration


def _apply_ikev1_phase2(state, attrs):
    """Quick Mode (IPSEC DOI) attributes: encapsulation mode and child SA algorithms."""
    encap = attrs.get("EncapsulationMode")
    if encap is not None:
        text = str(encap)
        if "Transport" in text:
            state["ipsec_mode"] = "Transport"
        elif "Tunnel" in text:
            state["ipsec_mode"] = "Tunnel"

    alg = attrs.get("AuthenticationAlgorithm")
    if alg is not None:
        state["authentication"] = IPSEC_INTEGRITY_NAME.get(str(alg), str(alg).upper())
        if state["hash"] == UNKNOWN:
            state["hash"] = IPSEC_AUTH_ALG.get(str(alg), str(alg).upper())

    grp = attrs.get("GroupDesc")
    if grp is not None:
        # A group in the quick mode proposal means PFS was requested.
        state["pfs_enabled"] = True
        if state["dh_group"] is None:
            state["dh_group"] = DH_LABEL_TO_NUM.get(str(grp))

    life_type = attrs.get("LifeType")
    duration = attrs.get("LifeDuration")
    if (
        duration is not None
        and isinstance(duration, int)
        and state["lifetime_seconds"] is None
        and (life_type is None or str(life_type).lower().startswith("second"))
    ):
        state["lifetime_seconds"] = duration


# --------------------------------------------------------------------------
# IKEv2 extraction
# --------------------------------------------------------------------------

def _parse_ikev2(raw, state, pkt_meta):
    """Update `state` from one IKEv2 message."""
    if not HAVE_IKEV2:
        state["parse_errors"] += 1
        return
    try:
        msg = ikev2.IKEv2(raw)
    except Exception:
        state["parse_errors"] += 1
        return

    state["protocol"] = "IKEv2"
    exch = int(getattr(msg, "exch_type", 0) or 0)
    label = ikev2.IKEv2ExchangeTypes.get(exch, UNKNOWN)
    state["exchanges"].add(label)
    if label == "IKE_SA_INIT":
        state["exchange_mode"] = "IKE_SA_INIT"
    elif state["exchange_mode"] == UNKNOWN and label != UNKNOWN:
        state["exchange_mode"] = label

    child_sa = label == "CREATE_CHILD_SA"
    saw_ke_here = False

    for layer in _walk(msg):
        if isinstance(layer, ikev2.IKEv2_KE):
            saw_ke_here = True
            group = getattr(layer, "group", None)
            if state["dh_group"] is None and isinstance(group, int):
                state["dh_group"] = group
        elif isinstance(layer, ikev2.IKEv2_Notify):
            ntype = int(getattr(layer, "type", 0) or 0)
            if ntype == NOTIFY_USE_TRANSPORT_MODE:
                state["ipsec_mode"] = "Transport"
            elif ntype in NOTIFY_NAT_DETECTION:
                state["nat_detection_seen"] = True
        elif isinstance(layer, (ikev2.IKEv2_IDi, ikev2.IKEv2_IDr)):
            # IKEv2 carries IDi/IDr inside the encrypted SK payload; seeing one
            # in the clear means the identity really is exposed.
            state["identity_exposed"] = True
        elif isinstance(layer, ikev2.IKEv2_AUTH):
            auth_type = int(getattr(layer, "auth_type", 0) or 0)
            label_auth = ikev2.IKEv2AuthenticationTypes.get(auth_type)
            if label_auth == "Shared Key Message Integrity Code":
                state["auth_method"] = "Pre-Shared Key"
            elif label_auth:
                state["auth_method"] = label_auth
        elif isinstance(layer, ikev2.IKEv2_Encrypted):
            state["saw_encrypted_payload"] = True
        elif isinstance(layer, ikev2.IKEv2_SA):
            for proposal in _iter_proposals(layer):
                if not isinstance(proposal, ikev2.IKEv2_Proposal):
                    continue
                proto = int(getattr(proposal, "proto", 1) or 1)
                if proto in (2, 3):  # AH / ESP child SA
                    state["negotiated_ipsec"].add("AH" if proto == 2 else "ESP")
                _apply_ikev2_proposal(
                    state, proposal, is_child=(proto in (2, 3) or child_sa)
                )

    if child_sa and saw_ke_here:
        state["pfs_enabled"] = True

    state["ike_packets"] += 1
    if pkt_meta.get("port") == 4500:
        state["nat_traversal"] = True


def _apply_ikev2_proposal(state, proposal, is_child):
    child_integrity = None
    child_aead = False
    for trans in _walk(getattr(proposal, "trans", None)):
        if not isinstance(trans, ikev2.IKEv2_Transform):
            continue
        ttype = int(getattr(trans, "transform_type", 0) or 0)
        tid = getattr(trans, "transform_id", None)
        klen = getattr(trans, "key_length", None)
        if isinstance(tid, str):  # Scapy may hand back the label
            tid = {v: k for k, v in ikev2.IKEv2TransformAlgorithms.get(ttype, {}).items()}.get(tid)
        if tid is None:
            continue

        if ttype == 1:  # Encryption
            state["encryption"] = _ikev2_cipher_name(int(tid), klen)
            if int(tid) in IKEV2_AEAD:
                state["aead"] = True
                child_aead = child_aead or is_child
        elif ttype == 3:  # Integrity
            state["hash"] = IKEV2_INTEG.get(int(tid), UNKNOWN)
            if is_child:
                child_integrity = IKEV2_INTEG_NAME.get(int(tid), UNKNOWN)
        elif ttype == 2 and state["hash"] == UNKNOWN:
            # AEAD suites carry no integrity transform; fall back to the PRF.
            prf = ikev2.IKEv2TransformAlgorithms.get(2, {}).get(int(tid), "")
            if "SHA2_256" in prf:
                state["hash"] = "SHA256"
            elif "SHA2_384" in prf:
                state["hash"] = "SHA384"
            elif "SHA2_512" in prf:
                state["hash"] = "SHA512"
            elif "SHA1" in prf:
                state["hash"] = "SHA1"
            elif "MD5" in prf:
                state["hash"] = "MD5"
        elif ttype == 4:  # DH group
            group = int(tid)
            if is_child:
                # A DH group in a child SA proposal is exactly what PFS means.
                state["pfs_enabled"] = True
            if state["dh_group"] is None or is_child:
                state["dh_group"] = group
        elif ttype == 5:  # Extended sequence numbers
            state["esn"] = int(tid) == 1

    # Only a child SA proposal describes the ESP/AH integrity algorithm; the IKE
    # SA's own integrity transform protects IKE messages, not the data plane.
    if child_integrity is not None:
        state["authentication"] = child_integrity
    elif child_aead:
        state["authentication"] = AEAD_INTEGRITY


# --------------------------------------------------------------------------
# ESP / AH statistics
# --------------------------------------------------------------------------

def _esp_seq(pkt):
    """(spi, seq) from an ESP or AH packet, including UDP-encapsulated ESP."""
    if ESP in pkt:
        return int(pkt[ESP].spi), int(pkt[ESP].seq)
    if AH in pkt:
        return int(pkt[AH].spi), int(pkt[AH].seq)
    if UDP in pkt:
        payload = bytes(pkt[UDP].payload)
        if len(payload) >= 8 and payload[:4] != b"\x00\x00\x00\x00":
            spi, seq = struct.unpack("!II", payload[:8])
            return spi, seq
    return None, None


def _replay_status(seq_by_spi):
    """True if every SA's sequence numbers increase monotonically, else False/None."""
    usable = {spi: seqs for spi, seqs in seq_by_spi.items() if len(seqs) >= 2}
    if not usable:
        return None
    for seqs in usable.values():
        for prev, cur in zip(seqs, seqs[1:]):
            if cur <= prev:
                return False
    return True


def _traffic_features(records, initiator):
    """Size/timing/direction statistics. Never reads payload content."""
    if not records:
        return {
            "packet_count": 0,
            "avg_packet_size": 0.0,
            "min_packet_size": 0,
            "max_packet_size": 0,
            "avg_inter_arrival_ms": 0.0,
            "duration_seconds": 0.0,
            "bytes_total": 0,
            "upstream_ratio": 0.0,
        }

    records = sorted(records, key=lambda r: r["time"])
    sizes = [r["size"] for r in records]
    times = [r["time"] for r in records]
    total = sum(sizes)

    gaps = [(b - a) * 1000.0 for a, b in zip(times, times[1:])]
    duration = times[-1] - times[0]
    upstream_bytes = sum(r["size"] for r in records if r["src"] == initiator)

    return {
        "packet_count": len(records),
        "avg_packet_size": round(total / len(records), 2),
        "min_packet_size": int(min(sizes)),
        "max_packet_size": int(max(sizes)),
        "avg_inter_arrival_ms": round(sum(gaps) / len(gaps), 3) if gaps else 0.0,
        "duration_seconds": round(duration, 6),
        "bytes_total": int(total),
        "upstream_ratio": round(upstream_bytes / total, 4) if total else 0.0,
    }


def _infer_mode_from_esp(records, explicit_mode):
    """Fall back to an ESP size heuristic when no encapsulation attribute was seen."""
    if explicit_mode != UNKNOWN:
        return explicit_mode, True
    if not records:
        return UNKNOWN, False
    # A tunnel-mode ESP packet always carries a full inner IP header (>=20 bytes)
    # on top of the IV and trailer, so the smallest packet is meaningfully larger
    # than a transport-mode one. Below the threshold we decline to guess.
    smallest_payload = min(r["esp_payload"] for r in records if r["esp_payload"] is not None) \
        if any(r["esp_payload"] is not None for r in records) else None
    if smallest_payload is None:
        return UNKNOWN, False
    if smallest_payload >= 56:
        return "Tunnel", False
    return UNKNOWN, False


def _ipsec_protocol(state):
    """ESP / AH / ESP+AH from the data plane, else from the negotiated proposal."""
    seen = set()
    if state["esp_records"]:
        seen.add("ESP")
    if state["ah_records"]:
        seen.add("AH")
    if not seen:
        seen = set(state["negotiated_ipsec"])
    if seen == {"ESP", "AH"}:
        return "ESP+AH"
    if len(seen) == 1:
        return next(iter(seen))
    return UNKNOWN


def _key_exchange(dh_group):
    """Name the key-exchange family for a DH group number."""
    if not isinstance(dh_group, int) or isinstance(dh_group, bool):
        return UNKNOWN
    return "ECDH" if dh_group in ECP_GROUPS else "Diffie-Hellman"


# --------------------------------------------------------------------------
# confidence
# --------------------------------------------------------------------------

_CONFIDENCE_FIELDS = (
    ("protocol", 0.15),
    ("exchange_mode", 0.08),
    ("encryption", 0.18),
    ("hash", 0.14),
    ("dh_group", 0.12),
    ("auth_method", 0.08),
    ("lifetime_seconds", 0.05),
    ("pfs_enabled", 0.07),
    ("ipsec_mode", 0.06),
    ("replay_protection", 0.07),
)


def _confidence(session, state):
    score = 0.0
    for field, weight in _CONFIDENCE_FIELDS:
        value = session.get(field)
        if value is None or value == UNKNOWN:
            continue
        score += weight
    if state.get("parse_errors"):
        score *= 0.8
    if state.get("mode_guessed"):
        score -= 0.03
    if state["ike_packets"] == 0:
        # ESP-only session: everything about the negotiation is inferred.
        score = min(score, 0.35)
    return round(max(0.0, min(1.0, score)), 3)


# --------------------------------------------------------------------------
# main entry point
# --------------------------------------------------------------------------

def _new_state():
    return {
        "protocol": UNKNOWN,
        "exchange_mode": UNKNOWN,
        "encryption": UNKNOWN,
        "hash": UNKNOWN,
        "authentication": UNKNOWN,
        "dh_group": None,
        "auth_method": UNKNOWN,
        "lifetime_seconds": None,
        "pfs_enabled": None,
        "ipsec_mode": UNKNOWN,
        "nat_traversal": None,
        "identity_exposed": None,
        "esn": None,
        "aead": False,
        "ike_packets": 0,
        "esp_records": [],
        "ah_records": [],
        "seq_by_spi": {},
        "exchanges": set(),
        "negotiated_ipsec": set(),
        "identity_values": set(),
        "parse_errors": 0,
        "saw_quick_mode": False,
        "saw_encrypted_payload": False,
        "nat_detection_seen": False,
        "first_src": None,
        "first_time": None,
        "mode_guessed": False,
    }


def parse_pcap(path):
    """Parse a capture and return a Contract A dict without the `findings` key.

    `backend.main` adds findings by running the rule engine over `sessions`.
    """
    packets = rdpcap(path)

    counts = {"ike_packets": 0, "esp_packets": 0, "ah_packets": 0, "other_packets": 0}
    versions = set()
    states = {}
    order = []

    for pkt in packets:
        info = _ip_layer(pkt)
        kind = classify_packet(pkt)
        counts[kind + "_packets"] += 1

        if info is None:
            continue
        src, dst, _, version = info
        versions.add(version)

        if kind == "other":
            continue

        key = _pair_key(src, dst)
        if key not in states:
            states[key] = _new_state()
            order.append(key)
        state = states[key]

        timestamp = float(pkt.time)
        if state["first_src"] is None:
            state["first_src"] = src
            state["first_time"] = timestamp

        if kind == "ike":
            raw = _ike_bytes(pkt)
            if not raw:
                continue
            port = 4500 if (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500) else 500
            meta = {"port": port, "time": timestamp}
            major = _ike_version(raw)
            if major == 2:
                _parse_ikev2(raw, state, meta)
            elif major == 1:
                _parse_ikev1(raw, state, meta)
            else:
                state["parse_errors"] += 1
            if port == 500 and state["nat_traversal"] is None:
                state["nat_traversal"] = False

        elif kind in ("esp", "ah"):
            spi, seq = _esp_seq(pkt)
            esp_payload = None
            if ESP in pkt:
                esp_payload = len(bytes(pkt[ESP].data)) if pkt[ESP].data else 0
            elif AH in pkt:
                esp_payload = len(bytes(pkt[AH].payload))
            record = {
                "time": timestamp,
                "size": len(pkt),
                "src": src,
                "esp_payload": esp_payload,
            }
            state["esp_records" if kind == "esp" else "ah_records"].append(record)
            if spi is not None and seq is not None:
                state["seq_by_spi"].setdefault(spi, []).append(seq)

    sessions = []
    for index, key in enumerate(order):
        state = states[key]
        flows = state["esp_records"] or state["ah_records"]
        initiator = state["first_src"]

        explicit_mode = state["ipsec_mode"]
        mode, explicit = _infer_mode_from_esp(state["esp_records"], explicit_mode)
        if explicit_mode == UNKNOWN and mode != UNKNOWN:
            state["mode_guessed"] = True
        # RFC 7296: tunnel mode is the IKEv2 default unless USE_TRANSPORT_MODE is sent.
        if mode == UNKNOWN and state["protocol"] == "IKEv2" and state["ike_packets"]:
            mode = "Tunnel"

        # Protocols that always encrypt identity payloads: absent a plaintext ID
        # on the wire, identity is protected rather than merely undetermined.
        if state["identity_exposed"] is None and state["ike_packets"]:
            if state["protocol"] == "IKEv2":
                state["identity_exposed"] = False  # RFC 7296: IDi/IDr ride inside SK
            elif state["protocol"] == "IKEv1" and state["exchange_mode"] == "Main":
                state["identity_exposed"] = False  # main mode sends IDs in msgs 5/6

        replay = _replay_status(state["seq_by_spi"])
        # Extended sequence numbers imply an anti-replay window is in use, but a
        # regression observed on the wire always wins.
        if replay is None and state["esn"] is True:
            replay = True

        src_ip, dst_ip = (initiator, key[1] if key[0] == initiator else key[0]) \
            if initiator else (key[0], key[1])

        # Key order follows the canonical Contract A (ai_engine/test_data).
        session = {
            "session_id": "S%d" % (index + 1),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ipsec_protocol": _ipsec_protocol(state),
            "protocol": state["protocol"],
            "exchange_mode": state["exchange_mode"],
            "ipsec_mode": mode,
            "encryption": state["encryption"],
            "authentication": state["authentication"],
            "hash": state["hash"],
            "dh_group": state["dh_group"],
            "key_exchange": _key_exchange(state["dh_group"]),
            "auth_method": state["auth_method"],
            "lifetime_seconds": state["lifetime_seconds"],
            "pfs_enabled": state["pfs_enabled"],
            "replay_protection": replay,
            "nat_traversal": state["nat_traversal"],
            "identity_exposed": state["identity_exposed"],
            "confidence": None,
            "traffic_features": _traffic_features(flows, initiator),
        }
        session["confidence"] = _confidence(session, state)
        sessions.append(session)

    if versions == {6}:
        ip_version = "IPv6"
    elif versions == {4}:
        ip_version = "IPv4"
    elif versions:
        ip_version = "Mixed"
    else:
        ip_version = UNKNOWN

    return {
        "file_name": os.path.basename(path),
        "total_packets": len(packets),
        "ip_version": ip_version,
        "packet_summary": counts,
        "sessions": sessions,
    }
