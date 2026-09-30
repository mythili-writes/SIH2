"""Deterministic IPsec configuration rule engine.

Consumes the per-session parameter dicts produced by `backend.parser` and emits
Contract A findings: {finding_id, session_id, category, issue, severity, evidence}.

Severity is only ever Critical/High/Medium/Low. Category is only ever one of the
eleven values in CATEGORIES. Unknown parameters never produce a finding — the
engine reports what it can see, not what it guesses.
"""

import re

import config

SEVERITIES = ("Critical", "High", "Medium", "Low")

CATEGORIES = (
    "Encryption",
    "Hash",
    "KeyExchange",
    "Authentication",
    "Mode",
    "Lifetime",
    "PFS",
    "Protocol",
    "ReplayProtection",
    "MetadataExposure",
    "Compliance",
)

UNKNOWN = "Unknown"

# --- cipher policy ---------------------------------------------------------

# Exact-match weak ciphers -> severity. Checked before the pattern rules below.
WEAK_ENCRYPTION = {
    "DES": ("Critical", "Weak encryption algorithm negotiated: DES (56-bit effective key)"),
    "3DES": ("High", "Weak encryption algorithm negotiated: 3DES (deprecated, 112-bit effective)"),
    "DES-IV64": ("Critical", "Weak encryption algorithm negotiated: DES-IV64"),
    "DES-IV32": ("Critical", "Weak encryption algorithm negotiated: DES-IV32"),
    "RC5": ("High", "Weak encryption algorithm negotiated: RC5"),
    "IDEA": ("High", "Weak encryption algorithm negotiated: IDEA"),
    "CAST": ("High", "Weak encryption algorithm negotiated: CAST"),
    "BLOWFISH": ("High", "Weak encryption algorithm negotiated: Blowfish"),
    "NULL": ("Critical", "Null encryption negotiated: traffic is not confidentiality-protected"),
}

WEAK_HASH = {
    "MD5": ("High", "Weak integrity/hash algorithm negotiated: MD5"),
    "HMAC-MD5": ("High", "Weak integrity/hash algorithm negotiated: HMAC-MD5"),
    "SHA1": ("Medium", "Deprecated integrity/hash algorithm negotiated: SHA-1"),
    "SHA-1": ("Medium", "Deprecated integrity/hash algorithm negotiated: SHA-1"),
    "HMAC-SHA1": ("Medium", "Deprecated integrity/hash algorithm negotiated: HMAC-SHA1"),
    "NONE": ("High", "No integrity algorithm negotiated"),
}

WEAK_DH_GROUPS = {
    1: ("High", "Weak Diffie-Hellman group negotiated: group 1 (768-bit MODP)"),
    2: ("High", "Weak Diffie-Hellman group negotiated: group 2 (1024-bit MODP)"),
    5: ("Medium", "Weak Diffie-Hellman group negotiated: group 5 (1536-bit MODP)"),
    22: (
        "Medium",
        "Weak Diffie-Hellman group negotiated: group 22 (1024-bit MODP with 160-bit POS)",
    ),
    23: (
        "Medium",
        "Weak Diffie-Hellman group negotiated: group 23 (2048-bit MODP with 224-bit POS)",
    ),
}


def _norm(value):
    """Uppercase, strip, collapse separators for tolerant matching."""
    if value is None:
        return UNKNOWN
    text = str(value).strip().upper()
    return text or UNKNOWN


def _is_unknown(value):
    return value is None or _norm(value) in ("UNKNOWN", "")


def _approved_suite(encryption, hash_alg, dh_group):
    """True when the suite meets the approved baseline: AES-GCM, or AES-256 + SHA256+.

    Returns (approved, reason) where reason explains a failure.
    """
    enc = _norm(encryption)
    h = _norm(hash_alg)

    if _is_unknown(encryption):
        return None, "encryption algorithm could not be determined"

    # AES-GCM is an AEAD mode: integrity is built in, so no separate hash needed.
    if "GCM" in enc and enc.startswith("AES"):
        key_bits = re.search(r"(128|192|256)", enc)
        if key_bits and int(key_bits.group(1)) < 128:
            return False, "AES-GCM with an under-strength key"
        return True, ""

    if "CCM" in enc and enc.startswith("AES"):
        return True, ""

    if not enc.startswith("AES"):
        return False, "cipher %s is outside the approved AES family" % enc

    key_bits = re.search(r"(128|192|256)", enc)
    if not key_bits or int(key_bits.group(1)) < 256:
        return False, ("cipher %s does not meet the AES-256 minimum for non-AEAD modes" % enc)

    if _is_unknown(hash_alg):
        return None, "integrity algorithm could not be determined"

    sha_bits = re.search(r"SHA-?(\d+)", h)
    if "SHA256" in h.replace("-", "") or (sha_bits and int(sha_bits.group(1)) >= 256):
        pass
    else:
        return False, "integrity algorithm %s is below the SHA-256 minimum" % h

    if isinstance(dh_group, int) and dh_group in WEAK_DH_GROUPS:
        return False, "DH group %d is below the group-14 minimum" % dh_group

    return True, ""


class _FindingBuilder:
    def __init__(self):
        self._items = []

    def add(self, session_id, category, issue, severity, evidence):
        assert severity in SEVERITIES, "bad severity %r" % severity
        assert category in CATEGORIES, "bad category %r" % category
        self._items.append(
            {
                "finding_id": "F%03d" % (len(self._items) + 1),
                "session_id": session_id,
                "category": category,
                "issue": issue,
                "severity": severity,
                "evidence": evidence,
            }
        )

    @property
    def items(self):
        return self._items


def evaluate_session(session, builder):
    """Apply every rule to one session, appending findings to `builder`."""
    sid = session.get("session_id")
    peer = "%s -> %s" % (session.get("src_ip", "?"), session.get("dst_ip", "?"))

    encryption = session.get("encryption")
    hash_alg = session.get("hash")
    dh_group = session.get("dh_group")
    protocol = session.get("protocol")
    exchange_mode = session.get("exchange_mode")
    auth_method = session.get("auth_method")
    lifetime = session.get("lifetime_seconds")
    pfs = session.get("pfs_enabled")
    ipsec_mode = session.get("ipsec_mode")
    replay = session.get("replay_protection")
    identity_exposed = session.get("identity_exposed")

    # --- Encryption --------------------------------------------------------
    enc = _norm(encryption)
    if not _is_unknown(encryption):
        matched = None
        for weak, (severity, issue) in WEAK_ENCRYPTION.items():
            # Match "3DES" inside "3DES-CBC" but never "DES" inside "3DES".
            if enc == weak or enc.startswith(weak + "-") or enc.startswith(weak + "_"):
                matched = (severity, issue)
                break
        if matched is None and enc.startswith("DES"):
            matched = WEAK_ENCRYPTION["DES"]

        if matched:
            builder.add(
                sid,
                "Encryption",
                matched[1],
                matched[0],
                "IKE transform payload advertised %s for session %s" % (encryption, peer),
            )
        elif enc.startswith("AES") and "CBC" in enc:
            builder.add(
                sid,
                "Encryption",
                "AES in CBC mode negotiated (%s): prefer an AEAD mode such as AES-GCM" % encryption,
                "Low",
                "IKE transform payload advertised %s; CBC requires a separate integrity "
                "algorithm and is more error-prone than AES-GCM" % encryption,
            )

    # --- Hash --------------------------------------------------------------
    if not _is_unknown(hash_alg):
        h = _norm(hash_alg)
        for weak, (severity, issue) in WEAK_HASH.items():
            if h == weak or h.startswith(weak + "-") or h.replace("-", "") == weak.replace("-", ""):
                builder.add(
                    sid,
                    "Hash",
                    issue,
                    severity,
                    "IKE transform payload advertised %s for session %s" % (hash_alg, peer),
                )
                break

    # --- Key exchange ------------------------------------------------------
    if isinstance(dh_group, int) and dh_group in WEAK_DH_GROUPS:
        severity, issue = WEAK_DH_GROUPS[dh_group]
        builder.add(
            sid,
            "KeyExchange",
            issue,
            severity,
            "IKE key exchange payload indicated DH group %d for session %s" % (dh_group, peer),
        )

    # --- Protocol ----------------------------------------------------------
    proto = _norm(protocol)
    mode = _norm(exchange_mode)
    if proto == "IKEV1":
        if mode == "AGGRESSIVE":
            builder.add(
                sid,
                "Protocol",
                "IKEv1 Aggressive Mode in use",
                "High",
                "ISAKMP header exchange type 4 (Aggressive) observed on UDP/500 for session %s"
                % peer,
            )
        else:
            builder.add(
                sid,
                "Protocol",
                "Deprecated key exchange protocol in use: IKEv1",
                "Medium",
                "ISAKMP header reported version 1.0 for session %s" % peer,
            )

    # --- Authentication ----------------------------------------------------
    auth = _norm(auth_method)
    if auth in ("PRE-SHARED KEY", "PRE_SHARED_KEY", "PSK", "PRESHARED KEY"):
        builder.add(
            sid,
            "Authentication",
            "Pre-Shared Key authentication in use",
            "Medium",
            "IKE transform payload advertised auth method 'Pre-Shared Key' for session %s" % peer,
        )

    # --- PFS ---------------------------------------------------------------
    if pfs is False:
        builder.add(
            sid,
            "PFS",
            "Perfect Forward Secrecy is disabled",
            "Medium",
            "No Diffie-Hellman key exchange payload observed during child SA "
            "negotiation for session %s" % peer,
        )

    # --- Lifetime ----------------------------------------------------------
    if isinstance(lifetime, (int, float)) and not isinstance(lifetime, bool):
        maximum, minimum = config.SA_LIFETIME_MAX_SECONDS, config.SA_LIFETIME_MIN_SECONDS
        if lifetime > maximum:
            builder.add(
                sid,
                "Lifetime",
                "SA lifetime exceeds the recommended maximum: %ds (> %ds)"
                % (int(lifetime), maximum),
                "Low",
                "IKE SA lifetime attribute decoded as %d seconds for session %s"
                % (int(lifetime), peer),
            )
        elif lifetime < minimum:
            builder.add(
                sid,
                "Lifetime",
                "SA lifetime below the recommended minimum: %ds (< %ds)" % (int(lifetime), minimum),
                "Low",
                "IKE SA lifetime attribute decoded as %d seconds for session %s; "
                "excessive rekeying destabilises the tunnel" % (int(lifetime), peer),
            )

    # --- Mode --------------------------------------------------------------
    if _norm(ipsec_mode) == "TRANSPORT" and session.get("is_site_to_site", True):
        builder.add(
            sid,
            "Mode",
            "Transport mode in use for what appears to be a site-to-site SA",
            "Low",
            "ESP payload structure for session %s is consistent with transport mode; "
            "the inner IP header is therefore not protected" % peer,
        )

    # --- Replay protection -------------------------------------------------
    if replay is False:
        builder.add(
            sid,
            "ReplayProtection",
            "Anti-replay protection appears disabled",
            "Medium",
            "ESP sequence numbers for session %s did not increase monotonically "
            "across the capture" % peer,
        )

    # --- Metadata exposure -------------------------------------------------
    if identity_exposed is True:
        builder.add(
            sid,
            "MetadataExposure",
            "Peer identity transmitted without encryption",
            "Medium",
            "An IKE ID payload was observed in an unencrypted message for session %s" % peer,
        )

    # --- Compliance --------------------------------------------------------
    approved, reason = _approved_suite(encryption, hash_alg, dh_group)
    if approved is False:
        builder.add(
            sid,
            "Compliance",
            "Negotiated cipher suite is not compliant with the approved baseline",
            "Medium",
            "Suite %s/%s/DH%s fails the AES-GCM or AES-256 + SHA-256 baseline: %s"
            % (
                encryption if not _is_unknown(encryption) else UNKNOWN,
                hash_alg if not _is_unknown(hash_alg) else UNKNOWN,
                dh_group if dh_group is not None else UNKNOWN,
                reason,
            ),
        )


def evaluate(sessions):
    """Run the rule engine over every session. Returns a Contract A findings list."""
    builder = _FindingBuilder()
    for session in sessions or []:
        evaluate_session(session, builder)
    return builder.items
