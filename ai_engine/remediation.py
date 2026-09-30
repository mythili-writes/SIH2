"""Configuration fix generator: a strongSwan ipsec.conf snippet for every finding.

Each finding category maps to the ipsec.conf settings that fix it, set to one
hardened baseline that matches the explainer's recommendations: IKEv2,
AES-256-GCM, SHA-256 PRF, DH group 19 (ecp256) with PFS, certificate
authentication, tunnel mode, an 8 h IKE SA and 1 h IPsec SA, and anti-replay.

Snippets are deterministic and rule-based. They never come from the LLM, so a
snippet cannot contain invented syntax. Comments sit on their own lines so the
snippet can be pasted as-is; where the capture showed the current value, a
"was" comment records it.

Two outputs:
- snippet_for_finding(): the lines that fix one finding
- session_config(): one merged conn block per session covering all its
  findings, because several categories rewrite the same ike= / esp= lines

Scope: strongSwan's legacy ipsec.conf (stroke) syntax only. The snippets have
not been validated against a running strongSwan instance.
"""

import re

TARGET_IKE = "aes256gcm16-prfsha256-ecp256!"
TARGET_ESP = "aes256gcm16-ecp256!"
IKEV1_FALLBACK_IKE = "aes256-sha256-ecp256!"

# Canonical order of settings inside a conn block.
KEY_ORDER = (
    "keyexchange",
    "aggressive",
    "ike",
    "esp",
    "leftauth",
    "rightauth",
    "leftcert",
    "rightid",
    "ikelifetime",
    "lifetime",
    "type",
    "replay_window",
)

CRYPTO_CATEGORIES = ("Encryption", "Hash", "KeyExchange", "Compliance")

# IANA DH group number -> strongSwan proposal keyword.
DH_TOKENS = {
    1: "modp768",
    2: "modp1024",
    5: "modp1536",
    14: "modp2048",
    15: "modp3072",
    16: "modp4096",
    17: "modp6144",
    18: "modp8192",
    19: "ecp256",
    20: "ecp384",
    21: "ecp521",
    22: "modp1024s160",
    23: "modp2048s224",
    24: "modp2048s256",
    25: "ecp192",
    26: "ecp224",
    27: "ecp224bp",
    28: "ecp256bp",
    29: "ecp384bp",
    30: "ecp512bp",
    31: "curve25519",
    32: "curve448",
}

HASH_TOKENS = {
    "MD5": "md5",
    "SHA1": "sha1",
    "SHA256": "sha256",
    "SHA384": "sha384",
    "SHA512": "sha512",
}

FIXED_CIPHERS = {
    "DES": "des",
    "DES-CBC": "des",
    "3DES": "3des",
    "3DES-CBC": "3des",
    "BLOWFISH-CBC": "blowfish",
    "CAST-CBC": "cast128",
    "NULL": "null",
}


def _cipher_token(encryption):
    """strongSwan keyword for a Contract A cipher name, or None if unknown."""
    name = str(encryption or "").upper()
    if name in FIXED_CIPHERS:
        return FIXED_CIPHERS[name]
    match = re.fullmatch(r"AES-(\d+)-(CBC|GCM|CTR|CCM)", name)
    if match:
        bits, mode = match.groups()
        suffix = {"CBC": "", "GCM": "gcm16", "CTR": "ctr", "CCM": "ccm16"}[mode]
        return "aes%s%s" % (bits, suffix)
    if name == "AES-CBC":
        return "aes128"
    return None


def observed_ike_proposal(session):
    """The session's IKE proposal in strongSwan syntax, as far as the capture showed it.

    Unknown parts appear as "?". Returns None when nothing about it is known.
    """
    cipher = _cipher_token(session.get("encryption"))
    hash_token = HASH_TOKENS.get(str(session.get("hash") or "").upper())
    dh_group = session.get("dh_group")
    dh = DH_TOKENS.get(dh_group) if isinstance(dh_group, int) else None
    if cipher is None and hash_token is None and dh is None:
        return None
    if cipher and ("gcm" in cipher or "ccm" in cipher):
        hash_token = "prf" + hash_token if hash_token else None  # AEAD suites name a PRF
    return "-".join(part or "?" for part in (cipher, hash_token, dh))


def _settings_for(finding, session):
    """{key: (value, [comment lines])} that fix one finding."""
    category = finding.get("category")
    protocol = str(session.get("protocol") or "")
    settings = {}

    def put(key, value, *notes):
        settings.setdefault(key, (value, [n for n in notes if n]))

    def require_ikev2(reason):
        if protocol != "IKEv2":
            was = "was (observed): keyexchange=ikev1" if protocol == "IKEv1" else None
            put("keyexchange", "ikev2", was, reason)

    if category in CRYPTO_CATEGORIES:
        require_ikev2("required: AES-GCM IKE proposals are only supported with IKEv2")
        observed = observed_ike_proposal(session)
        put(
            "ike",
            TARGET_IKE,
            "was (observed): ike=%s" % observed if observed else None,
            "if this peer must stay on IKEv1 for now: ike=%s" % IKEV1_FALLBACK_IKE,
        )
        put("esp", TARGET_ESP, "the DH group in the ESP proposal also turns on PFS")

    elif category == "PFS":
        put(
            "esp",
            TARGET_ESP,
            "was (observed): no DH group in the ESP proposal, so no PFS",
            "adding a DH group to the ESP proposal enables PFS on every rekey",
        )

    elif category == "Protocol":
        require_ikev2("IKEv1 is deprecated (RFC 9395)")
        if str(session.get("exchange_mode") or "") == "Aggressive":
            put(
                "aggressive",
                "no",
                "was (observed): aggressive=yes",
                "keeps IKEv1 peers in main mode during the migration",
            )

    elif category == "MetadataExposure":
        require_ikev2("IKEv2 encrypts the identity payloads")
        if str(session.get("exchange_mode") or "") == "Aggressive":
            put("aggressive", "no", "aggressive mode sends identities in the clear")

    elif category == "Authentication":
        put("leftauth", "pubkey", "was (observed): pre-shared key (authby=secret)")
        put("rightauth", "pubkey")
        put("leftcert", "gatewayCert.pem", "this gateway's certificate in /etc/ipsec.d/certs/")
        put(
            "rightid",
            '"CN=peer.example.org"',
            "set to the subject of the peer's certificate",
            "then remove this peer's PSK line from /etc/ipsec.secrets",
        )

    elif category == "Lifetime":
        seconds = session.get("lifetime_seconds")
        was = "was (observed): ikelifetime=%ss" % seconds if isinstance(seconds, int) else None
        put("ikelifetime", "8h", was, "28800 s for the IKE SA")
        put("lifetime", "1h", "3600 s for the IPsec SA")

    elif category == "Mode":
        put(
            "type",
            "tunnel",
            "was (observed): type=transport",
            "tunnel mode also encrypts the inner IP header",
        )

    elif category == "ReplayProtection":
        put(
            "replay_window",
            "32",
            "was: ESP sequence numbers went backwards in the capture, so anti-replay "
            "looks disabled",
            "0 disables anti-replay; values above 32 need the kernel-netlink backend",
        )

    return settings


def _conn_name(session_id):
    """A conn name strongSwan accepts, derived from the session id."""
    return "session-" + (re.sub(r"[^A-Za-z0-9_-]", "_", str(session_id)) or "unknown")


def _peers(session):
    return "%s <-> %s" % (session.get("src_ip") or "?", session.get("dst_ip") or "?")


def _render(header, session_id, settings):
    lines = ["# " + line for line in header]
    lines.append("conn %s" % _conn_name(session_id))
    for key in KEY_ORDER:
        if key in settings:
            value, notes = settings[key]
            lines.extend("    # " + note for note in notes)
            lines.append("    %s=%s" % (key, value))
    return "\n".join(lines) + "\n"


def snippet_for_finding(finding, session=None):
    """The ipsec.conf lines that fix one finding, or "" if no setting applies."""
    session = session if isinstance(session, dict) else {}
    settings = _settings_for(finding, session)
    if not settings:
        return ""
    header = [
        "strongSwan ipsec.conf: fix for %s (%s)"
        % (finding.get("finding_id"), finding.get("category")),
        "Session %s, %s. Merge into that peer's existing conn section."
        % (finding.get("session_id"), _peers(session)),
    ]
    return _render(header, finding.get("session_id"), settings)


def session_config(session, findings):
    """One merged conn block fixing every finding of `session`, or "" if none apply."""
    merged, covered = {}, []
    for finding in findings:
        settings = _settings_for(finding, session)
        if settings:
            covered.append(str(finding.get("finding_id")))
        for key, (value, notes) in settings.items():
            if key not in merged:
                merged[key] = (value, list(notes))
            else:
                # Every category targets the same baseline value, so only the
                # explanatory notes need combining.
                existing = merged[key][1]
                existing.extend(note for note in notes if note not in existing)
    if not merged:
        return ""
    header = [
        "strongSwan ipsec.conf: all fixes for session %s, %s"
        % (session.get("session_id"), _peers(session)),
        "Addresses %s. Merge into that peer's existing conn section." % ", ".join(covered),
    ]
    return _render(header, session.get("session_id"), merged)


def attach(findings, sessions):
    """Add remediation_snippet to copies of `findings`; also build one config per session.

    Returns (findings, remediation_config) where remediation_config is a list of
    {"session_id", "snippet"} for every session that has at least one fix.
    """
    by_id = {s.get("session_id"): s for s in sessions if isinstance(s, dict)}
    result = []
    for finding in findings:
        copy = dict(finding)
        copy["remediation_snippet"] = snippet_for_finding(
            finding, by_id.get(finding.get("session_id"))
        )
        result.append(copy)

    configs = []
    for session in sessions:
        if not isinstance(session, dict):
            continue
        own = [f for f in findings if f.get("session_id") == session.get("session_id")]
        snippet = session_config(session, own)
        if snippet:
            configs.append({"session_id": session.get("session_id"), "snippet": snippet})
    return result, configs
