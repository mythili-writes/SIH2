"""Offline knowledge base: explanation + remediation text per finding category.

Used by the rule-based fallback so the engine produces a useful report with no
API key present. When an API key is available the LLM rewrites the narrative
fields, but these remain the safety net.
"""

# Keyed by (category, matched keyword in issue) -> falls back to category default.
_EXPLANATIONS = {
    "Encryption": (
        "The tunnel negotiated a symmetric cipher that no longer provides the "
        "effective key strength modern guidance requires. An attacker who can "
        "capture the encrypted flow can retain it and attempt offline recovery "
        "of the plaintext as compute becomes cheaper.",
        "Renegotiate the IPsec proposal to AES-256-GCM (AEAD). If the peer "
        "cannot do GCM, use AES-256-CBC with a separate SHA-256 integrity "
        "algorithm, and remove DES/3DES from the allowed transform set entirely.",
    ),
    "Hash": (
        "The integrity/PRF algorithm in use has known collision weaknesses. A "
        "weak integrity algorithm undermines the authenticity guarantee of the "
        "tunnel: packet tampering becomes cheaper to hide than the cipher "
        "strength alone would suggest.",
        "Move the integrity algorithm to SHA-256 or above (SHA-384/SHA-512). "
        "Delete MD5 and SHA-1 transforms from both the IKE and ESP proposals.",
    ),
    "KeyExchange": (
        "The Diffie-Hellman group used to derive keying material is too small. "
        "Small MODP groups are within reach of well-resourced precomputation "
        "attacks, which would expose every session keyed from that group.",
        "Use DH group 14 (2048-bit MODP) as a minimum; prefer group 19/20 "
        "(ECP-256/384) or group 21. Remove groups 1, 2 and 5 from the policy.",
    ),
    "Authentication": (
        "Peer authentication relies on a pre-shared key. PSKs are commonly "
        "shared across devices, rarely rotated, and — in IKEv1 aggressive mode "
        "— can be captured in a form that permits offline cracking.",
        "Migrate to certificate-based authentication (RSA/ECDSA) with a managed "
        "PKI. Where a PSK must remain, make it at least 32 random characters, "
        "unique per peer, and rotate it on a defined schedule.",
    ),
    "Mode": (
        "The encapsulation mode does not match the deployment pattern. "
        "Transport mode leaves the original IP header exposed, which reveals "
        "the real endpoints of the protected traffic to anyone on path.",
        "Use tunnel mode for any site-to-site or gateway-to-gateway SA so that "
        "the inner IP header is encrypted along with the payload.",
    ),
    "Lifetime": (
        "The SA lifetime is outside the recommended window. Very long lifetimes "
        "increase the volume of data protected by a single key; very short ones "
        "cause constant rekeying that can destabilise the tunnel and burn CPU.",
        "Set the IKE SA lifetime to roughly 24 hours and the IPsec (child) SA "
        "lifetime to 1-8 hours, with a data-volume based rekey limit as well.",
    ),
    "PFS": (
        "Perfect Forward Secrecy is disabled, so child SA keys are derived from "
        "the IKE SA keying material. Compromise of that long-term material "
        "therefore retroactively exposes traffic from every prior session.",
        "Enable PFS on the child SA and pin it to DH group 14 or higher so each "
        "rekey performs a fresh Diffie-Hellman exchange.",
    ),
    "Protocol": (
        "The tunnel uses IKEv1, which is deprecated. IKEv1 lacks the built-in "
        "DoS protection, reliable rekeying and MOBIKE support of IKEv2, and its "
        "aggressive mode transmits identity material before encryption starts.",
        "Migrate the tunnel to IKEv2. If IKEv1 must remain during transition, "
        "disable aggressive mode and permit main mode only.",
    ),
    "ReplayProtection": (
        "Anti-replay is not in effect for this SA. Without a replay window an "
        "attacker who can capture ESP packets can retransmit them, and the "
        "receiver will accept and process the duplicates.",
        "Enable anti-replay on the SA and set the replay window to at least "
        "1024 packets (larger for high-throughput or multi-queue links).",
    ),
    "MetadataExposure": (
        "Endpoint identity material is observable in the negotiation. This lets "
        "a passive observer map which peers talk to which gateways, and gives "
        "an attacker the identity values needed to target credential attacks.",
        "Use IKEv2 (which encrypts identity payloads) or IKEv1 main mode, and "
        "avoid FQDN/user-FQDN identities that disclose organisational detail.",
    ),
    "Compliance": (
        "The negotiated cipher suite falls outside the approved baseline "
        "(AES-GCM / AES-256 with SHA-256 or stronger). Even where no single "
        "parameter is critical, the combination will not pass an audit against "
        "current hardening guidance.",
        "Align the proposal with the approved baseline: AES-256-GCM, SHA-256+, "
        "DH group 14/19+, IKEv2, PFS enabled, certificate authentication.",
    ),
}

_REFERENCES = {
    "Encryption": ["NIST SP 800-77 Rev.1 §3.2", "RFC 8221 §5"],
    "Hash": ["NIST SP 800-131A Rev.2", "RFC 8247 §2.2"],
    "KeyExchange": ["RFC 8247 §2.4", "NIST SP 800-57 Part 1 Rev.5"],
    "Authentication": ["NIST SP 800-77 Rev.1 §4.3", "RFC 8247 §2.3"],
    "Mode": ["RFC 4301 §4.1", "NIST SP 800-77 Rev.1 §3.1"],
    "Lifetime": ["NIST SP 800-77 Rev.1 §4.5", "RFC 4301 §4.4.2"],
    "PFS": ["RFC 7296 §1.3.2", "NIST SP 800-77 Rev.1 §4.4"],
    "Protocol": ["RFC 9395 (IKEv1 deprecation)", "RFC 7296"],
    "ReplayProtection": ["RFC 4303 §3.4.3", "NIST SP 800-77 Rev.1 §3.3"],
    "MetadataExposure": ["RFC 7296 §3.5", "RFC 2409 §5.4"],
    "Compliance": ["NIST SP 800-77 Rev.1", "RFC 8221"],
}

# Threat-matrix placement per category: (likelihood, impact, threat name).
_THREATS = {
    "Encryption": ("High", "Critical", "Offline decryption of captured tunnel traffic"),
    "Hash": ("Medium", "High", "Integrity forgery / packet tampering"),
    "KeyExchange": ("Medium", "Critical", "Key recovery via DH precomputation"),
    "Authentication": ("High", "High", "PSK cracking leading to peer impersonation"),
    "Mode": ("Medium", "Low", "Endpoint disclosure via exposed inner header"),
    "Lifetime": ("Low", "Medium", "Extended key exposure window"),
    "PFS": ("Medium", "High", "Retrospective decryption after key compromise"),
    "Protocol": ("High", "Medium", "Exploitation of deprecated IKEv1 weaknesses"),
    "ReplayProtection": ("Medium", "Medium", "Packet replay injection"),
    "MetadataExposure": ("High", "Low", "Passive identity and topology mapping"),
    "Compliance": ("High", "Medium", "Audit failure against hardening baseline"),
}

_DEFAULT = (
    "This configuration parameter deviates from current IPsec hardening "
    "guidance and weakens the security posture of the tunnel.",
    "Review the parameter against NIST SP 800-77 Rev.1 and align it with the "
    "approved cipher suite baseline.",
)


def explain(category):
    """Return (explanation, recommendation) prose for a finding category."""
    return _EXPLANATIONS.get(category, _DEFAULT)


def references_for(category):
    return list(_REFERENCES.get(category, ["NIST SP 800-77 Rev.1"]))


def threat_for(category):
    """Return (likelihood, impact, threat_name) for the threat matrix."""
    return _THREATS.get(category, ("Medium", "Medium", "Weak IPsec configuration"))
