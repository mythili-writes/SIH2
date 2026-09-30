"""Assembles the final AI report from model, scorer and explainer outputs.

Builds the plain-English executive report, the per-session technical report and a one-line summary.
"""

MAX_ITEMS = 5
SEVERE = ("Critical", "High")
COMPLIANCE_CATEGORIES = ("Encryption", "Hash", "KeyExchange", "Protocol")
NO_SESSIONS_TEXT = "No IPsec sessions found."

HEADLINES = {
    "Critical": "The VPN has serious security flaws and needs to be fixed right away",
    "High": "The VPN is not safe to use in its current setup",
    "Medium": "The VPN works but has weaknesses that should be fixed soon",
    "Low": "The VPN is set up well, with only minor issues",
}
NO_FINDINGS_HEADLINE = "No major weaknesses were found in the VPN setup"

# category -> plain sentence; {who} is e.g. "session 1" or "sessions 1 and 2".
KEY_POINTS = {
    "Encryption": "The encryption in {who} is weaker than current standards.",
    "Hash": "The integrity check in {who} is weak, so data could be changed without anyone noticing.",
    "KeyExchange": "The key exchange in {who} is too weak and could let attackers work out the keys.",
    "Authentication": "The VPN login in {who} uses a shared password instead of certificates.",
    "Protocol": "The VPN protocol setup in {who} is old and has known weaknesses.",
    "PFS": "Recorded traffic from {who} could be decrypted later if a key is ever stolen.",
    "Lifetime": "The encryption keys in {who} are kept for too long or changed too often.",
    "ReplayProtection": "Nothing in {who} stops attackers from resending captured packets.",
    "MetadataExposure": "The identity of the devices in {who} is visible to anyone watching the network.",
    "Mode": "The real addresses of the devices in {who} are visible to anyone watching the network.",
    "Compliance": "The security settings in {who} do not meet required standards.",
}

# category -> what could happen to the business if it is not fixed.
IMPACTS = {
    "Authentication": "attackers could join the VPN",
    "Protocol": "attackers could join the VPN",
    "Encryption": "company data could be read or changed",
    "Hash": "company data could be read or changed",
    "KeyExchange": "company data could be read or changed",
    "PFS": "recorded traffic could be read later",
    "MetadataExposure": "outsiders can see who is using the VPN",
    "Mode": "outsiders can see who is using the VPN",
    "ReplayProtection": "old packets could be replayed",
    "Lifetime": "a stolen key would expose more traffic",
    "Compliance": "the setup may fail security audits",
}
MAX_IMPACTS = 3
GENERIC_IMPACT = "These weaknesses make the VPN easier to attack."
NO_FINDINGS_IMPACT = "No major weaknesses were found, so the VPN setup adds little business risk."
NO_FINDINGS_ACTION = "Keep the current settings and re-check them after any configuration change."


def _join(items):
    """["a"] -> "a", ["a", "b"] -> "a and b", ["a", "b", "c"] -> "a, b and c"."""
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _unique(values):
    seen, result = set(), []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _known(value):
    """Return value, or None if it is missing or means "unknown"."""
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in ("", "unknown", "none", "null"):
        return None
    return value


def _text(value, unknown="unknown"):
    value = _known(value)
    return unknown if value is None else str(value)


def _mode(value):
    value = _known(value)
    return "(mode unknown)" if value is None else f"{value} Mode"


def _on_off(value):
    if value is True:
        return "on"
    if value is False:
        return "off"
    return "unknown"


def _worst_first(findings):
    return sorted(findings, key=lambda f: -(f.get("risk_score") or 0))


def _who(session_ids):
    ids = [str(i) for i in _unique(session_ids) if i is not None]
    if not ids:
        return "the VPN"
    return f"session {ids[0]}" if len(ids) == 1 else f"sessions {_join(ids)}"


def _traffic_types(traffic_analysis):
    return _unique(
        t.get("predicted_traffic_type")
        for t in traffic_analysis
        if _known(t.get("predicted_traffic_type"))
    )


def build_executive_report(findings, risk_score, risk_level, traffic_analysis):
    """Return {"headline", "key_points", "business_impact", "top_actions"} in plain English."""
    types = _traffic_types(traffic_analysis)
    traffic_sentence = (
        f" Even though the traffic is encrypted, an observer can still tell that it carries "
        f"{_join(types)} traffic from packet sizes and timing."
        if types
        else ""
    )

    if not findings:
        return {
            "headline": f"{NO_FINDINGS_HEADLINE} (risk score {risk_score}/100).",
            "key_points": ["No major weaknesses were found."],
            "business_impact": NO_FINDINGS_IMPACT + traffic_sentence,
            "top_actions": [NO_FINDINGS_ACTION],
        }

    worst = _worst_first(findings)

    # One point per category, worst first, naming every session that has it.
    groups = {}
    for finding in worst:
        groups.setdefault(finding.get("category"), []).append(finding)
    key_points = []
    for category, group in list(groups.items())[:MAX_ITEMS]:
        who = _who(f.get("session_id") for f in group)
        if category in KEY_POINTS:
            key_points.append(KEY_POINTS[category].format(who=who))
        else:
            issue = str(group[0].get("issue") or "A security weakness was found").rstrip(".")
            key_points.append(f"{issue} ({who}).")

    impacts = _unique(IMPACTS[f.get("category")] for f in worst if f.get("category") in IMPACTS)[
        :MAX_IMPACTS
    ]
    if impacts:
        business_impact = f"If these weaknesses are not fixed, {_join(impacts)}." + traffic_sentence
    else:
        business_impact = GENERIC_IMPACT + traffic_sentence

    top_actions, seen = [], set()
    for finding in worst:
        action = (finding.get("recommendation") or "").strip()
        if action and action.lower() not in seen:
            seen.add(action.lower())
            top_actions.append(action)
        if len(top_actions) == MAX_ITEMS:
            break

    headline = HEADLINES.get(risk_level, HEADLINES["High"])
    return {
        "headline": f"{headline} (risk score {risk_score}/100).",
        "key_points": key_points,
        "business_impact": business_impact,
        "top_actions": top_actions,
    }


def build_technical_report(sessions, findings, ip_version):
    """Return the five technical strings, one "Session N: ..." part per session joined with " | "."""
    sessions = [s for s in sessions if isinstance(s, dict)]
    if not sessions:
        return {
            key: NO_SESSIONS_TEXT
            for key in (
                "protocol_identification",
                "cipher_suite_analysis",
                "sa_analysis",
                "metadata_exposure",
                "compliance_notes",
            )
        }

    protocol, cipher, sa, exposed, compliance = [], [], [], [], []
    for s in sessions:
        sid = _text(s.get("session_id"))
        protocol.append(
            f"Session {sid}: {_text(s.get('protocol'), 'unknown IKE version')} {_mode(s.get('exchange_mode'))}, "
            f"{_text(s.get('ipsec_protocol'), 'unknown IPsec protocol')} {_mode(s.get('ipsec_mode'))} "
            f"over {_text(ip_version, 'unknown IP version')}"
        )
        cipher.append(
            f"Session {sid}: {_text(s.get('encryption'), 'unknown cipher')} + "
            f"{_text(s.get('authentication'), 'unknown integrity algorithm')}, "
            f"hash {_text(s.get('hash'))}, DH group {_text(s.get('dh_group'))}"
        )
        lifetime = _known(s.get("lifetime_seconds"))
        sa.append(
            f"Session {sid}: lifetime {'unknown' if lifetime is None else f'{lifetime} s'}, "
            f"replay protection {_on_off(s.get('replay_protection'))}, PFS {_on_off(s.get('pfs_enabled'))}, "
            f"NAT-T {_on_off(s.get('nat_traversal'))}"
        )
        if s.get("identity_exposed") is True:
            exposed.append(
                f"Session {sid}: peer identity is sent in clear and visible to eavesdroppers"
            )

        failing = _unique(
            f.get("category")
            for f in findings
            if f.get("session_id") == s.get("session_id")
            and f.get("severity") in SEVERE
            and f.get("category") in COMPLIANCE_CATEGORIES
        )
        if failing:
            compliance.append(
                f"Session {sid}: fails NIST SP 800-131A and SP 800-77r1 guidance ({', '.join(failing)})"
            )
        else:
            compliance.append(f"Session {sid}: meets the checked NIST guidance")

    if not exposed:
        exposed.append("No session sends its peer identity in clear")
    exposed.append(
        "Traffic type can still be inferred from packet sizes and timing even though ESP is encrypted"
    )

    return {
        "protocol_identification": " | ".join(protocol),
        "cipher_suite_analysis": " | ".join(cipher),
        "sa_analysis": " | ".join(sa),
        "metadata_exposure": " | ".join(exposed),
        "compliance_notes": " | ".join(compliance),
    }


def build_uncertainty_notes(sessions):
    """Per session: how many values were observed directly, which were inferred and why.

    One "Session N: ..." part per session joined with " | ", like the other
    technical report strings. Built from sessions[].field_provenance.
    """
    sessions = [s for s in sessions if isinstance(s, dict)]
    if not sessions:
        return NO_SESSIONS_TEXT

    parts = []
    for s in sessions:
        sid = _text(s.get("session_id"))
        provenance = s.get("field_provenance")
        if not isinstance(provenance, dict) or not provenance:
            parts.append(f"Session {sid}: the parser did not report how each value was obtained")
            continue
        entries = [(f, e) for f, e in provenance.items() if isinstance(e, dict)]
        observed = [f for f, e in entries if e.get("status") == "observed"]
        inferred = [(f, e.get("basis") or "") for f, e in entries if e.get("status") == "inferred"]
        unknown = [f for f, e in entries if e.get("status") == "unknown"]

        text = f"Session {sid}: {len(observed)} of {len(entries)} values observed directly"
        if inferred:
            text += "; inferred, not observed: " + "; ".join(
                f"{f} ({basis})" for f, basis in inferred
            )
        if unknown:
            text += "; not determined: " + ", ".join(unknown)
        parts.append(text)
    return " | ".join(parts)


def build_summary(risk_level, findings, traffic_analysis):
    """Return one plain sentence describing the overall result."""
    if findings:
        severe = sum(1 for f in findings if f.get("severity") in SEVERE)
        issues = f"{len(findings)} weakness{'es' if len(findings) != 1 else ''} found ({severe} high or critical)"
    else:
        issues = "no major weaknesses were found"
    types = _traffic_types(traffic_analysis)
    traffic = f", and the traffic looks like {_join(types)}" if types else ""
    return f"Overall risk is {str(risk_level).lower()}: {issues}{traffic}."
