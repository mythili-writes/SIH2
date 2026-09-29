"""Shared vocabulary for Contract A (parser output) and Contract B (report)."""

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

# Contribution of a single finding to the 0-100 risk score.
SEVERITY_WEIGHT = {"Critical": 40.0, "High": 22.0, "Medium": 10.0, "Low": 3.0}

# Rough CVSS-style base score used for reporting only.
SEVERITY_CVSS = {"Critical": 9.3, "High": 7.5, "Medium": 5.4, "Low": 3.1}

RISK_BANDS = (
    (75.0, "Critical"),
    (50.0, "High"),
    (25.0, "Medium"),
    (0.0, "Low"),
)

TRAFFIC_TYPES = (
    "VoIP",
    "Video Streaming",
    "Bulk File Transfer",
    "Web Browsing",
    "Interactive/Remote Shell",
    "Keepalive/Idle",
)


def risk_level_for(score):
    """Map a 0-100 risk score onto a severity band."""
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "Low"
