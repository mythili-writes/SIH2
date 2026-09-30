"""Computes risk scores, AI confidence and a threat matrix from sessions and findings.

Usage: python ai_engine/scorer.py <analysis.json>
"""

import json
import math
import os
import sys
from statistics import mean

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:  # also works when this file is run as a script
    sys.path.insert(0, _REPO_ROOT)

import config  # noqa: E402  (repo-root config.py: the single source of settings)

SEVERITY_SCORE = {"Critical": 95, "High": 75, "Medium": 50, "Low": 25}
DEFAULT_SCORE = 25

# Worst first. Unknown severities are treated as Low.
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

SEVERITY_TO_LIKELIHOOD = {"Critical": "High", "High": "High", "Medium": "Medium", "Low": "Low"}

# category -> (threat, impact)
THREATS = {
    "Encryption": ("Downgrade / weak cipher attack", "High"),
    "Hash": ("Integrity forgery / collision attack", "High"),
    "KeyExchange": ("Key recovery via weak Diffie-Hellman", "High"),
    "Authentication": ("Pre-shared key brute force", "High"),
    "Mode": ("Traffic exposure from wrong IPsec mode", "Medium"),
    "Lifetime": ("Long key exposure window", "Medium"),
    "PFS": ("Retroactive decryption without forward secrecy", "High"),
    "Protocol": ("Legacy IKE protocol attack", "High"),
    "ReplayProtection": ("Replay attack", "Medium"),
    "MetadataExposure": ("Identity and metadata leakage", "Medium"),
    "Compliance": ("Regulatory non-compliance", "Medium"),
}
UNKNOWN_THREAT = ("Other security weakness", "Medium")

LEVEL_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _severity_score(finding):
    return SEVERITY_SCORE.get(finding.get("severity"), DEFAULT_SCORE)


def score_findings(findings):
    """Return copies of the findings with an int "risk_score" added. The input is not changed."""
    scored = []
    for finding in findings:
        copy = dict(finding)
        copy["risk_score"] = _severity_score(finding)
        scored.append(copy)
    return scored


def overall_risk(findings):
    """Return (score, level) for the whole analysis. score is an int from 0 to 100."""
    if not findings:
        return 5, "Low"

    scores = [_severity_score(f) for f in findings]
    severe_count = sum(1 for f in findings if f.get("severity") in ("Critical", "High"))
    raw = 0.6 * max(scores) + 0.4 * mean(scores) + min(15, 3 * severe_count)
    score = max(0, min(100, int(round(raw))))
    return score, risk_level(score)


def risk_level(score):
    """Map a 0-100 score to Critical/High/Medium/Low using config.RISK_LEVEL_THRESHOLDS."""
    for level, threshold in config.RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "Low"


def ai_confidence(sessions, traffic_confidences=None):
    """Blend parser confidence with traffic-model confidence. Returns a float from 0 to 1, 2 decimals.

    Values that are not finite numbers are ignored rather than trusted: a NaN would
    otherwise survive the final clamp as 1.0, because min(1.0, nan) is 1.0.
    """
    parser_values = [
        s.get("confidence")
        for s in sessions or []
        if isinstance(s, dict) and _finite_number(s.get("confidence"))
    ]
    parser_conf = mean(parser_values) if parser_values else 0.5

    traffic_values = [c for c in traffic_confidences or [] if _finite_number(c)]
    if traffic_values:
        result = 0.5 * parser_conf + 0.5 * mean(traffic_values)
    else:
        result = parser_conf
    return round(max(0.0, min(1.0, result)), 2)


def _finite_number(value):
    """True for an int or float that is finite; False for bools, strings, None, NaN, inf."""
    return (
        isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    )


def build_threat_matrix(findings):
    """Group findings by category into threats, sorted by likelihood then impact (High first)."""
    groups = {}
    for finding in findings:
        groups.setdefault(finding.get("category"), []).append(finding)

    matrix = []
    for category, group in groups.items():
        worst = min((f.get("severity") for f in group), key=lambda s: SEVERITY_RANK.get(s, 3))
        threat, impact = THREATS.get(category, UNKNOWN_THREAT)
        matrix.append({
            "threat": threat,
            "category": category,
            "likelihood": SEVERITY_TO_LIKELIHOOD.get(worst, "Low"),
            "impact": impact,
            "related_findings": [f.get("finding_id") for f in group],
        })

    matrix.sort(key=lambda row: (LEVEL_ORDER[row["likelihood"]], LEVEL_ORDER[row["impact"]]))
    return matrix


def main():
    """CLI: print the risk score, confidence and threat matrix for a Contract A file."""
    from logging_setup import configure_logging

    configure_logging()
    if len(sys.argv) != 2:
        print("Usage: python ai_engine/scorer.py <analysis.json>")
        sys.exit(2)

    with open(sys.argv[1], encoding="utf-8") as f:
        analysis = json.load(f)
    findings = analysis.get("findings", [])
    sessions = analysis.get("sessions", [])

    score, level = overall_risk(findings)
    print(f"Overall risk score: {score}")
    print(f"Risk level:         {level}")
    print(f"AI confidence:      {ai_confidence(sessions)}")

    print("\nFindings:")
    for finding in score_findings(findings):
        print(f"  {finding.get('finding_id')}  {str(finding.get('severity')):<8}  risk_score={finding['risk_score']}")

    print("\nThreat matrix:")
    for row in build_threat_matrix(findings):
        print(f"  [{row['likelihood']:<6} likelihood / {row['impact']:<6} impact]  "
              f"{row['category']}: {row['threat']}  -> {', '.join(map(str, row['related_findings']))}")


if __name__ == "__main__":
    main()
