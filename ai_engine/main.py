#!/usr/bin/env python3
"""IPsec AI analysis engine: Contract A (parser output) -> Contract B (report).

Usage
-----
    python ai_engine/main.py analysis.json report.json [--offline]

Programmatic
------------
    from ai_engine.main import run
    report = run(analysis_dict, offline=True)

The engine is deterministic and fully functional with no network access. When
ANTHROPIC_API_KEY is present (and --offline is not passed) the narrative fields
are rewritten by Claude; every numeric field is still computed locally so the
report shape never depends on the model being reachable.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

if __package__ in (None, ""):  # allow `python ai_engine/main.py`
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from ai_engine import knowledge, traffic
    from ai_engine.contracts import (
        CATEGORIES,
        SEVERITIES,
        SEVERITY_CVSS,
        SEVERITY_WEIGHT,
        risk_level_for,
    )
else:
    from . import knowledge, traffic
    from .contracts import (
        CATEGORIES,
        SEVERITIES,
        SEVERITY_CVSS,
        SEVERITY_WEIGHT,
        risk_level_for,
    )

SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

def _severity_counts(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


def _score_from_findings(findings):
    """0-100 risk score with diminishing returns per additional finding.

    The first finding of a severity contributes its full weight; each repeat
    contributes less, so a config with six Medium issues does not outrank one
    with a single Critical.
    """
    by_sev = {s: [] for s in SEVERITIES}
    for f in findings:
        if f.get("severity") in by_sev:
            by_sev[f["severity"]].append(f)

    raw = 0.0
    for sev, items in by_sev.items():
        weight = SEVERITY_WEIGHT[sev]
        for index in range(len(items)):
            raw += weight * (0.55 ** index)

    # Squash to 0-100; 62 raw points lands at ~75 (the Critical band edge).
    score = 100.0 * (1.0 - pow(2.718281828, -raw / 45.0))
    return round(min(99.9, score), 1)


def _session_score(session, findings):
    sid = session.get("session_id")
    relevant = [f for f in findings if f.get("session_id") == sid]
    score = _score_from_findings(relevant)
    return score, risk_level_for(score), relevant


def _confidence(analysis, findings):
    """How much to trust this report, given parser confidence and coverage."""
    sessions = analysis.get("sessions") or []
    if sessions:
        confidences = []
        for s in sessions:
            c = s.get("confidence")
            confidences.append(float(c) if isinstance(c, (int, float)) else 0.4)
        parser_conf = sum(confidences) / len(confidences)
    else:
        parser_conf = 0.2

    # Penalise sessions whose key parameters came back Unknown.
    unknown_penalty = 0.0
    checked = ("encryption", "hash", "dh_group", "protocol", "auth_method")
    if sessions:
        total_fields = len(sessions) * len(checked)
        unknowns = sum(
            1
            for s in sessions
            for k in checked
            if s.get(k) in (None, "Unknown", "unknown")
        )
        unknown_penalty = 0.35 * (unknowns / total_fields) if total_fields else 0.0

    evidence_bonus = 0.05 if findings else 0.0
    return round(max(0.05, min(0.98, parser_conf - unknown_penalty + evidence_bonus)), 3)


# --------------------------------------------------------------------------
# enrichment
# --------------------------------------------------------------------------

def _normalise_finding(raw, index):
    severity = raw.get("severity")
    if severity not in SEVERITIES:
        severity = "Medium"
    category = raw.get("category")
    if category not in CATEGORIES:
        category = "Compliance"

    explanation, recommendation = knowledge.explain(category)
    return {
        "finding_id": raw.get("finding_id") or "F%03d" % (index + 1),
        "session_id": raw.get("session_id"),
        "category": category,
        "issue": raw.get("issue") or "Unspecified IPsec configuration weakness",
        "severity": severity,
        "evidence": raw.get("evidence") or "Derived from IKE/ESP negotiation metadata.",
        "explanation": explanation,
        "recommendation": recommendation,
        "cvss_estimate": SEVERITY_CVSS[severity],
        "references": knowledge.references_for(category),
    }


def _build_traffic_analysis(analysis):
    out = []
    for session in analysis.get("sessions") or []:
        features = session.get("traffic_features") or {}
        predicted, confidence, top = traffic.classify(features)
        out.append(
            {
                "session_id": session.get("session_id"),
                "src_ip": session.get("src_ip"),
                "dst_ip": session.get("dst_ip"),
                "predicted_traffic_type": predicted,
                "traffic_confidence": confidence,
                "top_predictions": top,
                "traffic_features": features,
                "metadata_inference": traffic.infer_metadata(features, session),
            }
        )
    return out


def _build_threat_matrix(findings):
    likelihood_axis = ["Low", "Medium", "High"]
    impact_axis = ["Low", "Medium", "High", "Critical"]

    entries = []
    seen = {}
    for f in findings:
        likelihood, impact, threat = knowledge.threat_for(f["category"])
        key = (threat, likelihood, impact)
        if key in seen:
            seen[key]["related_findings"].append(f["finding_id"])
            continue
        entry = {
            "threat": threat,
            "category": f["category"],
            "likelihood": likelihood,
            "impact": impact,
            "severity": f["severity"],
            "related_findings": [f["finding_id"]],
        }
        seen[key] = entry
        entries.append(entry)

    cells = []
    for likelihood in likelihood_axis:
        for impact in impact_axis:
            matched = [
                e["threat"]
                for e in entries
                if e["likelihood"] == likelihood and e["impact"] == impact
            ]
            cells.append(
                {
                    "likelihood": likelihood,
                    "impact": impact,
                    "count": len(matched),
                    "threats": matched,
                }
            )

    return {
        "axes": {"likelihood": likelihood_axis, "impact": impact_axis},
        "entries": entries,
        "cells": cells,
    }


def _build_sessions(analysis, findings):
    out = []
    for session in analysis.get("sessions") or []:
        score, level, related = _session_score(session, findings)
        out.append(
            {
                "session_id": session.get("session_id"),
                "src_ip": session.get("src_ip"),
                "dst_ip": session.get("dst_ip"),
                "protocol": session.get("protocol", "Unknown"),
                "exchange_mode": session.get("exchange_mode", "Unknown"),
                "ipsec_mode": session.get("ipsec_mode", "Unknown"),
                "encryption": session.get("encryption", "Unknown"),
                "hash": session.get("hash", "Unknown"),
                "dh_group": session.get("dh_group"),
                "auth_method": session.get("auth_method", "Unknown"),
                "lifetime_seconds": session.get("lifetime_seconds"),
                "pfs_enabled": session.get("pfs_enabled"),
                "nat_traversal": session.get("nat_traversal"),
                "identity_exposed": session.get("identity_exposed"),
                "replay_protection": session.get("replay_protection"),
                "parser_confidence": session.get("confidence"),
                "session_risk_score": score,
                "session_risk_level": level,
                "finding_count": len(related),
            }
        )
    return out


# --------------------------------------------------------------------------
# narrative (offline rule-based)
# --------------------------------------------------------------------------

def _summary_text(analysis, findings, score, level, counts):
    name = analysis.get("file_name", "capture")
    n_sessions = len(analysis.get("sessions") or [])
    if not findings:
        return (
            "Analysis of %s found %d IPsec session(s) with no configuration "
            "weaknesses against the current rule set. The negotiated parameters "
            "are consistent with the approved cipher suite baseline. Overall "
            "risk score %.1f/100 (%s)." % (name, n_sessions, score, level)
        )

    worst = [f for f in findings if f["severity"] == "Critical"] or [
        f for f in findings if f["severity"] == "High"
    ]
    lead = worst[0]["issue"] if worst else findings[0]["issue"]
    breakdown = ", ".join(
        "%d %s" % (counts[s], s) for s in SEVERITIES if counts[s]
    )
    return (
        "Analysis of %s identified %d finding(s) across %d IPsec session(s) "
        "(%s). The most significant issue is: %s. The combination of weaknesses "
        "places this deployment at an overall risk score of %.1f/100 (%s). "
        "Remediation should begin with the highest-severity cryptographic "
        "parameters before addressing policy and hygiene items."
        % (name, len(findings), n_sessions, breakdown, lead, score, level)
    )


def _key_risks(findings):
    order = {s: i for i, s in enumerate(SEVERITIES)}
    ranked = sorted(findings, key=lambda f: order.get(f["severity"], 9))
    risks = []
    for f in ranked[:5]:
        risks.append(
            {
                "severity": f["severity"],
                "category": f["category"],
                "risk": f["issue"],
                "why_it_matters": f["explanation"].split(". ")[0] + ".",
            }
        )
    return risks


def _business_impact(level, counts):
    if level == "Critical":
        return (
            "Traffic crossing these tunnels should be treated as potentially "
            "recoverable by a capable adversary. Any regulated or commercially "
            "sensitive data carried over the VPN is exposed to interception risk, "
            "and the configuration would not survive a security audit."
        )
    if level == "High":
        return (
            "Material weaknesses are present. Confidentiality of tunnel traffic "
            "depends on parameters that current guidance considers inadequate, "
            "creating both breach exposure and compliance findings at audit."
        )
    if level == "Medium":
        return (
            "The tunnels are broadly functional but carry hygiene and policy gaps "
            "that increase exposure over time and are likely to be raised as "
            "observations during a security review."
        )
    return (
        "No material exposure identified. The configuration is consistent with "
        "current hardening guidance; maintain the posture through periodic review."
    )


def _recommended_actions(findings):
    order = {s: i for i, s in enumerate(SEVERITIES)}
    ranked = sorted(findings, key=lambda f: order.get(f["severity"], 9))
    actions, seen = [], set()
    timeline = {
        "Critical": "Immediate (0-7 days)",
        "High": "Short term (1-4 weeks)",
        "Medium": "Planned (1-3 months)",
        "Low": "Routine maintenance",
    }
    for f in ranked:
        if f["category"] in seen:
            continue
        seen.add(f["category"])
        actions.append(
            {
                "priority": len(actions) + 1,
                "timeline": timeline.get(f["severity"], "Planned"),
                "area": f["category"],
                "action": f["recommendation"],
                "addresses": f["finding_id"],
            }
        )
    return actions


def _compliance_posture(findings, counts):
    failing = sorted({f["category"] for f in findings})
    if not failing:
        return {
            "baseline": "NIST SP 800-77 Rev.1 / RFC 8221",
            "status": "Pass",
            "failing_controls": [],
            "note": "Negotiated parameters meet the approved cipher suite baseline.",
        }
    status = "Fail" if (counts["Critical"] or counts["High"]) else "Partial"
    return {
        "baseline": "NIST SP 800-77 Rev.1 / RFC 8221",
        "status": status,
        "failing_controls": failing,
        "note": (
            "%d control area(s) deviate from the baseline; %d high-or-critical "
            "finding(s) must be closed before the deployment can be considered "
            "compliant." % (len(failing), counts["Critical"] + counts["High"])
        ),
    }


def _build_executive_report(analysis, findings, score, level, counts, summary):
    return {
        "title": "IPsec VPN Security Assessment - Executive Summary",
        "source_capture": analysis.get("file_name", "capture"),
        "assessment_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "overall_risk_score": score,
        "risk_level": level,
        "headline": (
            "%s risk: %d finding(s) across %d session(s)"
            % (level, len(findings), len(analysis.get("sessions") or []))
        ),
        "summary": summary,
        "severity_breakdown": counts,
        "key_risks": _key_risks(findings),
        "business_impact": _business_impact(level, counts),
        "recommended_actions": _recommended_actions(findings),
        "compliance_posture": _compliance_posture(findings, counts),
        "next_steps": [
            "Approve the remediation plan and assign an owner per action area.",
            "Schedule a maintenance window to renegotiate the affected tunnels.",
            "Re-capture and re-run this assessment after the change to confirm closure.",
        ],
        "scope_note": (
            "This assessment identifies, scores and explains IPsec configuration "
            "weaknesses from passive traffic capture. It does not modify or "
            "auto-patch any VPN device."
        ),
    }


def _build_technical_report(analysis, findings, sessions, traffic_analysis, matrix, score, level):
    summary = analysis.get("packet_summary") or {}
    return {
        "title": "IPsec VPN Security Assessment - Technical Detail",
        "methodology": (
            "Passive analysis of a packet capture. IKEv1/IKEv2 negotiation "
            "payloads are parsed for the agreed transform set; ESP and AH flows "
            "are measured for encapsulation mode, sequence-number behaviour and "
            "statistical traffic features. Findings are produced by a "
            "deterministic rule engine and scored by severity with diminishing "
            "returns. ESP payloads are never decrypted."
        ),
        "environment": {
            "source_capture": analysis.get("file_name", "capture"),
            "total_packets": analysis.get("total_packets", 0),
            "ip_version": analysis.get("ip_version", "Unknown"),
            "ike_packets": summary.get("ike_packets", 0),
            "esp_packets": summary.get("esp_packets", 0),
            "ah_packets": summary.get("ah_packets", 0),
            "other_packets": summary.get("other_packets", 0),
            "sessions_analysed": len(sessions),
        },
        "overall_risk_score": score,
        "risk_level": level,
        "findings_detail": findings,
        "session_details": sessions,
        "traffic_analysis": traffic_analysis,
        "threat_matrix": matrix,
        "remediation_plan": _recommended_actions(findings),
        "detection_notes": [
            "Alert on IKEv1 aggressive mode exchanges (UDP/500) originating from any gateway.",
            "Flag ESP SAs whose sequence numbers reset or regress, which indicates replay exposure.",
            "Baseline per-tunnel packet-size distributions; a shift can reveal an application change behind the tunnel.",
            "Track IKE proposals offering DES/3DES/MD5/DH1/DH2 and treat any acceptance as a policy violation.",
        ],
        "limitations": [
            "Parameters that never appear on the wire (for example a locally configured SA lifetime that is not negotiated) are reported as Unknown.",
            "Encapsulation mode and anti-replay status are inferred from ESP structure and sequence behaviour, not read from configuration.",
            "Traffic classification is probabilistic and based only on size/timing metadata.",
        ],
        "appendix": {
            "severity_model": SEVERITY_WEIGHT,
            "schema_version": SCHEMA_VERSION,
        },
    }


# --------------------------------------------------------------------------
# optional LLM narrative pass
# --------------------------------------------------------------------------

def _llm_enrich(report, model="claude-sonnet-5"):
    """Rewrite narrative fields with Claude. Any failure leaves the report as-is."""
    try:
        import anthropic
    except ImportError:
        report["mode"] = "offline"
        report["ai_notes"] = "anthropic SDK not installed; used rule-based narrative."
        return report

    payload = {
        "overall_risk_score": report["overall_risk_score"],
        "risk_level": report["risk_level"],
        "findings": [
            {k: f[k] for k in ("finding_id", "category", "issue", "severity", "evidence")}
            for f in report["findings"]
        ],
        "sessions": report["sessions"],
        "traffic_analysis": [
            {
                "session_id": t["session_id"],
                "predicted_traffic_type": t["predicted_traffic_type"],
                "traffic_confidence": t["traffic_confidence"],
            }
            for t in report["traffic_analysis"]
        ],
    }

    prompt = (
        "You are a senior network security analyst reviewing an IPsec VPN "
        "assessment. Here is the machine-generated finding set:\n\n"
        + json.dumps(payload, indent=2)
        + "\n\nReturn ONLY a JSON object with these keys:\n"
        '  "summary": a 3-5 sentence technical summary,\n'
        '  "business_impact": 2-3 sentences for a non-technical executive,\n'
        '  "headline": one short sentence.\n'
        "Do not invent findings that are not in the data. Do not wrap the JSON "
        "in markdown fences."
    )

    try:
        client = anthropic.Anthropic()
        response = client.messages.create(
            model=model,
            max_tokens=1200,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in response.content if block.type == "text").strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            text = text[4:] if text.startswith("json") else text
        data = json.loads(text)
    except Exception as exc:  # network, auth, parse - all non-fatal
        report["mode"] = "offline"
        report["ai_notes"] = "LLM enrichment failed (%s); used rule-based narrative." % type(exc).__name__
        return report

    if isinstance(data.get("summary"), str):
        report["summary"] = data["summary"]
        report["executive_report"]["summary"] = data["summary"]
    if isinstance(data.get("business_impact"), str):
        report["executive_report"]["business_impact"] = data["business_impact"]
    if isinstance(data.get("headline"), str):
        report["executive_report"]["headline"] = data["headline"]

    report["mode"] = "llm"
    report["ai_notes"] = "Narrative fields generated by %s; all scores computed locally." % model
    return report


# --------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------

def run(analysis, offline=False, model="claude-sonnet-5"):
    """Turn a Contract A analysis dict into a Contract B report dict."""
    if not isinstance(analysis, dict):
        raise TypeError("analysis must be a dict conforming to Contract A")

    raw_findings = analysis.get("findings") or []
    findings = [_normalise_finding(f, i) for i, f in enumerate(raw_findings)]

    counts = _severity_counts(findings)
    score = _score_from_findings(findings)
    level = risk_level_for(score)
    confidence = _confidence(analysis, findings)

    sessions = _build_sessions(analysis, findings)
    traffic_analysis = _build_traffic_analysis(analysis)
    matrix = _build_threat_matrix(findings)
    summary = _summary_text(analysis, findings, score, level, counts)

    seed = json.dumps(analysis, sort_keys=True, default=str).encode("utf-8")
    report = {
        "schema_version": SCHEMA_VERSION,
        "report_id": "RPT-" + hashlib.sha256(seed).hexdigest()[:12].upper(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": analysis.get("file_name", "capture"),
        "mode": "offline",
        "overall_risk_score": score,
        "risk_level": level,
        "ai_confidence_score": confidence,
        "summary": summary,
        "severity_breakdown": counts,
        "findings": findings,
        "sessions": sessions,
        "traffic_analysis": traffic_analysis,
        "threat_matrix": matrix,
        "executive_report": _build_executive_report(
            analysis, findings, score, level, counts, summary
        ),
        "technical_report": _build_technical_report(
            analysis, findings, sessions, traffic_analysis, matrix, score, level
        ),
        "ai_notes": "Rule-based analysis; no model call made.",
    }

    use_llm = not offline and os.environ.get("ANTHROPIC_API_KEY")
    if use_llm:
        report = _llm_enrich(report, model=model)

    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="IPsec AI analysis engine (Contract A -> Contract B)."
    )
    parser.add_argument("input", help="Contract A analysis JSON from backend/main.py")
    parser.add_argument("output", help="path to write the Contract B report JSON")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="force rule-based analysis; never call the Anthropic API",
    )
    parser.add_argument("--model", default="claude-sonnet-5", help="model id for LLM mode")
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as fh:
        analysis = json.load(fh)

    report = run(analysis, offline=args.offline, model=args.model)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(
        "[ai_engine] %s -> %s | risk %.1f (%s) | confidence %.2f | mode=%s"
        % (
            args.input,
            args.output,
            report["overall_risk_score"],
            report["risk_level"],
            report["ai_confidence_score"],
            report["mode"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
