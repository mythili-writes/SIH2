"""Entry point for the AI engine: turns a Contract A analysis into a Contract B report.

Usage: python ai_engine/main.py <analysis.json> <report.json> [--offline]
Frontend: from ai_engine.main import run
"""

import copy
import json
import os
import sys

if __package__:
    from . import explainer, report_builder, scorer, traffic_model
else:  # run as a script: python ai_engine/main.py
    import explainer
    import report_builder
    import scorer
    import traffic_model

SEVERITIES = ("Critical", "High", "Medium", "Low")
FINDING_KEYS = ("finding_id", "session_id", "category", "issue", "severity", "risk_score",
                "explanation", "recommendation", "reference")
TECHNICAL_KEYS = ("protocol_identification", "cipher_suite_analysis", "sa_analysis",
                  "metadata_exposure", "compliance_notes")


def _safe(part, func, default):
    """Run one pipeline part; on any error print a warning and return default."""
    try:
        return func()
    except Exception as exc:
        print(f"Warning: {part} failed ({type(exc).__name__}: {exc}); using a safe default.", file=sys.stderr)
        return default


def _as_list(value):
    return value if isinstance(value, list) else []


def _contract_finding(finding):
    """Contract B key order, without "evidence". Unknown severities count as Low, as in the scorer."""
    result = {key: finding.get(key) for key in FINDING_KEYS}
    if result["severity"] not in SEVERITIES:
        result["severity"] = "Low"
    return result


def _build(analysis):
    sessions = copy.deepcopy(_as_list(analysis.get("sessions")))
    raw_findings = [f for f in _as_list(analysis.get("findings")) if isinstance(f, dict)]

    findings, _mode = _safe(
        "explainer", lambda: explainer.explain_findings(raw_findings),
        ([dict(f, explanation="", recommendation="", reference="") for f in raw_findings], "none"))
    findings = _safe("risk scoring", lambda: scorer.score_findings(findings),
                     [dict(f, risk_score=0) for f in findings])
    findings = [_contract_finding(f) for f in findings]

    risk_score, risk_level = _safe("overall risk", lambda: scorer.overall_risk(findings), (0, "Low"))
    traffic_analysis = _safe("traffic model", lambda: traffic_model.predict_sessions(sessions), [])
    confidence = _safe(
        "AI confidence",
        lambda: scorer.ai_confidence(
            sessions, [t["traffic_confidence"] for t in traffic_analysis if t["traffic_confidence"] > 0]),
        0.0)
    threat_matrix = _safe("threat matrix", lambda: scorer.build_threat_matrix(findings), [])

    executive_report = _safe(
        "executive report",
        lambda: report_builder.build_executive_report(findings, risk_score, risk_level, traffic_analysis),
        {"headline": "The report could not be fully generated.", "key_points": [],
         "business_impact": "", "top_actions": []})
    technical_report = _safe(
        "technical report",
        lambda: report_builder.build_technical_report(sessions, findings, analysis.get("ip_version") or "Unknown"),
        {key: "Not available." for key in TECHNICAL_KEYS})
    summary = _safe("summary", lambda: report_builder.build_summary(risk_level, findings, traffic_analysis),
                    f"Overall risk is {risk_level.lower()}.")

    return {
        "file_name": str(analysis.get("file_name") or "Unknown"),
        "overall_risk_score": risk_score,
        "risk_level": risk_level,
        "ai_confidence_score": confidence,
        "summary": summary,
        "executive_report": executive_report,
        "technical_report": technical_report,
        "traffic_analysis": traffic_analysis,
        "threat_matrix": threat_matrix,
        "findings": findings,
        "sessions": sessions,
    }


def run(analysis, offline=False):
    """Turn a Contract A analysis dict into a Contract B report dict.

    offline=True skips the LLM for this run only (rule-based explanations). If one part of the
    pipeline fails, a warning is printed and a safe default is used for that part.
    """
    previous = os.environ.get("AI_OFFLINE")
    if offline:
        os.environ["AI_OFFLINE"] = "1"
    try:
        return _build(analysis if isinstance(analysis, dict) else {})
    finally:
        if offline:
            if previous is None:
                os.environ.pop("AI_OFFLINE", None)
            else:
                os.environ["AI_OFFLINE"] = previous


def _fail(message):
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(1)


def main():
    args = [a for a in sys.argv[1:] if a != "--offline"]
    offline = len(args) != len(sys.argv) - 1
    if len(args) != 2:
        print("Usage: python ai_engine/main.py <analysis.json> <report.json> [--offline]")
        sys.exit(2)
    in_path, out_path = args

    try:
        with open(in_path, encoding="utf-8") as f:
            analysis = json.load(f)
    except FileNotFoundError:
        _fail(f"input file not found: {in_path}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{in_path} is not valid JSON ({exc})")
    except OSError as exc:
        _fail(f"cannot read {in_path} ({exc.strerror})")
    if not isinstance(analysis, dict):
        _fail(f"{in_path} must contain a JSON object, not {type(analysis).__name__}")

    report = run(analysis, offline=offline)

    try:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    except OSError as exc:
        _fail(f"cannot write {out_path} ({exc.strerror})")

    print(f"Risk score:    {report['overall_risk_score']} ({report['risk_level']})")
    print(f"AI confidence: {report['ai_confidence_score']}")
    print(f"Findings:      {len(report['findings'])}")
    print(f"Report saved:  {out_path}")


if __name__ == "__main__":
    main()
