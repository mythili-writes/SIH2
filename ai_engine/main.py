"""Entry point for the AI engine: turns a Contract A analysis into a Contract B report.

Usage: python ai_engine/main.py <analysis.json> <report.json> [--offline]
Frontend: from ai_engine.main import run
"""

import copy
import json
import logging
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:  # config.py and logging_setup.py live at the repo root
    sys.path.insert(0, _REPO_ROOT)

if __package__:
    from . import explainer, remediation, report_builder, scorer, traffic_model
else:  # run as a script: python ai_engine/main.py
    import explainer
    import remediation
    import report_builder
    import scorer
    import traffic_model

log = logging.getLogger("ai_engine.main")

SEVERITIES = ("Critical", "High", "Medium", "Low")
FINDING_KEYS = (
    "finding_id",
    "session_id",
    "category",
    "issue",
    "severity",
    "risk_score",
    "explanation",
    "recommendation",
    "reference",
    # Additive (see docs/CONTRACTS.md): a strongSwan ipsec.conf fix, "" if none applies,
    # and whether the finding rests on observed or inferred data.
    "remediation_snippet",
    "evidence_status",
    "evidence_basis",
)
EVIDENCE_STATUSES = ("observed", "inferred", "unknown")
TECHNICAL_KEYS = (
    "protocol_identification",
    "cipher_suite_analysis",
    "sa_analysis",
    "metadata_exposure",
    "compliance_notes",
)


def _safe(part, func, default):
    """Run one pipeline part; on any error log a warning and return default."""
    try:
        return func()
    except Exception as exc:
        log.warning(
            "pipeline step failed step=%s error=%s; using a safe default",
            part,
            type(exc).__name__,
            exc_info=True,
        )
        return default


def _as_list(value):
    """Return value if it is a list, else an empty list."""
    return value if isinstance(value, list) else []


def _clean_sessions(raw):
    """Keep only dict sessions, so one malformed entry cannot break every session's analysis."""
    sessions = [copy.deepcopy(s) for s in _as_list(raw) if isinstance(s, dict)]
    dropped = len(_as_list(raw)) - len(sessions)
    if dropped:
        log.warning("malformed sessions ignored count=%d reason=not an object", dropped)
    return sessions


def _clean_findings(raw):
    """Keep dict findings and give each the string fields Contract B requires.

    A missing or non-string finding_id gets a generated one; a missing category
    becomes "Unknown" and a missing issue a generic description. The input list
    and its dicts are not modified.
    """
    findings = []
    for index, finding in enumerate(f for f in _as_list(raw) if isinstance(f, dict)):
        clean = dict(finding)
        finding_id = clean.get("finding_id")
        if finding_id is None or isinstance(finding_id, bool) or str(finding_id).strip() == "":
            clean["finding_id"] = "F%03d-generated" % (index + 1)
        elif not isinstance(finding_id, str):
            clean["finding_id"] = str(finding_id)
        if not isinstance(clean.get("category"), str) or not clean["category"].strip():
            clean["category"] = "Unknown"
        if not isinstance(clean.get("issue"), str) or not clean["issue"].strip():
            clean["issue"] = "Unspecified IPsec configuration weakness"
        findings.append(clean)
    dropped = len(_as_list(raw)) - len(findings)
    if dropped:
        log.warning("malformed findings ignored count=%d reason=not an object", dropped)
    return findings


def _contract_finding(finding):
    """Contract B key order, without "evidence". Unknown severities count as Low, as in the scorer."""
    result = {key: finding.get(key) for key in FINDING_KEYS}
    if result["severity"] not in SEVERITIES:
        result["severity"] = "Low"
    # Contract A input without provenance: say so rather than imply observation.
    if result["evidence_status"] not in EVIDENCE_STATUSES:
        result["evidence_status"] = "unknown"
    if not isinstance(result["evidence_basis"], str):
        result["evidence_basis"] = ""
    if not isinstance(result["remediation_snippet"], str):
        result["remediation_snippet"] = ""
    return result


def _build(analysis):
    started = time.perf_counter()
    sessions = _clean_sessions(analysis.get("sessions"))
    raw_findings = _clean_findings(analysis.get("findings"))

    findings, explain_mode = _safe(
        "explainer",
        lambda: explainer.explain_findings(raw_findings),
        ([dict(f, explanation="", recommendation="", reference="") for f in raw_findings], "none"),
    )
    findings = _safe(
        "risk scoring",
        lambda: scorer.score_findings(findings),
        [dict(f, risk_score=0) for f in findings],
    )
    findings, remediation_config = _safe(
        "remediation",
        lambda: remediation.attach(findings, sessions),
        ([dict(f, remediation_snippet="") for f in findings], []),
    )
    findings = [_contract_finding(f) for f in findings]

    risk_score, risk_level = _safe(
        "overall risk", lambda: scorer.overall_risk(findings), (0, "Low")
    )
    traffic_analysis = _safe("traffic model", lambda: traffic_model.predict_sessions(sessions), [])
    confidence = _safe(
        "AI confidence",
        lambda: scorer.ai_confidence(
            sessions,
            [t["traffic_confidence"] for t in traffic_analysis if t["traffic_confidence"] > 0],
        ),
        0.0,
    )
    threat_matrix = _safe("threat matrix", lambda: scorer.build_threat_matrix(findings), [])

    executive_report = _safe(
        "executive report",
        lambda: report_builder.build_executive_report(
            findings, risk_score, risk_level, traffic_analysis
        ),
        {
            "headline": "The report could not be fully generated.",
            "key_points": [],
            "business_impact": "",
            "top_actions": [],
        },
    )
    technical_report = _safe(
        "technical report",
        lambda: report_builder.build_technical_report(
            sessions, findings, analysis.get("ip_version") or "Unknown"
        ),
        {key: "Not available." for key in TECHNICAL_KEYS},
    )
    technical_report["uncertainty_notes"] = _safe(
        "uncertainty notes",
        lambda: report_builder.build_uncertainty_notes(sessions),
        "Not available.",
    )
    summary = _safe(
        "summary",
        lambda: report_builder.build_summary(risk_level, findings, traffic_analysis),
        f"Overall risk is {risk_level.lower()}.",
    )

    log.info(
        "report built file=%s risk=%s level=%s findings=%d sessions=%d explanations=%s seconds=%.2f",
        os.path.basename(str(analysis.get("file_name") or "Unknown")),
        risk_score,
        risk_level,
        len(findings),
        len(sessions),
        explain_mode,
        time.perf_counter() - started,
    )
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
        "remediation_config": remediation_config,
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
    """CLI: python ai_engine/main.py <analysis.json> <report.json> [--offline]."""
    from logging_setup import configure_logging

    configure_logging()
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
