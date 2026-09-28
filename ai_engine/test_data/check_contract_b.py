"""Checks that a report JSON file matches Contract B.

Usage: python check_contract_b.py [path/to/report.json]
Defaults to test_report.json next to this script.
"""

import json
import math
import sys
from pathlib import Path

TOP_LEVEL_KEYS = {
    "file_name", "overall_risk_score", "risk_level", "ai_confidence_score", "summary", "executive_report",
    "technical_report", "traffic_analysis", "threat_matrix", "findings", "sessions",
}
EXECUTIVE_KEYS = {"headline", "key_points", "business_impact", "top_actions"}
TECHNICAL_KEYS = {"protocol_identification", "cipher_suite_analysis", "sa_analysis", "metadata_exposure",
                  "compliance_notes"}
TRAFFIC_KEYS = {"session_id", "predicted_traffic_type", "traffic_confidence", "top_predictions",
                "metadata_inference"}
PREDICTION_KEYS = {"type", "probability"}
THREAT_KEYS = {"threat", "category", "likelihood", "impact", "related_findings"}
FINDING_KEYS = {"finding_id", "session_id", "category", "issue", "severity", "risk_score", "explanation",
                "recommendation", "reference"}

LEVELS = {"Critical", "High", "Medium", "Low"}
LIKELIHOODS = {"Low", "Medium", "High"}
TRAFFIC_TYPES = {"VoIP", "WhatsApp", "Email", "Web Browsing", "ICMP", "Video Streaming", "File Transfer", "Unknown"}


def is_str(value):
    return isinstance(value, str)


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def is_str_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def check_keys(obj, expected, where, errors):
    """Record missing and unexpected keys. Returns False if obj is not a dict."""
    if not isinstance(obj, dict):
        errors.append(f"{where}: expected an object, got {type(obj).__name__}")
        return False
    for key in sorted(expected - obj.keys()):
        errors.append(f"{where}: missing key '{key}'")
    for key in sorted(obj.keys() - expected):
        errors.append(f"{where}: unexpected key '{key}'")
    return True


def check_enum(obj, key, allowed, where, errors):
    if key in obj and obj[key] not in allowed:
        errors.append(f"{where}: {key}={obj[key]!r} is not one of {sorted(allowed)}")


def check_type(obj, keys, predicate, label, where, errors):
    for key in keys:
        if key in obj and not predicate(obj[key]):
            errors.append(f"{where}: {key}={obj[key]!r} should be {label}")


def check_range(obj, key, low, high, where, errors):
    if is_number(obj.get(key)) and not low <= obj[key] <= high:
        errors.append(f"{where}: {key}={obj[key]!r} is outside {low}-{high}")


def check_list(data, key, errors):
    """Return data[key] if it is a list, else record an error and return []."""
    if key in data and not isinstance(data[key], list):
        errors.append(f"top level: {key} should be a list")
        return []
    return data.get(key, [])


def check_contract_b(data):
    errors = []
    if not check_keys(data, TOP_LEVEL_KEYS, "top level", errors):
        return errors
    check_type(data, ["file_name", "summary"], is_str, "a string", "top level", errors)
    check_type(data, ["overall_risk_score"], is_int, "an int", "top level", errors)
    check_range(data, "overall_risk_score", 0, 100, "top level", errors)
    check_enum(data, "risk_level", LEVELS, "top level", errors)
    check_type(data, ["ai_confidence_score"], is_number, "a number", "top level", errors)
    check_range(data, "ai_confidence_score", 0, 1, "top level", errors)

    if "executive_report" in data and check_keys(data["executive_report"], EXECUTIVE_KEYS, "executive_report", errors):
        report = data["executive_report"]
        check_type(report, ["headline", "business_impact"], is_str, "a string", "executive_report", errors)
        check_type(report, ["key_points", "top_actions"], is_str_list, "a list of strings", "executive_report", errors)

    if "technical_report" in data and check_keys(data["technical_report"], TECHNICAL_KEYS, "technical_report", errors):
        check_type(data["technical_report"], TECHNICAL_KEYS, is_str, "a string", "technical_report", errors)

    sessions = check_list(data, "sessions", errors)
    session_ids = set()
    for i, session in enumerate(sessions):
        if not isinstance(session, dict):
            errors.append(f"sessions[{i}]: expected an object, got {type(session).__name__}")
            continue
        session_ids.add(session.get("session_id"))

    for i, item in enumerate(check_list(data, "traffic_analysis", errors)):
        where = f"traffic_analysis[{i}]"
        if not check_keys(item, TRAFFIC_KEYS, where, errors):
            continue
        check_enum(item, "predicted_traffic_type", TRAFFIC_TYPES, where, errors)
        check_type(item, ["traffic_confidence"], is_number, "a number", where, errors)
        check_range(item, "traffic_confidence", 0, 1, where, errors)
        check_type(item, ["metadata_inference"], is_str, "a string", where, errors)
        if "session_id" in item and item["session_id"] not in session_ids:
            errors.append(f"{where}: session_id={item['session_id']!r} does not match any session")
        predictions = item.get("top_predictions", [])
        if not isinstance(predictions, list):
            errors.append(f"{where}: top_predictions should be a list")
            continue
        if len(predictions) > 3:
            errors.append(f"{where}: top_predictions has {len(predictions)} items, at most 3 allowed")
        for j, prediction in enumerate(predictions):
            p_where = f"{where}.top_predictions[{j}]"
            if check_keys(prediction, PREDICTION_KEYS, p_where, errors):
                check_enum(prediction, "type", TRAFFIC_TYPES, p_where, errors)
                check_type(prediction, ["probability"], is_number, "a number", p_where, errors)
                check_range(prediction, "probability", 0, 1, p_where, errors)

    finding_ids = set()
    for i, finding in enumerate(check_list(data, "findings", errors)):
        where = f"findings[{i}]"
        if not check_keys(finding, FINDING_KEYS, where, errors):
            continue
        finding_ids.add(finding.get("finding_id"))
        check_type(finding, ["finding_id", "category", "issue", "explanation", "recommendation", "reference"],
                   is_str, "a string", where, errors)
        check_enum(finding, "severity", LEVELS, where, errors)
        check_type(finding, ["risk_score"], is_int, "an int", where, errors)
        check_range(finding, "risk_score", 0, 100, where, errors)
        if "session_id" in finding and finding["session_id"] not in session_ids:
            errors.append(f"{where}: session_id={finding['session_id']!r} does not match any session")

    for i, row in enumerate(check_list(data, "threat_matrix", errors)):
        where = f"threat_matrix[{i}]"
        if not check_keys(row, THREAT_KEYS, where, errors):
            continue
        check_type(row, ["threat", "category"], is_str, "a string", where, errors)
        check_enum(row, "likelihood", LIKELIHOODS, where, errors)
        check_enum(row, "impact", LIKELIHOODS, where, errors)
        related = row.get("related_findings", [])
        if not isinstance(related, list):
            errors.append(f"{where}: related_findings should be a list")
            continue
        for finding_id in related:
            if finding_id not in finding_ids:
                errors.append(f"{where}: related finding {finding_id!r} does not match any finding")

    return errors


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("test_report.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    errors = check_contract_b(data)
    if errors:
        print(f"Contract B FAILED ({len(errors)} errors) in {path}:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)
    print("Contract B OK")


if __name__ == "__main__":
    main()
