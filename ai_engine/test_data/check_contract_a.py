"""Checks that an analysis JSON file matches Contract A.

Usage: python check_contract_a.py [path/to/analysis.json]
Defaults to test_analysis.json next to this script.
"""

import json
import sys
from pathlib import Path

TOP_LEVEL_KEYS = {"file_name", "total_packets", "ip_version", "packet_summary", "sessions", "findings"}
PACKET_SUMMARY_KEYS = {"ike_packets", "esp_packets", "ah_packets", "other_packets"}
SESSION_KEYS = {
    "session_id", "src_ip", "dst_ip", "ipsec_protocol", "protocol", "exchange_mode", "ipsec_mode",
    "encryption", "authentication", "hash", "dh_group", "key_exchange", "auth_method",
    "lifetime_seconds", "pfs_enabled", "replay_protection", "nat_traversal", "identity_exposed",
    "confidence", "traffic_features",
}
TRAFFIC_FEATURE_KEYS = {
    "packet_count", "avg_packet_size", "min_packet_size", "max_packet_size",
    "avg_inter_arrival_ms", "duration_seconds", "bytes_total", "upstream_ratio",
}
FINDING_KEYS = {"finding_id", "session_id", "category", "issue", "severity", "evidence"}

SEVERITIES = {"Critical", "High", "Medium", "Low"}
CATEGORIES = {
    "Encryption", "Hash", "KeyExchange", "Authentication", "Mode", "Lifetime", "PFS",
    "Protocol", "ReplayProtection", "MetadataExposure", "Compliance",
}
# "Unknown" follows the Contract A convention for values that cannot be determined:
# an IKE-only session has no data plane to name, and a capture with no IP packets
# has no IP version.
IPSEC_PROTOCOLS = {"ESP", "AH", "ESP+AH", "Unknown"}
IP_VERSIONS = {"IPv4", "IPv6", "Mixed", "Unknown"}


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


def check_contract_a(data):
    errors = []
    if not check_keys(data, TOP_LEVEL_KEYS, "top level", errors):
        return errors
    check_enum(data, "ip_version", IP_VERSIONS, "top level", errors)

    if "packet_summary" in data:
        check_keys(data["packet_summary"], PACKET_SUMMARY_KEYS, "packet_summary", errors)

    session_ids = set()
    for i, session in enumerate(data.get("sessions", [])):
        where = f"sessions[{i}]"
        if not check_keys(session, SESSION_KEYS, where, errors):
            continue
        session_ids.add(session.get("session_id"))
        check_enum(session, "ipsec_protocol", IPSEC_PROTOCOLS, where, errors)
        if "traffic_features" in session:
            check_keys(session["traffic_features"], TRAFFIC_FEATURE_KEYS, f"{where}.traffic_features", errors)

    for i, finding in enumerate(data.get("findings", [])):
        where = f"findings[{i}]"
        if not check_keys(finding, FINDING_KEYS, where, errors):
            continue
        check_enum(finding, "severity", SEVERITIES, where, errors)
        check_enum(finding, "category", CATEGORIES, where, errors)
        if "session_id" in finding and finding["session_id"] not in session_ids:
            errors.append(f"{where}: session_id={finding['session_id']!r} does not match any session")

    return errors


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("test_analysis.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    errors = check_contract_a(data)
    if errors:
        print(f"Contract A FAILED ({len(errors)} errors) in {path}:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)
    print("Contract A OK")


if __name__ == "__main__":
    main()
