#!/usr/bin/env python3
"""Backend CLI: PCAP -> Contract A analysis JSON.

    python backend/main.py input.pcap output.json
"""

import argparse
import json
import os
import sys

if __package__ in (None, ""):  # allow `python backend/main.py`
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from backend import rules
    from backend.parser import parse_pcap
else:
    from . import rules
    from .parser import parse_pcap


def analyze(pcap_path):
    """Full Contract A dict for a capture: parse, then run the rule engine."""
    analysis = parse_pcap(pcap_path)
    analysis["findings"] = rules.evaluate(analysis["sessions"])
    return analysis


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Parse an IPsec packet capture into Contract A analysis JSON."
    )
    parser.add_argument("pcap", help="input .pcap / .pcapng file")
    parser.add_argument("output", help="path to write the Contract A JSON")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.pcap):
        print("error: no such file: %s" % args.pcap, file=sys.stderr)
        return 2

    try:
        analysis = analyze(args.pcap)
    except Exception as exc:
        print("error: failed to parse %s: %s: %s" % (args.pcap, type(exc).__name__, exc),
              file=sys.stderr)
        return 1

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(analysis, fh, indent=2)

    summary = analysis["packet_summary"]
    print(
        "[backend] %s -> %s | %d packets (%s) | ike=%d esp=%d ah=%d other=%d | "
        "%d session(s) | %d finding(s)"
        % (
            args.pcap,
            args.output,
            analysis["total_packets"],
            analysis["ip_version"],
            summary["ike_packets"],
            summary["esp_packets"],
            summary["ah_packets"],
            summary["other_packets"],
            len(analysis["sessions"]),
            len(analysis["findings"]),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
