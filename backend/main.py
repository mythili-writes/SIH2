#!/usr/bin/env python3
"""Backend CLI: PCAP -> Contract A analysis JSON.

python backend/main.py input.pcap output.json
"""

import argparse
import json
import logging
import os
import sys

if __package__ in (None, ""):  # allow `python backend/main.py`
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from backend import rules
    from backend.parser import CaptureError, parse_pcap
else:
    from . import rules
    from .parser import CaptureError, parse_pcap

log = logging.getLogger("backend.main")


def analyze(pcap_path):
    """Full Contract A dict for a capture: parse, then run the rule engine."""
    analysis = parse_pcap(pcap_path)
    analysis["findings"] = rules.evaluate(analysis["sessions"])
    severities = [f["severity"] for f in analysis["findings"]]
    log.info(
        "rule engine done file=%s findings=%d critical=%d high=%d medium=%d low=%d",
        analysis["file_name"],
        len(severities),
        severities.count("Critical"),
        severities.count("High"),
        severities.count("Medium"),
        severities.count("Low"),
    )
    return analysis


def main(argv=None):
    """CLI: python backend/main.py input.pcap output.json."""
    from logging_setup import configure_logging

    configure_logging()
    parser = argparse.ArgumentParser(
        description="Parse an IPsec packet capture into Contract A analysis JSON."
    )
    parser.add_argument("pcap", help="input .pcap / .pcapng file")
    parser.add_argument("output", help="path to write the Contract A JSON")
    args = parser.parse_args(argv)

    try:
        analysis = analyze(args.pcap)
    except CaptureError as exc:
        # Bad input, not a bug: a clear message and exit code 2, no traceback.
        log.warning("capture rejected file=%s reason=%s", os.path.basename(args.pcap), exc)
        print("error: could not parse %s: %s" % (args.pcap, exc), file=sys.stderr)
        return 2
    except Exception as exc:
        log.error("capture parse failed file=%s", os.path.basename(args.pcap), exc_info=True)
        print(
            "error: failed to parse %s: %s: %s" % (args.pcap, type(exc).__name__, exc),
            file=sys.stderr,
        )
        return 1

    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(analysis, fh, indent=2)
    except OSError as exc:
        print("error: cannot write %s (%s)" % (args.output, exc.strerror), file=sys.stderr)
        return 1
    for warning in analysis.get("parse_warnings") or []:
        print("warning: %s" % warning, file=sys.stderr)

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
