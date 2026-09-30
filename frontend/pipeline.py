"""Glue between the dashboard and the two engines.

Kept free of Streamlit imports so the whole pipeline can be exercised headlessly:

    from frontend.pipeline import run_pipeline
    analysis, report = run_pipeline("sample_data/sample_weak.pcap")
"""

import json
import logging
import os
import re
import sys
import tempfile
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import config  # noqa: E402
from ai_engine import scorer  # noqa: E402
from ai_engine.main import run as run_ai_engine  # noqa: E402
from backend.main import analyze as run_backend  # noqa: E402

log = logging.getLogger("frontend.pipeline")

SAMPLE_DIR = os.path.join(_ROOT, "sample_data")

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")

SCOPE_NOTE = (
    "This assessment identifies, scores and explains IPsec configuration weaknesses "
    "from a passive packet capture and recommends fixes. It does not modify or "
    "auto-patch any VPN device."
)


def run_pipeline(pcap_path, offline=True):
    """pcap path -> (Contract A analysis, Contract B report)."""
    log.info("analysis requested file=%s offline=%s", os.path.basename(pcap_path), offline)
    analysis = run_backend(pcap_path)
    report = run_ai_engine(analysis, offline=offline)
    return analysis, report


def run_pipeline_on_bytes(data, file_name="upload.pcap", offline=True):
    """Same as run_pipeline, for an uploaded file held in memory.

    Scapy reads from a path, so the bytes go to a temp file that is removed
    before returning. `file_name` replaces the temp name in both contracts so
    the UI shows the name the user uploaded.
    """
    suffix = ".pcapng" if file_name.lower().endswith(".pcapng") else ".pcap"
    handle, temp_path = tempfile.mkstemp(suffix=suffix, prefix="ipsec_upload_")
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(data)
        analysis, report = run_pipeline(temp_path, offline=offline)
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass

    analysis["file_name"] = file_name
    report["file_name"] = file_name
    return analysis, report


def list_samples():
    """Bundled captures that exist on disk, as [(label, path), ...]."""
    labels = {
        "sample_weak.pcap": "Weak config - IKEv1 Aggressive, 3DES/MD5/DH2 (IPv4)",
        "sample_mixed.pcap": "Mixed config - IKEv1 Main, AES-128-CBC/SHA-1/DH5 (IPv6)",
        "sample_strong.pcap": "Strong config - IKEv2, AES-256-GCM/SHA-256/DH14 (IPv4)",
        "test_weak.pcap": "Test capture - IKEv1 Aggressive, 3DES/MD5/DH2, VoIP traffic",
    }
    found = []
    for name, label in labels.items():
        path = os.path.join(SAMPLE_DIR, name)
        if os.path.isfile(path):
            found.append((label, path))
    return found


def severity_counts(findings):
    """Count findings per severity, always returning all four keys."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for finding in findings or []:
        severity = finding.get("severity") if isinstance(finding, dict) else None
        if severity in counts:
            counts[severity] += 1
    return counts


def session_risk(findings, session_id):
    """(score, level) for one session, using the engine's own overall-risk formula."""
    own = [
        f for f in findings or [] if isinstance(f, dict) and f.get("session_id") == session_id
    ]
    return scorer.overall_risk(own)


def evidence_by_finding(analysis):
    """{finding_id: evidence} from Contract A; Contract B drops the evidence field."""
    result = {}
    for finding in (analysis or {}).get("findings") or []:
        if isinstance(finding, dict) and finding.get("finding_id") is not None:
            result[finding.get("finding_id")] = finding.get("evidence") or ""
    return result


def model_card():
    """Facts about the shipped traffic model, read from its training report.

    Returns None if the report is missing or unreadable, so the UI never shows
    a stale hard-coded accuracy figure.
    """
    try:
        with open(config.TRAFFIC_REPORT_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return {
        "accuracy": data.get("accuracy"),
        "n_samples": data.get("n_samples"),
        "classes": data.get("classes") or [],
        "sklearn_version": data.get("sklearn_version"),
        "note": data.get("note") or "",
    }


# --------------------------------------------------------------------------
# Executive PDF
# --------------------------------------------------------------------------


def _ascii(text):
    """fpdf2's core fonts are latin-1 only; fold anything else to ASCII."""
    text = str(text)
    replacements = {
        "—": "-",
        "–": "-",
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
        "…": "...",
        "·": "-",
        "→": "->",
        "≥": ">=",
        "≤": "<=",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return re.sub(r"[^\x20-\x7e\n]", "?", text)


def build_executive_pdf(report):
    """Render the executive report to PDF bytes, or None if fpdf2 is unavailable."""
    try:
        from fpdf import FPDF
    except ImportError:
        return None

    report = report or {}
    executive = report.get("executive_report") or {}
    level = report.get("risk_level", "Unknown")
    rgb = {
        "Critical": (208, 59, 59),
        "High": (236, 131, 90),
        "Medium": (250, 178, 25),
        "Low": (12, 163, 12),
    }.get(level, (82, 81, 78))

    pdf = FPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    def mc(text, height=5):
        """multi_cell that always starts at the left margin.

        fpdf2 leaves the cursor at the right edge after a multi_cell, which
        leaves zero width for the next full-width write.
        """
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, height, _ascii(text), new_x="LMARGIN", new_y="NEXT")

    def heading(text, size=12, gap=2):
        pdf.ln(gap)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", size)
        pdf.set_text_color(11, 11, 11)
        pdf.cell(0, 7, _ascii(text), new_x="LMARGIN", new_y="NEXT")

    def body(text, size=10):
        pdf.set_font("Helvetica", "", size)
        pdf.set_text_color(40, 40, 40)
        mc(text)

    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(11, 11, 11)
    mc("IPsec VPN Security Assessment - Executive Summary", height=8)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(
        0,
        6,
        _ascii(
            "Capture: %s   |   Generated: %s"
            % (
                report.get("file_name", "-"),
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            )
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )

    # Hero figure: the score is the headline, in its status colour.
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 34)
    pdf.set_text_color(*rgb)
    pdf.cell(30, 15, _ascii("%s" % report.get("overall_risk_score", 0)))
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 15, _ascii("/100   %s RISK" % str(level).upper()), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 100, 100)
    mc("Analysis confidence %.0f%%" % (float(report.get("ai_confidence_score") or 0) * 100))

    heading("Headline")
    body(executive.get("headline", ""))

    heading("Summary")
    body(report.get("summary", ""))

    counts = severity_counts(report.get("findings"))
    heading("Severity breakdown")
    body("   ".join("%s: %d" % (k, v) for k, v in counts.items()))

    heading("Key points")
    for point in executive.get("key_points") or ["None."]:
        body("- %s" % point)

    heading("Business impact")
    body(executive.get("business_impact", ""))

    heading("Top actions")
    for index, action in enumerate(executive.get("top_actions") or [], start=1):
        body("%d. %s" % (index, action))

    pdf.ln(3)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 120)
    mc(SCOPE_NOTE, height=4)

    return bytes(pdf.output())
