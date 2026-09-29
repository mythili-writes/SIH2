"""Glue between the dashboard and the two engines.

Kept free of Streamlit imports so the whole pipeline can be exercised headlessly:

    from frontend.pipeline import run_pipeline
    analysis, report = run_pipeline("sample_data/sample_weak.pcap")
"""

import os
import re
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ai_engine.main import run as run_ai_engine  # noqa: E402
from backend.main import analyze as run_backend  # noqa: E402

SAMPLE_DIR = os.path.join(_ROOT, "sample_data")


def run_pipeline(pcap_path, offline=True):
    """pcap path -> (Contract A analysis, Contract B report)."""
    analysis = run_backend(pcap_path)
    report = run_ai_engine(analysis, offline=offline)
    return analysis, report


def run_pipeline_on_bytes(data, file_name="upload.pcap", offline=True):
    """Same, for an uploaded file held in memory.

    Scapy reads from a path, so the bytes go to a temp file that is removed
    before returning. `file_name` is preserved in the report so the UI shows the
    name the user uploaded rather than the temp name.
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
    report["source_file"] = file_name
    report["executive_report"]["source_capture"] = file_name
    report["technical_report"]["environment"]["source_capture"] = file_name
    return analysis, report


def list_samples():
    """Bundled captures, newest-spec first, as [(label, path), ...]."""
    labels = {
        "sample_weak.pcap": "Weak config - IKEv1 Aggressive, 3DES/MD5/DH2 (IPv4)",
        "sample_strong.pcap": "Strong config - IKEv2, AES-256-GCM/SHA-256/DH14 (IPv4)",
        "sample_mixed.pcap": "Mixed config - IKEv1 Main, AES-128-CBC/SHA-1/DH5 (IPv6)",
    }
    found = []
    for name, label in labels.items():
        path = os.path.join(SAMPLE_DIR, name)
        if os.path.isfile(path):
            found.append((label, path))
    return found


# --------------------------------------------------------------------------
# Executive PDF
# --------------------------------------------------------------------------

def _ascii(text):
    """fpdf2's core fonts are latin-1 only; fold anything else to ASCII."""
    text = str(text)
    replacements = {
        "—": "-", "–": "-", "‘": "'", "’": "'",
        "“": '"', "”": '"', "…": "...", "·": "-",
        "→": "->", "≥": ">=", "≤": "<=",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return re.sub(r"[^\x20-\x7e\n]", "?", text)


def build_executive_pdf(report):
    """Render the executive report to PDF bytes, or None if fpdf is unavailable."""
    try:
        from fpdf import FPDF
    except ImportError:
        return None

    exec_report = report.get("executive_report", {})
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

    # Title
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(11, 11, 11)
    mc(exec_report.get("title", "IPsec VPN Security Assessment"), height=8)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(
        0, 6,
        _ascii("Capture: %s   |   Date: %s   |   Report: %s" % (
            report.get("source_file", "-"),
            exec_report.get("assessment_date", "-"),
            report.get("report_id", "-"),
        )),
        new_x="LMARGIN", new_y="NEXT",
    )

    # Hero figure: the score is the headline, in its status colour.
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 34)
    pdf.set_text_color(*rgb)
    pdf.cell(42, 15, _ascii("%.1f" % report.get("overall_risk_score", 0)))
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 15, _ascii("/100   %s RISK" % level.upper()), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(
        0, 5,
        _ascii("Analysis confidence %.0f%%   |   %s" % (
            report.get("ai_confidence_score", 0) * 100,
            exec_report.get("headline", ""),
        )),
        new_x="LMARGIN", new_y="NEXT",
    )

    heading("Summary")
    body(exec_report.get("summary", report.get("summary", "")))

    counts = report.get("severity_breakdown", {})
    heading("Severity breakdown")
    body("   ".join("%s: %d" % (k, v) for k, v in counts.items()))

    heading("Key risks")
    for risk in exec_report.get("key_risks", []) or [{"risk": "None identified.", "severity": "", "why_it_matters": ""}]:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*rgb if risk.get("severity") == level else (40, 40, 40))
        mc("[%s] %s" % (risk.get("severity", "-"), risk.get("risk", "")))
        body("      %s" % risk.get("why_it_matters", ""), size=9)

    heading("Business impact")
    body(exec_report.get("business_impact", ""))

    heading("Recommended actions")
    for action in exec_report.get("recommended_actions", []) or []:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(40, 40, 40)
        mc("%d. %s  (%s)" % (
            action.get("priority", 0), action.get("area", ""), action.get("timeline", ""),
        ))
        body("      %s" % action.get("action", ""), size=9)

    posture = exec_report.get("compliance_posture", {})
    heading("Compliance posture")
    body("Baseline: %s\nStatus: %s\nFailing control areas: %s\n%s" % (
        posture.get("baseline", "-"),
        posture.get("status", "-"),
        ", ".join(posture.get("failing_controls", [])) or "none",
        posture.get("note", ""),
    ))

    heading("Next steps")
    for step in exec_report.get("next_steps", []) or []:
        body("- %s" % step)

    pdf.ln(3)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 120)
    mc(exec_report.get("scope_note", ""), height=4)

    return bytes(pdf.output())
