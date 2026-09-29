#!/usr/bin/env python3
"""IPsec VPN Security Analyser - Streamlit dashboard.

    streamlit run frontend/app.py

Uploads (or picks) a packet capture, runs backend.parser + backend.rules to get
Contract A, then calls ai_engine.main.run() in-process to get Contract B, and
renders the result. Defaults to offline mode so the demo never needs an API key.
"""

import json
import os
import sys

import streamlit as st

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from frontend.pipeline import (  # noqa: E402
    build_executive_pdf,
    list_samples,
    run_pipeline,
    run_pipeline_on_bytes,
)

# --------------------------------------------------------------------------
# palette
# --------------------------------------------------------------------------
# Status palette (fixed, never themed). Colour never carries meaning alone -
# every severity is rendered with its label beside the colour.
STATUS = {
    "Critical": "#d03b3b",
    "High": "#ec835a",
    "Medium": "#fab219",
    "Low": "#0ca30c",
}
# Same four at ~18% over the light chart surface, for cell fills behind dark ink.
STATUS_TINT = {
    "Critical": "#f4d9d8",
    "High": "#f9e6de",
    "Medium": "#fcefd2",
    "Low": "#d1ecd0",
}
# Sequential blue, light -> dark, for the threat-matrix magnitude encoding.
SEQ = ["#f4f4f2", "#cde2fb", "#86b6ef", "#3987e5", "#1c5cab"]
SEQ_INK = ["#0b0b0b", "#0b0b0b", "#0b0b0b", "#ffffff", "#ffffff"]
SERIES_1 = "#2a78d6"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

CSS = """
<style>
.block-container { padding-top: 2.2rem; max-width: 1500px; }

.hero-wrap { display: flex; align-items: flex-end; gap: 28px; flex-wrap: wrap; }
.hero-figure { font-size: 76px; font-weight: 700; line-height: 0.95;
               letter-spacing: -0.03em; font-variant-numeric: tabular-nums; }
.hero-scale { font-size: 20px; font-weight: 500; color: #52514e; margin-left: 4px; }
.hero-label { font-size: 13px; color: #52514e; text-transform: uppercase;
              letter-spacing: 0.08em; margin-bottom: 6px; }

.meter-track { height: 8px; border-radius: 4px; background: #ececeb; width: 100%;
               margin-top: 14px; overflow: hidden; }
.meter-fill { height: 8px; border-radius: 4px; }
.meter-scale { display: flex; justify-content: space-between; font-size: 11px;
               color: #8a8983; margin-top: 5px; }

.tile-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 4px; }
.tile { flex: 1 1 150px; border: 1px solid #e6e5e1; border-radius: 10px;
        padding: 12px 14px; background: #fcfcfb; }
.tile-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em;
              color: #8a8983; margin-bottom: 5px; }
.tile-value { font-size: 24px; font-weight: 650; color: #0b0b0b;
              font-variant-numeric: tabular-nums; line-height: 1.1; }
.tile-sub { font-size: 11px; color: #8a8983; margin-top: 3px; }

.dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%;
       margin-right: 7px; vertical-align: middle; }

.sev-chip { display: inline-block; padding: 2px 9px; border-radius: 11px;
            font-size: 12px; font-weight: 600; color: #0b0b0b; white-space: nowrap; }

table.viz { border-collapse: separate; border-spacing: 0 2px; width: 100%;
            font-size: 13px; }
table.viz th { text-align: left; font-size: 11px; text-transform: uppercase;
               letter-spacing: 0.06em; color: #8a8983; font-weight: 600;
               padding: 4px 10px; border-bottom: 1px solid #e6e5e1; }
table.viz td { padding: 9px 10px; background: #fcfcfb; vertical-align: top;
               border-top: 1px solid #f0efec; border-bottom: 1px solid #f0efec; }
table.viz td:first-child { border-left: 1px solid #f0efec;
                           border-radius: 7px 0 0 7px; }
table.viz td:last-child { border-right: 1px solid #f0efec;
                          border-radius: 0 7px 7px 0; }
table.viz tr:hover td { background: #f4f4f2; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }

.bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 2px; }
.bar-name { width: 190px; font-size: 12.5px; color: #52514e; text-align: right;
            flex-shrink: 0; }
.bar-track { flex: 1; height: 14px; background: #f4f4f2; border-radius: 4px; }
.bar-fill { height: 14px; border-radius: 0 4px 4px 0; background: #2a78d6; }
.bar-value { width: 52px; font-size: 12px; color: #0b0b0b; font-weight: 600;
             font-variant-numeric: tabular-nums; }

table.matrix { border-collapse: separate; border-spacing: 2px; }
table.matrix th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
                  color: #8a8983; font-weight: 600; padding: 6px 10px; }
table.matrix td { width: 104px; height: 58px; text-align: center; border-radius: 7px;
                  font-size: 19px; font-weight: 650; font-variant-numeric: tabular-nums; }

.scope-note { font-size: 12px; color: #8a8983; border-left: 3px solid #e6e5e1;
              padding: 8px 0 8px 12px; margin-top: 8px; }
.kv { font-size: 13.5px; line-height: 1.65; }
.kv b { color: #0b0b0b; }
</style>
"""


# --------------------------------------------------------------------------
# small render helpers
# --------------------------------------------------------------------------

def esc(value):
    text = "-" if value is None else str(value)
    return (
        text.replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace('"', "&quot;")
    )


def fmt(value, dash="Unknown"):
    if value is None:
        return dash
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return str(value)


def sev_chip(severity):
    return '<span class="sev-chip" style="background:%s">%s</span>' % (
        STATUS_TINT.get(severity, "#f0efec"), esc(severity),
    )


def hero(report):
    score = report.get("overall_risk_score", 0.0)
    level = report.get("risk_level", "Unknown")
    colour = STATUS.get(level, "#52514e")

    st.markdown(
        '<div class="hero-label">Overall risk score</div>'
        '<div class="hero-wrap">'
        '  <div><span class="hero-figure" style="color:%s">%.1f</span>'
        '       <span class="hero-scale">/ 100</span></div>'
        '  <div style="padding-bottom:10px;font-size:19px;font-weight:650;color:%s">'
        '    <span class="dot" style="background:%s"></span>%s risk</div>'
        '</div>'
        '<div class="meter-track"><div class="meter-fill" style="width:%.1f%%;background:%s"></div></div>'
        '<div class="meter-scale"><span>0 low</span><span>25</span><span>50</span>'
        '<span>75</span><span>100 critical</span></div>'
        % (colour, score, colour, colour, esc(level), max(1.0, score), colour),
        unsafe_allow_html=True,
    )


def tiles(items):
    cells = "".join(
        '<div class="tile"><div class="tile-label">%s</div>'
        '<div class="tile-value">%s%s</div><div class="tile-sub">%s</div></div>'
        % (
            esc(label),
            ('<span class="dot" style="background:%s"></span>' % dot) if dot else "",
            esc(value),
            esc(sub),
        )
        for label, value, sub, dot in items
    )
    st.markdown('<div class="tile-row">%s</div>' % cells, unsafe_allow_html=True)


def viz_table(headers, rows):
    """rows: list of lists of already-escaped/HTML-safe cell strings."""
    head = "".join("<th>%s</th>" % esc(h) for h in headers)
    body = "".join(
        "<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in row) for row in rows
    )
    st.markdown(
        '<table class="viz"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>'
        % (head, body),
        unsafe_allow_html=True,
    )


def bar_chart(pairs, max_value=1.0):
    """Single-series magnitude bars. One hue, direct value labels, no legend."""
    rows = []
    for name, value in pairs:
        width = 0.0 if max_value <= 0 else max(1.0, 100.0 * value / max_value)
        rows.append(
            '<div class="bar-row"><div class="bar-name">%s</div>'
            '<div class="bar-track"><div class="bar-fill" style="width:%.1f%%"></div></div>'
            '<div class="bar-value">%.1f%%</div></div>'
            % (esc(name), width, value * 100.0)
        )
    st.markdown("".join(rows), unsafe_allow_html=True)


# --------------------------------------------------------------------------
# tab bodies
# --------------------------------------------------------------------------

def render_overview(report, analysis):
    hero(report)
    st.write("")

    counts = report.get("severity_breakdown", {})
    summary = analysis.get("packet_summary", {})
    tiles([
        ("Risk level", report.get("risk_level", "-"), "banded from the score",
         STATUS.get(report.get("risk_level"), "")),
        ("Analysis confidence", "%.0f%%" % (report.get("ai_confidence_score", 0) * 100),
         "parser coverage x evidence", ""),
        ("Findings", str(len(report.get("findings", []))),
         " / ".join("%d %s" % (counts[s], s) for s in SEVERITY_ORDER if counts.get(s))
         or "none", ""),
        ("Sessions", str(len(report.get("sessions", []))),
         "%s capture" % analysis.get("ip_version", "-"), ""),
        ("Packets", str(analysis.get("total_packets", 0)),
         "IKE %d / ESP %d / AH %d / other %d" % (
             summary.get("ike_packets", 0), summary.get("esp_packets", 0),
             summary.get("ah_packets", 0), summary.get("other_packets", 0)), ""),
    ])

    st.write("")
    st.markdown("#### Summary")
    st.write(report.get("summary", ""))

    st.markdown(
        '<div class="scope-note">%s</div>'
        % esc(report.get("executive_report", {}).get("scope_note", "")),
        unsafe_allow_html=True,
    )


def render_findings(report):
    findings = report.get("findings", [])
    if not findings:
        st.success(
            "No configuration weaknesses found. Every negotiated parameter met "
            "the approved cipher suite baseline."
        )
        return

    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings = sorted(findings, key=lambda f: order.get(f.get("severity"), 9))

    st.markdown("#### Findings (%d)" % len(findings))
    rows = []
    for f in findings:
        rows.append([
            '<span class="mono">%s</span>' % esc(f.get("finding_id")),
            sev_chip(f.get("severity")),
            esc(f.get("category")),
            "<b>%s</b>" % esc(f.get("issue")),
            '<span class="mono">%s</span>' % esc(f.get("session_id")),
            "%.1f" % f.get("cvss_estimate", 0.0),
        ])
    viz_table(["ID", "Severity", "Category", "Issue", "Session", "CVSS"], rows)

    st.write("")
    st.markdown("#### Detail and remediation")
    for f in findings:
        with st.expander("%s  -  %s  (%s)" % (
            f.get("finding_id"), f.get("issue"), f.get("severity")
        )):
            st.markdown(
                '<div class="kv"><b>Severity:</b> %s &nbsp; <b>Category:</b> %s '
                '&nbsp; <b>Session:</b> %s &nbsp; <b>CVSS (est.):</b> %.1f</div>'
                % (sev_chip(f.get("severity")), esc(f.get("category")),
                   esc(f.get("session_id")), f.get("cvss_estimate", 0.0)),
                unsafe_allow_html=True,
            )
            st.markdown("**Evidence**")
            st.code(f.get("evidence", ""), language=None)
            st.markdown("**Why it matters**")
            st.write(f.get("explanation", ""))
            st.markdown("**Recommendation**")
            st.write(f.get("recommendation", ""))
            st.caption("References: " + ", ".join(f.get("references", [])))


def render_sessions(report):
    sessions = report.get("sessions", [])
    if not sessions:
        st.info("No IPsec sessions were reconstructed from this capture.")
        return

    st.markdown("#### Session details (%d)" % len(sessions))
    rows = []
    for s in sessions:
        rows.append([
            '<span class="mono">%s</span>' % esc(s.get("session_id")),
            '<span class="mono">%s<br>&rarr; %s</span>'
            % (esc(s.get("src_ip")), esc(s.get("dst_ip"))),
            "%s<br><span style='color:#8a8983;font-size:12px'>%s</span>"
            % (esc(fmt(s.get("protocol"))), esc(fmt(s.get("exchange_mode")))),
            esc(fmt(s.get("ipsec_mode"))),
            esc(fmt(s.get("encryption"))),
            esc(fmt(s.get("hash"))),
            esc(fmt(s.get("dh_group"))),
            esc(fmt(s.get("pfs_enabled"))),
            esc(fmt(s.get("replay_protection"))),
            '%s <span style="color:#8a8983">%.1f</span>'
            % (sev_chip(s.get("session_risk_level")), s.get("session_risk_score", 0.0)),
        ])
    viz_table(
        ["ID", "Peers", "Protocol", "Mode", "Cipher", "Hash", "DH", "PFS",
         "Replay", "Session risk"],
        rows,
    )

    st.write("")
    with st.expander("All negotiated parameters"):
        for s in sessions:
            st.markdown("**Session %s** - %s &rarr; %s" % (
                s.get("session_id"), s.get("src_ip"), s.get("dst_ip")))
            fields = [
                ("Protocol", fmt(s.get("protocol"))),
                ("Exchange mode", fmt(s.get("exchange_mode"))),
                ("IPsec mode", fmt(s.get("ipsec_mode"))),
                ("Encryption", fmt(s.get("encryption"))),
                ("Integrity / hash", fmt(s.get("hash"))),
                ("DH group", fmt(s.get("dh_group"))),
                ("Auth method", fmt(s.get("auth_method"))),
                ("SA lifetime (s)", fmt(s.get("lifetime_seconds"))),
                ("PFS enabled", fmt(s.get("pfs_enabled"))),
                ("NAT traversal", fmt(s.get("nat_traversal"))),
                ("Identity exposed", fmt(s.get("identity_exposed"))),
                ("Replay protection", fmt(s.get("replay_protection"))),
                ("Parser confidence", "%.0f%%" % ((s.get("parser_confidence") or 0) * 100)),
                ("Findings", s.get("finding_count", 0)),
            ]
            st.markdown(
                '<div class="kv">%s</div>'
                % " &nbsp;|&nbsp; ".join(
                    "<b>%s:</b> %s" % (esc(k), esc(v)) for k, v in fields
                ),
                unsafe_allow_html=True,
            )
            st.write("")


def render_traffic(report):
    entries = report.get("traffic_analysis", [])
    if not entries:
        st.info("No ESP traffic was present, so no traffic classification was possible.")
        return

    st.markdown("#### Encrypted traffic classification")
    st.caption(
        "Predicted from packet size, timing and direction only. ESP payloads are "
        "encrypted and are never inspected."
    )

    for entry in entries:
        st.write("")
        st.markdown(
            "**Session %s** &nbsp; <span class='mono'>%s &rarr; %s</span>"
            % (esc(entry.get("session_id")), esc(entry.get("src_ip")),
               esc(entry.get("dst_ip"))),
            unsafe_allow_html=True,
        )

        left, right = st.columns([3, 2])
        with left:
            tiles([
                ("Predicted traffic type", entry.get("predicted_traffic_type", "-"),
                 "highest-probability class", ""),
                ("Classifier confidence",
                 "%.0f%%" % (entry.get("traffic_confidence", 0) * 100),
                 "margin over runner-up", ""),
            ])
            st.write("")
            st.markdown("**Top predictions**")
            top = entry.get("top_predictions", [])
            bar_chart(
                [(p.get("traffic_type", "-"), p.get("probability", 0.0)) for p in top],
                max_value=max([p.get("probability", 0.0) for p in top] or [1.0]),
            )

        with right:
            features = entry.get("traffic_features", {})
            st.markdown("**Flow features**")
            rows = [
                [esc(label), '<span class="mono">%s</span>' % esc(value)]
                for label, value in [
                    ("Packets", features.get("packet_count")),
                    ("Bytes total", features.get("bytes_total")),
                    ("Avg packet size", features.get("avg_packet_size")),
                    ("Min / max size", "%s / %s" % (
                        features.get("min_packet_size"), features.get("max_packet_size"))),
                    ("Avg inter-arrival", "%s ms" % features.get("avg_inter_arrival_ms")),
                    ("Duration", "%s s" % features.get("duration_seconds")),
                    ("Upstream ratio", features.get("upstream_ratio")),
                ]
            ]
            viz_table(["Feature", "Value"], rows)

        meta = entry.get("metadata_inference", {})
        with st.expander("Metadata inference - what a passive observer learns"):
            tiles([
                ("Metadata leakage", "%.2f" % meta.get("metadata_leakage_score", 0),
                 "0 = opaque, 1 = highly fingerprintable", ""),
                ("Privacy risk", meta.get("privacy_risk", "-"), "from leakage score",
                 STATUS.get(meta.get("privacy_risk"), "")),
                ("Est. throughput", "%s bps" % meta.get("estimated_throughput_bps", 0),
                 "from bytes / duration", ""),
            ])
            st.write("")
            for observation in meta.get("observations", []):
                st.markdown("- %s" % observation)
            st.caption(meta.get("note", ""))


def render_threat_matrix(report):
    matrix = report.get("threat_matrix", {})
    entries = matrix.get("entries", [])
    axes = matrix.get("axes", {})
    likelihoods = axes.get("likelihood", ["Low", "Medium", "High"])
    impacts = axes.get("impact", ["Low", "Medium", "High", "Critical"])

    st.markdown("#### Threat matrix")
    if not entries:
        st.success("No threats were placed on the matrix: the rule engine found no issues.")
        return
    st.caption(
        "Likelihood (rows) against impact (columns). Cell shading is the number "
        "of distinct threats in that bucket; hover a cell for their names."
    )

    lookup = {}
    for cell in matrix.get("cells", []):
        lookup[(cell.get("likelihood"), cell.get("impact"))] = cell

    head = "<tr><th></th>" + "".join(
        "<th style='text-align:center'>%s impact</th>" % esc(i) for i in impacts
    ) + "</tr>"

    body = ""
    for likelihood in reversed(likelihoods):  # highest likelihood at the top
        body += "<tr><th>%s<br>likelihood</th>" % esc(likelihood)
        for impact in impacts:
            cell = lookup.get((likelihood, impact), {"count": 0, "threats": []})
            count = cell.get("count", 0)
            step = min(count, len(SEQ) - 1)
            label = str(count) if count else "&middot;"
            tooltip = " | ".join(cell.get("threats", [])) or "no threats in this bucket"
            body += (
                "<td style='background:%s;color:%s' title='%s'>%s</td>"
                % (SEQ[step], SEQ_INK[step] if count else "#b5b4ae", esc(tooltip), label)
            )
        body += "</tr>"

    st.markdown(
        "<table class='matrix'><thead>%s</thead><tbody>%s</tbody></table>" % (head, body),
        unsafe_allow_html=True,
    )

    st.write("")
    st.markdown("#### Threats (table view)")
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows = []
    for e in sorted(entries, key=lambda x: order.get(x.get("severity"), 9)):
        rows.append([
            "<b>%s</b>" % esc(e.get("threat")),
            esc(e.get("category")),
            esc(e.get("likelihood")),
            esc(e.get("impact")),
            sev_chip(e.get("severity")),
            '<span class="mono">%s</span>' % esc(", ".join(e.get("related_findings", []))),
        ])
    viz_table(
        ["Threat", "Category", "Likelihood", "Impact", "Severity", "Findings"], rows
    )


def render_executive(report):
    exec_report = report.get("executive_report", {})
    st.markdown("### %s" % exec_report.get("title", "Executive Summary"))
    st.caption("Capture: %s  |  Assessed: %s  |  Report: %s" % (
        report.get("source_file", "-"),
        exec_report.get("assessment_date", "-"),
        report.get("report_id", "-"),
    ))

    hero(report)
    st.write("")
    st.markdown("**%s**" % exec_report.get("headline", ""))
    st.write(exec_report.get("summary", ""))

    st.markdown("#### Key risks")
    risks = exec_report.get("key_risks", [])
    if risks:
        viz_table(
            ["Severity", "Area", "Risk", "Why it matters"],
            [[sev_chip(r.get("severity")), esc(r.get("category")),
              "<b>%s</b>" % esc(r.get("risk")), esc(r.get("why_it_matters"))]
             for r in risks],
        )
    else:
        st.write("None identified.")

    st.markdown("#### Business impact")
    st.write(exec_report.get("business_impact", ""))

    st.markdown("#### Recommended actions")
    actions = exec_report.get("recommended_actions", [])
    if actions:
        viz_table(
            ["#", "Timeline", "Area", "Action", "Addresses"],
            [[str(a.get("priority", "")), esc(a.get("timeline")), esc(a.get("area")),
              esc(a.get("action")), '<span class="mono">%s</span>' % esc(a.get("addresses"))]
             for a in actions],
        )
    else:
        st.write("No remediation required.")

    posture = exec_report.get("compliance_posture", {})
    st.markdown("#### Compliance posture")
    tiles([
        ("Baseline", posture.get("baseline", "-"), "assessed against", ""),
        ("Status", posture.get("status", "-"), "overall verdict",
         {"Pass": STATUS["Low"], "Partial": STATUS["Medium"], "Fail": STATUS["Critical"]}
         .get(posture.get("status"), "")),
        ("Failing control areas", str(len(posture.get("failing_controls", []))),
         ", ".join(posture.get("failing_controls", [])) or "none", ""),
    ])
    st.write("")
    st.caption(posture.get("note", ""))

    st.markdown("#### Next steps")
    for step in exec_report.get("next_steps", []):
        st.markdown("- %s" % step)

    st.markdown('<div class="scope-note">%s</div>' % esc(exec_report.get("scope_note", "")),
                unsafe_allow_html=True)

    st.write("")
    left, right = st.columns(2)
    with left:
        st.download_button(
            "Download executive report (JSON)",
            data=json.dumps(exec_report, indent=2),
            file_name="executive_report.json",
            mime="application/json",
            use_container_width=True,
        )
    with right:
        pdf_bytes = build_executive_pdf(report)
        if pdf_bytes:
            st.download_button(
                "Download executive report (PDF)",
                data=pdf_bytes,
                file_name="executive_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        else:
            st.caption("PDF export needs `fpdf2` (pip install fpdf2).")


def render_technical(report):
    tech = report.get("technical_report", {})
    st.markdown("### %s" % tech.get("title", "Technical Detail"))

    st.markdown("#### Methodology")
    st.write(tech.get("methodology", ""))

    st.markdown("#### Environment")
    env = tech.get("environment", {})
    viz_table(
        ["Property", "Value"],
        [[esc(k.replace("_", " ").capitalize()), '<span class="mono">%s</span>' % esc(v)]
         for k, v in env.items()],
    )

    st.markdown("#### Findings detail")
    findings = tech.get("findings_detail", [])
    if findings:
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        viz_table(
            ["ID", "Severity", "Category", "Issue", "Evidence"],
            [['<span class="mono">%s</span>' % esc(f.get("finding_id")),
              sev_chip(f.get("severity")), esc(f.get("category")),
              "<b>%s</b>" % esc(f.get("issue")),
              '<span class="mono">%s</span>' % esc(f.get("evidence"))]
             for f in sorted(findings, key=lambda x: order.get(x.get("severity"), 9))],
        )
    else:
        st.write("No findings.")

    st.markdown("#### Remediation plan")
    plan = tech.get("remediation_plan", [])
    if plan:
        viz_table(
            ["#", "Timeline", "Area", "Action"],
            [[str(a.get("priority", "")), esc(a.get("timeline")), esc(a.get("area")),
              esc(a.get("action"))] for a in plan],
        )
    else:
        st.write("No remediation required.")

    st.markdown("#### Detection notes")
    for note in tech.get("detection_notes", []):
        st.markdown("- %s" % note)

    st.markdown("#### Limitations")
    for note in tech.get("limitations", []):
        st.markdown("- %s" % note)

    with st.expander("Raw Contract B report (JSON)"):
        st.json(report, expanded=False)

    st.write("")
    left, right = st.columns(2)
    with left:
        st.download_button(
            "Download technical report (JSON)",
            data=json.dumps(tech, indent=2),
            file_name="technical_report.json",
            mime="application/json",
            use_container_width=True,
        )
    with right:
        st.download_button(
            "Download full report (JSON)",
            data=json.dumps(report, indent=2),
            file_name="ipsec_report.json",
            mime="application/json",
            use_container_width=True,
        )


# --------------------------------------------------------------------------
# app
# --------------------------------------------------------------------------

def sidebar():
    """Collect the input selection. Returns (source_kind, payload, offline)."""
    with st.sidebar:
        st.markdown("### IPsec VPN Analyser")
        st.caption("Passive IPsec configuration assessment from a packet capture.")
        st.divider()

        samples = list_samples()
        options = ["Upload a capture"] + (["Use a bundled sample"] if samples else [])
        choice = st.radio("Input", options, label_visibility="collapsed")

        payload, kind = None, None
        if choice == "Upload a capture":
            uploaded = st.file_uploader(
                "Packet capture", type=["pcap", "pcapng"],
                help="A capture containing IKE (UDP 500/4500) and/or ESP traffic.",
            )
            if uploaded is not None:
                kind, payload = "upload", uploaded
        else:
            labels = [label for label, _ in samples]
            picked = st.selectbox("Sample capture", labels)
            kind = "sample"
            payload = dict(samples)[picked]

        st.divider()
        offline = st.toggle(
            "Offline mode (no API key needed)", value=True,
            help=(
                "On: the report narrative is rule-based and fully deterministic. "
                "Off: if ANTHROPIC_API_KEY is set, Claude rewrites the summary and "
                "business-impact prose. Scores are always computed locally."
            ),
        )
        if not offline and not os.environ.get("ANTHROPIC_API_KEY"):
            st.warning("No ANTHROPIC_API_KEY in the environment - the engine will "
                       "fall back to the offline narrative.")

        analyse = st.button(
            "Analyze", type="primary", use_container_width=True, disabled=payload is None
        )
        if payload is None:
            st.caption("Choose a capture to enable analysis.")

        st.divider()
        st.caption(
            "Identifies, scores and explains IPsec weaknesses and recommends fixes. "
            "It does not modify or auto-patch any VPN device."
        )

    return kind, payload, offline, analyse


def main():
    st.set_page_config(
        page_title="IPsec VPN Security Analyser",
        page_icon="shield",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(CSS, unsafe_allow_html=True)

    kind, payload, offline, analyse = sidebar()

    # Deep link: /?sample=weak|strong|mixed loads that bundled capture straight
    # into the dashboard, so a demo can open on a populated screen.
    requested = st.query_params.get("sample")
    if requested and "report" not in st.session_state:
        match = [
            path for label, path in list_samples()
            if os.path.basename(path) == "sample_%s.pcap" % str(requested).lower()
        ]
        if match:
            kind, payload, analyse = "sample", match[0], True

    if analyse and payload is not None:
        with st.spinner("Parsing capture and scoring the configuration..."):
            try:
                if kind == "upload":
                    analysis, report = run_pipeline_on_bytes(
                        payload.getvalue(), payload.name, offline=offline
                    )
                else:
                    analysis, report = run_pipeline(payload, offline=offline)
                st.session_state["analysis"] = analysis
                st.session_state["report"] = report
                st.session_state["error"] = None
            except Exception as exc:
                st.session_state["error"] = "%s: %s" % (type(exc).__name__, exc)
                st.session_state.pop("report", None)

    if st.session_state.get("error"):
        st.error("Analysis failed - %s" % st.session_state["error"])
        st.caption(
            "The capture may not be a readable pcap/pcapng. Try one of the bundled "
            "samples to confirm the pipeline itself is working."
        )
        return

    report = st.session_state.get("report")
    analysis = st.session_state.get("analysis")

    if not report:
        st.title("IPsec VPN Security Analyser")
        st.write(
            "Upload a packet capture, or pick a bundled sample, then press "
            "**Analyze** in the sidebar."
        )
        st.markdown(
            """
The pipeline runs in three stages:

1. **Parse** - Scapy splits the capture into IKE, ESP, AH and other packets,
   reconstructs one session per peer pair across IPv4 and IPv6, and extracts the
   negotiated transform set. Anything not visible on the wire is reported as
   *Unknown* rather than guessed.
2. **Score** - a deterministic rule engine checks every parameter against the
   hardening baseline and emits severity-rated findings.
3. **Explain** - the analysis engine scores overall risk, classifies the
   encrypted traffic from metadata alone, builds a threat matrix, and writes an
   executive and a technical report.
            """
        )
        st.info(
            "This tool identifies, scores and explains IPsec vulnerabilities and "
            "recommends fixes. It does not modify or auto-patch any VPN device.",
            icon=None,
        )
        return

    st.markdown("## IPsec VPN Security Analyser")
    st.caption(
        "Capture: **%s**  |  Report **%s**  |  Mode: %s"
        % (report.get("source_file", "-"), report.get("report_id", "-"),
           report.get("mode", "offline"))
    )

    tab_names = [
        "Overview", "Findings", "Sessions", "Traffic Analysis",
        "Threat Matrix", "Executive Report", "Technical Report",
    ]
    tabs = st.tabs(tab_names)
    with tabs[0]:
        render_overview(report, analysis)
    with tabs[1]:
        render_findings(report)
    with tabs[2]:
        render_sessions(report)
    with tabs[3]:
        render_traffic(report)
    with tabs[4]:
        render_threat_matrix(report)
    with tabs[5]:
        render_executive(report)
    with tabs[6]:
        render_technical(report)


if __name__ == "__main__":
    main()
