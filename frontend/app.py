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

import config  # noqa: E402
from frontend.pipeline import (  # noqa: E402
    SCOPE_NOTE,
    build_executive_pdf,
    evidence_by_finding,
    list_samples,
    model_card,
    run_pipeline,
    run_pipeline_on_bytes,
    session_risk,
    severity_counts,
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

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


CSS = """
<style>
.block-container { padding-top: 2.2rem; max-width: 1500px; }

.hero-wrap { display: flex; align-items: flex-end; gap: 28px; flex-wrap: wrap; }
.hero-figure { font-size: 76px; font-weight: 700; line-height: 0.95; color: #0b0b0b;
               letter-spacing: -0.03em; font-variant-numeric: tabular-nums; }
.hero-scale { font-size: 20px; font-weight: 500; color: #52514e; margin-left: 4px; }
.hero-label { font-size: 13px; color: #52514e; text-transform: uppercase;
              letter-spacing: 0.08em; margin-bottom: 6px; }

.meter-track { height: 8px; border-radius: 4px; background: #ececeb; width: 100%;
               margin-top: 14px; overflow: hidden; }
.meter-fill { height: 8px; border-radius: 4px; }
.meter-scale { position: relative; height: 16px; font-size: 11px; color: #8a8983;
               margin-top: 5px; }
.meter-scale span { position: absolute; transform: translateX(-50%); white-space: nowrap; }
.meter-scale span.first { transform: none; }
.meter-scale span.last { transform: translateX(-100%); }

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
.muted { color: #8a8983; font-size: 12px; }

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
table.matrix td { width: 120px; height: 58px; text-align: center; border-radius: 7px;
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
    """HTML-escape a value for use inside unsafe_allow_html markup."""
    text = "-" if value is None else str(value)
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def fmt(value, dash="Unknown"):
    """Display form of a Contract A value: booleans as Yes/No, None as `dash`."""
    if value is None:
        return dash
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return str(value)


def sev_chip(severity):
    """Severity label on its status tint; the word always accompanies the colour."""
    return '<span class="sev-chip" style="background:%s">%s</span>' % (
        STATUS_TINT.get(severity, "#f0efec"),
        esc(severity),
    )


def as_list(value):
    """Return value if it is a list, else an empty list."""
    return value if isinstance(value, list) else []


def as_dict(value):
    """Return value if it is a dict, else an empty dict."""
    return value if isinstance(value, dict) else {}


def hero(report):
    """Risk score as the hero figure, with a meter marked at the real band edges.

    The number and label stay in ink; the status colour is carried by the dot and
    the meter fill, because amber and green text are illegible on white.
    """
    try:
        score = int(report.get("overall_risk_score") or 0)
    except (TypeError, ValueError):
        score = 0
    level = report.get("risk_level", "Unknown")
    colour = STATUS.get(level, "#52514e")

    ticks = '<span class="first" style="left:0%">0</span>'
    for name, edge in sorted(config.RISK_LEVEL_THRESHOLDS, key=lambda band: band[1]):
        ticks += '<span style="left:%d%%">%d %s</span>' % (edge, edge, name.lower())
    ticks += '<span class="last" style="left:100%">100</span>'

    st.markdown(
        '<div class="hero-label">Overall risk score</div>'
        '<div class="hero-wrap">'
        '  <div><span class="hero-figure">%d</span>'
        '       <span class="hero-scale">/ 100</span></div>'
        '  <div style="padding-bottom:10px;font-size:19px;font-weight:650">'
        '    <span class="dot" style="background:%s;width:12px;height:12px"></span>'
        "%s risk</div>"
        "</div>"
        '<div class="meter-track"><div class="meter-fill" '
        'style="width:%d%%;background:%s"></div></div>'
        '<div class="meter-scale">%s</div>'
        % (score, colour, esc(level), max(1, score), colour, ticks),
        unsafe_allow_html=True,
    )


def tiles(items):
    """A row of stat tiles from (label, value, sub, dot_colour) tuples."""
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
    """Render a table; rows are lists of already-escaped, HTML-safe cell strings."""
    head = "".join("<th>%s</th>" % esc(h) for h in headers)
    body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in row) for row in rows)
    st.markdown(
        '<table class="viz"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>' % (head, body),
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
            '<div class="bar-value">%.0f%%</div></div>' % (esc(name), width, value * 100.0)
        )
    st.markdown("".join(rows), unsafe_allow_html=True)


def per_session_lines(text):
    """Split a technical-report string ("Session 1: ... | Session 2: ...") into lines."""
    return [part.strip() for part in str(text or "").split(" | ") if part.strip()]


def session_label(session_id):
    """Readable session reference for the UI."""
    return "Session %s" % session_id


# --------------------------------------------------------------------------
# tab bodies
# --------------------------------------------------------------------------


def render_overview(report, analysis):
    """Hero score, stat tiles, and the one-line summary."""
    hero(report)
    st.write("")

    findings = as_list(report.get("findings"))
    counts = severity_counts(findings)
    summary = as_dict(analysis.get("packet_summary"))
    tiles(
        [
            (
                "Risk level",
                report.get("risk_level", "-"),
                "banded from the score",
                STATUS.get(report.get("risk_level"), ""),
            ),
            (
                "AI confidence",
                "%.0f%%" % (float(report.get("ai_confidence_score") or 0) * 100),
                "parser and traffic-model confidence",
                "",
            ),
            (
                "Findings",
                str(len(findings)),
                " / ".join("%d %s" % (counts[s], s) for s in SEVERITY_ORDER if counts.get(s))
                or "none",
                "",
            ),
            (
                "Sessions",
                str(len(as_list(report.get("sessions")))),
                "%s capture" % analysis.get("ip_version", "-"),
                "",
            ),
            (
                "Packets",
                str(analysis.get("total_packets", 0)),
                "IKE %d / ESP %d / AH %d / other %d"
                % (
                    summary.get("ike_packets", 0),
                    summary.get("esp_packets", 0),
                    summary.get("ah_packets", 0),
                    summary.get("other_packets", 0),
                ),
                "",
            ),
        ]
    )

    st.write("")
    st.markdown("#### Summary")
    st.write(report.get("summary", ""))
    headline = as_dict(report.get("executive_report")).get("headline")
    if headline:
        st.markdown("**%s**" % headline)

    st.markdown('<div class="scope-note">%s</div>' % esc(SCOPE_NOTE), unsafe_allow_html=True)


def render_findings(report, analysis):
    """Findings table plus a detail expander per finding."""
    findings = [f for f in as_list(report.get("findings")) if isinstance(f, dict)]
    if not findings:
        st.success(
            "No configuration weaknesses found. Every negotiated parameter met "
            "the approved cipher suite baseline."
        )
        return

    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings = sorted(findings, key=lambda f: order.get(f.get("severity"), 9))
    evidence = evidence_by_finding(analysis)

    st.markdown("#### Findings (%d)" % len(findings))
    rows = []
    for f in findings:
        rows.append(
            [
                '<span class="mono">%s</span>' % esc(f.get("finding_id")),
                sev_chip(f.get("severity")),
                esc(f.get("category")),
                "<b>%s</b>" % esc(f.get("issue")),
                '<span class="mono">%s</span>' % esc(f.get("session_id")),
                esc(f.get("risk_score")),
            ]
        )
    viz_table(["ID", "Severity", "Category", "Issue", "Session", "Risk"], rows)

    st.write("")
    st.markdown("#### Detail and remediation")
    for f in findings:
        with st.expander("%s  -  %s  (%s)" % (f.get("finding_id"), f.get("issue"), f.get("severity"))):
            st.markdown(
                '<div class="kv"><b>Severity:</b> %s &nbsp; <b>Category:</b> %s '
                "&nbsp; <b>Session:</b> %s &nbsp; <b>Risk score:</b> %s</div>"
                % (
                    sev_chip(f.get("severity")),
                    esc(f.get("category")),
                    esc(f.get("session_id")),
                    esc(f.get("risk_score")),
                ),
                unsafe_allow_html=True,
            )
            if evidence.get(f.get("finding_id")):
                st.markdown("**Evidence**")
                st.code(evidence[f.get("finding_id")], language=None)
            st.markdown("**Why it matters**")
            st.write(f.get("explanation") or "-")
            st.markdown("**Recommendation**")
            st.write(f.get("recommendation") or "-")
            if f.get("reference"):
                st.caption("Reference: %s" % f.get("reference"))


def render_sessions(report):
    """Negotiated parameters per session, with a per-session risk score."""
    sessions = [s for s in as_list(report.get("sessions")) if isinstance(s, dict)]
    if not sessions:
        st.info("No IPsec sessions were reconstructed from this capture.")
        return

    findings = as_list(report.get("findings"))
    st.markdown("#### Session details (%d)" % len(sessions))
    rows = []
    for s in sessions:
        score, level = session_risk(findings, s.get("session_id"))
        rows.append(
            [
                '<span class="mono">%s</span>' % esc(s.get("session_id")),
                '<span class="mono">%s<br>&rarr; %s</span>'
                % (esc(s.get("src_ip")), esc(s.get("dst_ip"))),
                '%s<br><span class="muted">%s</span>'
                % (esc(fmt(s.get("protocol"))), esc(fmt(s.get("exchange_mode")))),
                '%s<br><span class="muted">%s</span>'
                % (esc(fmt(s.get("ipsec_protocol"))), esc(fmt(s.get("ipsec_mode")))),
                '%s<br><span class="muted">%s</span>'
                % (esc(fmt(s.get("encryption"))), esc(fmt(s.get("authentication")))),
                esc(fmt(s.get("hash"))),
                '%s<br><span class="muted">%s</span>'
                % (esc(fmt(s.get("dh_group"))), esc(fmt(s.get("key_exchange")))),
                esc(fmt(s.get("pfs_enabled"))),
                esc(fmt(s.get("replay_protection"))),
                '%s <span class="muted">%d</span>' % (sev_chip(level), score),
            ]
        )
    viz_table(
        [
            "ID",
            "Peers",
            "IKE",
            "IPsec",
            "Cipher / integrity",
            "Hash",
            "DH",
            "PFS",
            "Replay",
            "Session risk",
        ],
        rows,
    )
    st.caption("Session risk applies the engine's overall-risk formula to that session's findings.")

    st.write("")
    with st.expander("All negotiated parameters"):
        for s in sessions:
            st.markdown(
                "**%s** - %s &rarr; %s"
                % (session_label(s.get("session_id")), s.get("src_ip"), s.get("dst_ip"))
            )
            fields = [
                ("IKE version", fmt(s.get("protocol"))),
                ("Exchange mode", fmt(s.get("exchange_mode"))),
                ("IPsec protocol", fmt(s.get("ipsec_protocol"))),
                ("IPsec mode", fmt(s.get("ipsec_mode"))),
                ("Encryption", fmt(s.get("encryption"))),
                ("Integrity", fmt(s.get("authentication"))),
                ("Hash", fmt(s.get("hash"))),
                ("DH group", fmt(s.get("dh_group"))),
                ("Key exchange", fmt(s.get("key_exchange"))),
                ("Auth method", fmt(s.get("auth_method"))),
                ("SA lifetime (s)", fmt(s.get("lifetime_seconds"))),
                ("PFS enabled", fmt(s.get("pfs_enabled"))),
                ("Replay protection", fmt(s.get("replay_protection"))),
                ("NAT traversal", fmt(s.get("nat_traversal"))),
                ("Identity exposed", fmt(s.get("identity_exposed"))),
                ("Parser confidence", fmt(s.get("confidence"))),
            ]
            st.markdown(
                '<div class="kv">%s</div>'
                % " &nbsp;|&nbsp; ".join("<b>%s:</b> %s" % (esc(k), esc(v)) for k, v in fields),
                unsafe_allow_html=True,
            )
            st.write("")


def render_traffic(report):
    """Traffic-model prediction, top-3 probabilities and flow features per session."""
    entries = [t for t in as_list(report.get("traffic_analysis")) if isinstance(t, dict)]
    if not entries:
        st.info("No ESP traffic was present, so no traffic classification was possible.")
        return

    sessions = {
        s.get("session_id"): s for s in as_list(report.get("sessions")) if isinstance(s, dict)
    }
    st.markdown("#### Encrypted traffic classification")
    card = model_card()
    if card and card.get("accuracy") is not None:
        st.caption(
            "Random Forest over packet size, timing and direction only; ESP payloads are "
            "never inspected. %.1f%% accuracy on a held-out split of %s synthetic sessions. "
            "Accuracy on real captures has not been measured."
            % (float(card["accuracy"]) * 100, card.get("n_samples", "?"))
        )
    else:
        st.caption(
            "Predicted from packet size, timing and direction only; ESP payloads are "
            "never inspected."
        )

    for entry in entries:
        session_id = entry.get("session_id")
        session = as_dict(sessions.get(session_id))
        st.write("")
        st.markdown(
            "**%s** &nbsp; <span class='mono'>%s &rarr; %s</span>"
            % (
                esc(session_label(session_id)),
                esc(session.get("src_ip")),
                esc(session.get("dst_ip")),
            ),
            unsafe_allow_html=True,
        )

        left, right = st.columns([3, 2])
        with left:
            tiles(
                [
                    (
                        "Predicted traffic type",
                        entry.get("predicted_traffic_type", "-"),
                        "Unknown below 40% model confidence",
                        "",
                    ),
                    (
                        "Model confidence",
                        "%.0f%%" % (float(entry.get("traffic_confidence") or 0) * 100),
                        "top-class probability",
                        "",
                    ),
                ]
            )
            st.write("")
            top = [p for p in as_list(entry.get("top_predictions")) if isinstance(p, dict)]
            if top:
                st.markdown("**Top predictions**")
                probabilities = [float(p.get("probability") or 0) for p in top]
                bar_chart(
                    [(p.get("type", "-"), v) for p, v in zip(top, probabilities)],
                    max_value=max(probabilities) or 1.0,
                )
            st.write("")
            st.markdown("**What an observer can infer**")
            st.write(entry.get("metadata_inference") or "-")

        with right:
            features = as_dict(session.get("traffic_features"))
            st.markdown("**Flow features**")
            rows = [
                [esc(label), '<span class="mono">%s</span>' % esc(value)]
                for label, value in [
                    ("Packets", features.get("packet_count")),
                    ("Bytes total", features.get("bytes_total")),
                    ("Avg packet size", features.get("avg_packet_size")),
                    (
                        "Min / max size",
                        "%s / %s"
                        % (features.get("min_packet_size"), features.get("max_packet_size")),
                    ),
                    ("Avg inter-arrival", "%s ms" % features.get("avg_inter_arrival_ms")),
                    ("Duration", "%s s" % features.get("duration_seconds")),
                    ("Upstream ratio", features.get("upstream_ratio")),
                ]
            ]
            viz_table(["Feature", "Value"], rows)


def render_threat_matrix(report):
    """Likelihood x impact heatmap of threats, backed by a table view."""
    entries = [t for t in as_list(report.get("threat_matrix")) if isinstance(t, dict)]
    levels = ["Low", "Medium", "High"]

    st.markdown("#### Threat matrix")
    if not entries:
        st.success("No threats were placed on the matrix: the rule engine found no issues.")
        return
    st.caption(
        "Likelihood (rows) against impact (columns). Cell shading is the number of "
        "threats in that bucket; hover a cell for their names."
    )

    buckets = {}
    for entry in entries:
        key = (entry.get("likelihood"), entry.get("impact"))
        buckets.setdefault(key, []).append(str(entry.get("threat") or "-"))

    head = (
        "<tr><th></th>"
        + "".join("<th style='text-align:center'>%s impact</th>" % esc(i) for i in levels)
        + "</tr>"
    )
    body = ""
    for likelihood in reversed(levels):  # highest likelihood at the top
        body += "<tr><th>%s<br>likelihood</th>" % esc(likelihood)
        for impact in levels:
            threats = buckets.get((likelihood, impact), [])
            count = len(threats)
            step = min(count, len(SEQ) - 1)
            label = str(count) if count else "&middot;"
            tooltip = " | ".join(threats) or "no threats in this bucket"
            body += "<td style='background:%s;color:%s' title='%s'>%s</td>" % (
                SEQ[step],
                SEQ_INK[step] if count else "#b5b4ae",
                esc(tooltip),
                label,
            )
        body += "</tr>"
    st.markdown(
        "<table class='matrix'><thead>%s</thead><tbody>%s</tbody></table>" % (head, body),
        unsafe_allow_html=True,
    )

    st.write("")
    st.markdown("#### Threats (table view)")
    viz_table(
        ["Threat", "Category", "Likelihood", "Impact", "Findings"],
        [
            [
                "<b>%s</b>" % esc(e.get("threat")),
                esc(e.get("category")),
                esc(e.get("likelihood")),
                esc(e.get("impact")),
                '<span class="mono">%s</span>'
                % esc(", ".join(str(x) for x in as_list(e.get("related_findings")))),
            ]
            for e in entries
        ],
    )


def render_executive(report):
    """Plain-English executive report with JSON and PDF downloads."""
    executive = as_dict(report.get("executive_report"))
    st.markdown("### Executive summary")
    st.caption("Capture: %s" % report.get("file_name", "-"))

    hero(report)
    st.write("")
    st.markdown("**%s**" % (executive.get("headline") or ""))
    st.write(report.get("summary", ""))

    st.markdown("#### Key points")
    for point in as_list(executive.get("key_points")) or ["None."]:
        st.markdown("- %s" % point)

    st.markdown("#### Business impact")
    st.write(executive.get("business_impact") or "-")

    st.markdown("#### Top actions")
    actions = as_list(executive.get("top_actions"))
    if actions:
        for index, action in enumerate(actions, start=1):
            st.markdown("%d. %s" % (index, action))
    else:
        st.write("No remediation required.")

    st.markdown('<div class="scope-note">%s</div>' % esc(SCOPE_NOTE), unsafe_allow_html=True)

    st.write("")
    left, right = st.columns(2)
    with left:
        st.download_button(
            "Download executive report (JSON)",
            data=json.dumps(executive, indent=2),
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


TECHNICAL_SECTIONS = [
    ("protocol_identification", "Protocol identification"),
    ("cipher_suite_analysis", "Cipher suite analysis"),
    ("sa_analysis", "Security association analysis"),
    ("metadata_exposure", "Metadata exposure"),
    ("compliance_notes", "Compliance notes"),
]


def render_technical(report, analysis):
    """The five technical-report sections, split per session, plus raw downloads."""
    technical = as_dict(report.get("technical_report"))
    st.markdown("### Technical report")
    st.caption(
        "Produced from a passive capture: IKE negotiation payloads are parsed for the "
        "agreed transform set, ESP/AH flows are measured for mode, sequence behaviour "
        "and traffic features, and a deterministic rule engine raises the findings. "
        "ESP payloads are never decrypted."
    )

    for key, title in TECHNICAL_SECTIONS:
        st.markdown("#### %s" % title)
        lines = per_session_lines(technical.get(key))
        for line in lines or ["Not available."]:
            st.markdown("- %s" % line)

    with st.expander("Raw Contract B report (JSON)"):
        st.json(report, expanded=False)

    st.write("")
    first, second, third = st.columns(3)
    with first:
        st.download_button(
            "Download technical report (JSON)",
            data=json.dumps(technical, indent=2),
            file_name="technical_report.json",
            mime="application/json",
            use_container_width=True,
        )
    with second:
        st.download_button(
            "Download full report (JSON)",
            data=json.dumps(report, indent=2),
            file_name="ipsec_report.json",
            mime="application/json",
            use_container_width=True,
        )
    with third:
        st.download_button(
            "Download parser analysis (JSON)",
            data=json.dumps(analysis, indent=2),
            file_name="ipsec_analysis.json",
            mime="application/json",
            use_container_width=True,
        )


# --------------------------------------------------------------------------
# app
# --------------------------------------------------------------------------


def sidebar():
    """Collect the input selection. Returns (source_kind, payload, offline, analyse)."""
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
                "Packet capture",
                type=["pcap", "pcapng", "cap"],
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
            "Offline mode (no API key needed)",
            value=True,
            help=(
                "On: finding explanations come from built-in rules and are fully "
                "deterministic. Off: if ANTHROPIC_API_KEY is set, one Claude call writes "
                "the explanations; scores are always computed locally."
            ),
        )
        if not offline and not os.environ.get("ANTHROPIC_API_KEY"):
            st.warning(
                "No ANTHROPIC_API_KEY in the environment - the engine will "
                "use the built-in explanations."
            )

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


def render_landing():
    """First screen, before any capture has been analysed."""
    st.title("IPsec VPN Security Analyser")
    st.write(
        "Upload a packet capture, or pick a bundled sample, then press **Analyze** in the sidebar."
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
3. **Explain** - the AI engine scores overall risk, classifies the encrypted
   traffic from metadata alone with a Random Forest, builds a threat matrix, and
   writes an executive and a technical report.
        """
    )
    st.info(SCOPE_NOTE)


def main():
    """Streamlit entry point."""
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
            path
            for _label, path in list_samples()
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
    analysis = st.session_state.get("analysis") or {}
    if not report:
        render_landing()
        return

    st.markdown("## IPsec VPN Security Analyser")
    st.caption(
        "Capture: **%s**  |  Explanations: %s"
        % (report.get("file_name", "-"), "built-in rules" if offline else "Claude when available")
    )

    tabs = st.tabs(
        [
            "Overview",
            "Findings",
            "Sessions",
            "Traffic Analysis",
            "Threat Matrix",
            "Executive Report",
            "Technical Report",
        ]
    )
    with tabs[0]:
        render_overview(report, analysis)
    with tabs[1]:
        render_findings(report, analysis)
    with tabs[2]:
        render_sessions(report)
    with tabs[3]:
        render_traffic(report)
    with tabs[4]:
        render_threat_matrix(report)
    with tabs[5]:
        render_executive(report)
    with tabs[6]:
        render_technical(report, analysis)


if __name__ == "__main__":
    main()
