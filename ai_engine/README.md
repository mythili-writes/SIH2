# ai_engine

Turns **Contract A** (the parser's analysis JSON) into **Contract B** (the scored,
explained security report). Deterministic, offline-capable, no network required.

## Interface

```python
from ai_engine.main import run

report = run(analysis_dict, offline=True)   # -> Contract B dict
```

```bash
python ai_engine/main.py analysis.json report.json --offline
```

`--offline` forces the rule-based path. Without it, the engine uses the Anthropic
API **only if** `ANTHROPIC_API_KEY` is set, and only to rewrite three narrative
fields (`summary`, `executive_report.business_impact`, `executive_report.headline`).
Every score, finding, classification and matrix cell is computed locally, so the
report shape never depends on the model being reachable. Any API failure silently
falls back to the rule-based narrative and sets `mode: "offline"`.

## Contract A (input)

```
file_name, total_packets, ip_version
packet_summary { ike_packets, esp_packets, ah_packets, other_packets }
sessions[] { session_id, src_ip, dst_ip, protocol, exchange_mode, encryption,
             hash, dh_group, auth_method, lifetime_seconds, pfs_enabled,
             nat_traversal, identity_exposed, ipsec_mode, replay_protection,
             confidence, traffic_features { packet_count, avg_packet_size,
               min_packet_size, max_packet_size, avg_inter_arrival_ms,
               duration_seconds, bytes_total, upstream_ratio } }
findings[] { finding_id, session_id, category, issue, severity, evidence }
```

Unknown values are the string `"Unknown"` (or `null` for booleans/numbers).
Keys are never omitted.

## Contract B (output)

```
schema_version, report_id, generated_at, source_file, mode
overall_risk_score (0-100), risk_level, ai_confidence_score (0-1), summary
severity_breakdown { Critical, High, Medium, Low }
findings[]           + explanation, recommendation, cvss_estimate, references[]
sessions[]           + session_risk_score, session_risk_level, finding_count
traffic_analysis[]   { predicted_traffic_type, traffic_confidence,
                       top_predictions[], metadata_inference{} }
threat_matrix        { axes{}, entries[], cells[] }
executive_report     { headline, key_risks[], business_impact,
                       recommended_actions[], compliance_posture{}, next_steps[] }
technical_report     { methodology, environment{}, findings_detail[],
                       session_details[], remediation_plan[], detection_notes[],
                       limitations[], appendix{} }
```

## Scoring

Severity weights are Critical 40 / High 22 / Medium 10 / Low 3. Repeats of the
same severity decay at 0.55^n, so six Medium findings never outrank one Critical.
The raw total is squashed to 0-100 with `100 * (1 - e^(-raw/45))`. Bands:
Critical >= 75, High >= 50, Medium >= 25, Low below that.

## Modules

| File | Role |
|---|---|
| `main.py` | orchestration, scoring, report assembly, CLI |
| `contracts.py` | severities, categories, weights, risk bands |
| `knowledge.py` | per-category explanation / remediation / references / threat placement |
| `traffic.py` | metadata-only traffic classification and inference |

`test_data/test_analysis.json` is a canonical Contract A input;
`test_data/test_report.json` is the Contract B output it produces.
