# Data contracts

The pipeline passes two JSON documents between its stages:

```
capture (.pcap / .pcapng)
   -> backend (parser + rule engine)  -> Contract A: what was on the wire, and what is wrong with it
   -> ai_engine                       -> Contract B: the scored, explained report
   -> frontend (dashboard)
```

The executable definitions are the checkers, which CI runs on every push:

- `ai_engine/test_data/check_contract_a.py`
- `ai_engine/test_data/check_contract_b.py`

Canonical examples live next to them: `test_analysis.json` (A) and
`test_report.json` (B).

## Compatibility rules

1. **Changes are additive.** Existing keys keep their name, type and meaning.
   New keys are optional, so a document written before the key existed still
   validates.
2. **Unknown keys are errors.** The checkers reject any key that is neither
   required nor listed as optional. This catches typos and silent drift
   between the stages.
3. **Unknown values are explicit.** A value that cannot be determined is the
   string `"Unknown"`, or `null` for booleans and numbers. Keys are never
   omitted.
4. A contract change updates, in the same pull request: this file, the
   checker, the canonical example, and the tests.

## Contract A: parser analysis

Produced by `backend/main.py` (`backend.main.analyze()`).

### Top level

| Key | Type | Notes |
|---|---|---|
| `file_name` | string | Base name of the capture |
| `total_packets` | int | Packets analysed (can be fewer than in the file: see `parse_warnings`) |
| `ip_version` | `"IPv4"` `"IPv6"` `"Mixed"` `"Unknown"` | |
| `packet_summary` | object | `ike_packets`, `esp_packets`, `ah_packets`, `other_packets` |
| `sessions` | list | One per peer pair; see below |
| `findings` | list | Rule-engine output; see below |
| `parse_warnings` | list of string | *Optional, additive.* Caveats about the capture itself: truncation, the packet limit, packets that failed to dissect, no IPsec traffic |

### Session

| Key | Type | Notes |
|---|---|---|
| `session_id` | string or int | The backend emits `"S1"`, `"S2"`, ... |
| `src_ip`, `dst_ip` | string | `src_ip` is the peer seen first |
| `ipsec_protocol` | `"ESP"` `"AH"` `"ESP+AH"` `"Unknown"` | From the data plane, else the negotiated proposal |
| `protocol` | `"IKEv1"` `"IKEv2"` `"Unknown"` | |
| `exchange_mode` | string | `Main`, `Aggressive`, `IKE_SA_INIT`, ... or `Unknown` |
| `ipsec_mode` | `"Tunnel"` `"Transport"` `"Unknown"` | |
| `encryption` | string | e.g. `3DES-CBC`, `AES-256-GCM` |
| `authentication` | string | ESP/AH integrity, e.g. `HMAC-SHA256`, or `AEAD` for AES-GCM-style ciphers |
| `hash` | string | IKE hash / PRF, e.g. `MD5`, `SHA256` |
| `dh_group` | int or null | IANA group number |
| `key_exchange` | `"Diffie-Hellman"` `"ECDH"` `"Unknown"` | |
| `auth_method` | string | e.g. `Pre-Shared Key`, `RSA Digital Signature` |
| `lifetime_seconds` | int or null | |
| `pfs_enabled`, `replay_protection`, `nat_traversal`, `identity_exposed` | bool or null | |
| `confidence` | number 0-1 | Weighted share of key fields the parser determined |
| `traffic_features` | object | `packet_count`, `avg_packet_size`, `min_packet_size`, `max_packet_size`, `avg_inter_arrival_ms`, `duration_seconds`, `bytes_total`, `upstream_ratio`; from ESP/AH sizes and timing only |

### Finding

| Key | Type | Notes |
|---|---|---|
| `finding_id` | string | `F001`, `F002`, ... |
| `session_id` | as in the session | Must match a session |
| `category` | enum | `Encryption` `Hash` `KeyExchange` `Authentication` `Mode` `Lifetime` `PFS` `Protocol` `ReplayProtection` `MetadataExposure` `Compliance` |
| `issue` | string | One line |
| `severity` | `"Critical"` `"High"` `"Medium"` `"Low"` | |
| `evidence` | string | What in the capture triggered the rule |

## Contract B: report

Produced by `ai_engine.main.run()` (CLI: `ai_engine/main.py`). `run()` never
raises; if one step fails it logs a warning and uses a safe default for that
step.

### Top level

| Key | Type | Notes |
|---|---|---|
| `file_name` | string | |
| `overall_risk_score` | int 0-100 | See the scoring section of the README |
| `risk_level` | `"Critical"` `"High"` `"Medium"` `"Low"` | Bands from `config.RISK_LEVEL_THRESHOLDS` (80 / 60 / 35) |
| `ai_confidence_score` | number 0-1 | Mean parser confidence blended 50/50 with mean traffic-model confidence |
| `summary` | string | One sentence |
| `executive_report` | object | `headline`, `key_points` (list), `business_impact`, `top_actions` (list) |
| `technical_report` | object | Five strings, one `Session N: ...` part per session joined with ` \| `: `protocol_identification`, `cipher_suite_analysis`, `sa_analysis`, `metadata_exposure`, `compliance_notes` |
| `traffic_analysis` | list | See below |
| `threat_matrix` | list | See below |
| `findings` | list | Contract A findings without `evidence`, plus the fields below |
| `sessions` | list | The Contract A sessions, passed through unchanged |
| `remediation_config` | list | *Optional, additive.* One `{session_id, snippet}` per session with at least one fix: a single strongSwan `conn` block merging the fixes for all of that session's findings |

### Finding (additional fields)

| Key | Type | Notes |
|---|---|---|
| `risk_score` | int | Critical 95, High 75, Medium 50, Low 25 |
| `explanation`, `recommendation`, `reference` | string | Rule-based offline; from Claude when a key is set and the call succeeds |
| `remediation_snippet` | string | *Optional, additive.* strongSwan `ipsec.conf` lines that fix this finding, with `# was` comments recording the observed values; `""` when no setting applies. Always rule-generated, never from the LLM |

### Traffic analysis entry

| Key | Type | Notes |
|---|---|---|
| `session_id` | as in the session | |
| `predicted_traffic_type` | enum | `VoIP` `WhatsApp` `Email` `Web Browsing` `ICMP` `Video Streaming` `File Transfer` `Unknown` |
| `traffic_confidence` | number 0-1 | Top-class probability; `Unknown` below `config.TRAFFIC_MIN_CONFIDENCE` (0.4) |
| `top_predictions` | list, at most 3 | `{type, probability}` |
| `metadata_inference` | string | What a passive observer can infer |

### Threat matrix entry

| Key | Type | Notes |
|---|---|---|
| `threat`, `category` | string | One entry per finding category |
| `likelihood` | `"Low"` `"Medium"` `"High"` | From the category's worst severity |
| `impact` | `"Low"` `"Medium"` `"High"` | Fixed per category |
| `related_findings` | list of finding_id | |
