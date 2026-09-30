# IPsec VPN Security Analyser

Reads a packet capture of IPsec VPN traffic, reconstructs how each tunnel was
negotiated, and produces a scored, explained security report, for a technical
reader and for an executive one.

**This tool identifies, scores and explains IPsec vulnerabilities and recommends
fixes. It does not modify or auto-patch any VPN device.**

It runs fully offline: no API key is needed, and ESP payloads are never
decrypted. Built for Smart India Hackathon 2026.

[![tests](https://github.com/mythili-writes/SIH2/actions/workflows/test.yml/badge.svg)](https://github.com/mythili-writes/SIH2/actions/workflows/test.yml)

---

## Status: what is real and what is not

Read this before relying on any output.

| Area | State |
|---|---|
| Rule engine | Deterministic. Every rule is unit-tested against the rule table below, firing on its weak value and staying silent otherwise. |
| Risk scoring | Deterministic formula, unit-tested against hand-computed values. **It is a heuristic**: the weights and bands follow common hardening guidance and have not been calibrated against real incidents. |
| PCAP parser | Tested **only on synthetic captures** crafted with Scapy (the bundled samples and the test suite's captures). **Not yet validated on real-world captures.** |
| What a real capture reveals | Much less than the samples. Real IKEv2 encrypts everything after `IKE_SA_INIT`, and IKEv1 encrypts main mode after message 4 and all of quick mode, so on real traffic fields such as PFS, the ESP integrity algorithm and IKEv2's auth method will usually come back `Unknown`. The samples deliberately write those payloads in the clear so the whole pipeline can be exercised. |
| Traffic classifier | Random Forest **trained and evaluated on synthetic data only**: 94.29% on a held-out synthetic split. **Accuracy on real captures has not been measured.** |
| Configuration fixes | Rule-generated strongSwan `ipsec.conf` snippets for every finding. Tested for structure, syntax shape, consistency with the recommendations, and determinism. **Not yet validated against a running strongSwan instance**, and only strongSwan's legacy `ipsec.conf` syntax is produced (no `swanctl.conf`, Cisco or Juniper). |
| Observed vs inferred | Every session value is labelled observed, inferred or not determined, with the reason, and findings resting on inferred values are marked. Tested on crafted captures for each inference the parser makes. The labels are only as good as the parser's own reasoning, which has been checked on synthetic captures only. |
| Claude explanations | Optional. Not exercised by the test suite or CI, which have no API key. The fallback to built-in explanations when the call fails is tested. |
| Dashboard | Smoke-tested headlessly (every sample, every tab, the error paths). Single user, no authentication, not load-tested. |
| Not built | Live capture, parsing vendor configurations (Cisco, Juniper, strongSwan files), comparing captures over time, authentication, persistence, deployment packaging. |

## Architecture

```
            .pcap / .pcapng
                   |
                   v
+--------------------------------------------------+
| backend/                                         |
|  parser.py  validate (magic bytes, size) and     |
|             stream with Scapy                    |
|             - IKE / ESP / AH / other, IPv4 + v6  |
|             - one session per peer pair          |
|             - IKEv1 + IKEv2 transform sets       |
|             - traffic features from packet size, |
|               timing and direction only          |
|  rules.py   deterministic rule engine            |
|             11 categories x 4 severities         |
+--------------------------------------------------+
                   |
             Contract A (JSON)            docs/CONTRACTS.md
                   |
                   v
+--------------------------------------------------+
| ai_engine/                                       |
|  explainer.py      explanation per finding       |
|                    (rules offline, Claude opt.)  |
|  scorer.py         risk score, AI confidence,    |
|                    threat matrix                 |
|  traffic_model.py  Random Forest traffic type    |
|  report_builder.py executive + technical report  |
+--------------------------------------------------+
                   |
             Contract B (JSON)
                   |
                   v
+--------------------------------------------------+
| frontend/  Streamlit dashboard, PDF export       |
|  Overview | Findings | Sessions | Traffic        |
|  Threat Matrix | Executive | Technical           |
+--------------------------------------------------+

config.py         every tunable setting, in one place
logging_setup.py  stdout + rotating logs/app.log
```

The dashboard calls `backend.main.analyze()` and `ai_engine.main.run()`
in-process; nothing shells out. Each stage also runs on its own from the command
line.

## Quick start

Requires Python 3.10 to 3.13.

```bash
git clone https://github.com/mythili-writes/SIH2.git
cd SIH2
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run frontend/app.py
```

Pick a bundled sample in the sidebar and press **Analyze**, or open a sample
directly: `http://localhost:8501/?sample=weak` (also `mixed`, `strong`).

## Tests and code quality

```bash
pip install -r requirements-dev.txt
python -m pytest          # 242 tests, ~10 s, fully offline
ruff check .
black --check .
```

CI (`.github/workflows/test.yml`) runs the linters, the contract checkers and
the test suite on every push and pull request, on Python 3.10 and 3.12.

The suite covers the pipeline's critical paths: every rule, the scoring formula
and its boundaries, the parser on crafted captures, capture validation, the
engine's tolerance of malformed input, both data contracts end to end, the
verified sample scores, both CLIs, and the dashboard rendered headlessly. It
does not aim for full line coverage.

## Command line

```bash
# capture -> Contract A
python backend/main.py sample_data/sample_weak.pcap analysis.json

# Contract A -> Contract B
python ai_engine/main.py analysis.json report.json --offline

# check a file against its contract
python ai_engine/test_data/check_contract_a.py analysis.json
python ai_engine/test_data/check_contract_b.py report.json

# regenerate the synthetic captures
python sample_data/generate_samples.py
```

`backend/main.py` exits with 2 and a one-line reason for input it cannot
analyse (not a capture, empty, too large), and prints any parse warnings, such
as truncation, to stderr.

## Configuration

Tunable settings live in [`config.py`](config.py): input limits, risk band
thresholds, the traffic-model confidence threshold, model paths, SA lifetime
policy, LLM model and timeout, and logging. Every module reads them from there.

Environment variables, all optional, are documented in
[`.env.example`](.env.example):

| Variable | Effect |
|---|---|
| `ANTHROPIC_API_KEY` | Enables Claude-written explanations (scores never use it) |
| `ANTHROPIC_MODEL` | Model for those explanations |
| `AI_OFFLINE=1` | Force built-in explanations even with a key |
| `IPSEC_MAX_CAPTURE_MB` | Largest capture accepted (default 200) |
| `IPSEC_MAX_PACKETS` | Packets analysed before stopping (default 200000) |
| `IPSEC_LOG_LEVEL` | `DEBUG` ... `CRITICAL` (default `INFO`) |

An invalid value falls back to the default and is logged.

Logs go to stdout and to the rotating file `logs/app.log`. They never contain
packet payloads, IP addresses or the API key.

## Configuration fixes

Every finding comes with the strongSwan `ipsec.conf` lines that fix it, and
every affected session gets one merged `conn` block covering all its findings
(shown in the dashboard's Remediation tab, and downloadable as a `.conf`).
Fixes target one hardened baseline that matches the written recommendations:
IKEv2, AES-256-GCM, SHA-256, DH group 19 with PFS, certificates, tunnel mode,
8 h / 1 h lifetimes, anti-replay. Where the capture showed the current value,
a `# was` comment records it. For `sample_weak.pcap`'s 3DES finding:

```
# strongSwan ipsec.conf: fix for F001 (Encryption)
# Session S1, 10.0.0.1 <-> 203.0.113.9. Merge into that peer's existing conn section.
conn session-S1
    # was (observed): keyexchange=ikev1
    # required: AES-GCM IKE proposals are only supported with IKEv2
    keyexchange=ikev2
    # was (observed): ike=3des-md5-modp1024
    # if this peer must stay on IKEv1 for now: ike=aes256-sha256-ecp256!
    ike=aes256gcm16-prfsha256-ecp256!
    # the DH group in the ESP proposal also turns on PFS
    esp=aes256gcm16-ecp256!
```

Snippets are generated by rules, never by the LLM, so they cannot contain
invented syntax. Review them before applying: the tool never touches a device.

## Observed vs inferred

A report is only as trustworthy as the values under it, and a passive
capture cannot see everything. Instead of presenting every field with the same
implied confidence, the parser records for each session value whether it was:

- **observed**: read from a plaintext protocol field (e.g. the encryption
  attribute of the IKE proposal)
- **inferred**: deduced from a heuristic, a protocol default or packet
  behaviour (e.g. "Tunnel" because IKEv2 defaults to it; anti-replay from
  sequence numbers, since the receiver's replay window is never on the wire)
- **not determined**, with the reason (e.g. "IKEv2 does not negotiate
  lifetimes on the wire")

Each finding inherits the weakest status of the fields its rule reads. The
dashboard marks inferred values in the Sessions table, shows the full
breakdown with reasons, flags findings that rest on inference, and the
technical report opens with a data-quality section. For `sample_weak.pcap`,
14 of 16 values are observed and the anti-replay finding is flagged as
inferred: "ESP sequence numbers went backwards or repeated across 40 packets,
so the sender is not honouring anti-replay".

Risk scores deliberately do not change with provenance: the uncertainty is
reported alongside the score, not folded into it.

## Input handling

- Files are checked before parsing: pcap or pcapng magic bytes, not empty,
  within the size limit. Anything else is rejected with a reason ("the file is
  gzip-compressed; decompress it...").
- Captures are streamed packet by packet and stop at `IPSEC_MAX_PACKETS`, so a
  huge file cannot exhaust memory.
- A truncated or corrupt classic pcap is analysed up to its last intact packet,
  and the report says so. (Scapy on its own reads such files silently.)
- A packet that fails to dissect is skipped and counted, not fatal.

## Rule table

| Weak value | Severity | Category |
|---|---|---|
| DES / NULL encryption | Critical | Encryption |
| 3DES, RC5, IDEA, CAST, Blowfish | High | Encryption |
| AES-*-CBC | Low | Encryption (prefer AES-GCM) |
| MD5 | High | Hash |
| SHA-1 | Medium | Hash |
| DH group 1 or 2 | High | KeyExchange |
| DH group 5 | Medium | KeyExchange |
| IKEv1 | Medium | Protocol |
| IKEv1 Aggressive Mode | High | Protocol |
| Pre-Shared Key | Medium | Authentication |
| PFS disabled | Medium | PFS |
| SA lifetime > 86400 s or < 300 s | Low | Lifetime |
| Transport mode, site-to-site | Low | Mode |
| Anti-replay disabled | Medium | ReplayProtection |
| Identity exposed | Medium | MetadataExposure |
| Suite outside the baseline: AES-GCM, or AES-256 with SHA-256+ and no weak DH group (1, 2, 5, 22, 23) | Medium | Compliance |

A value the parser could not determine never raises a finding.

## Scoring

Each finding scores Critical 95, High 75, Medium 50 or Low 25. The overall
score is

```
0.6 x worst finding + 0.4 x mean finding + min(15, 3 x number of Critical/High findings)
```

clamped to 0-100, with 5 when there are no findings. Bands: Critical from 80,
High from 60, Medium from 35, otherwise Low (`config.RISK_LEVEL_THRESHOLDS`).
AI confidence is the mean parser confidence blended 50/50 with the mean
traffic-model confidence.

## Bundled samples

Synthetic captures crafted with Scapy (`sample_data/generate_samples.py`).

| Capture | Configuration | Findings | Risk |
|---|---|---|---|
| `sample_weak.pcap` | IPv4, IKEv1 Aggressive, 3DES / MD5 / DH 2, PSK, 48 h lifetime, PFS off, identity exposed, ESP sequence regression | 10 | **80 Critical** |
| `sample_mixed.pcap` | IPv6, IKEv1 Main, AES-128-CBC / SHA-1 / DH 5, RSA auth, transport mode, 120 s lifetime | 7 | **46 Medium** |
| `sample_strong.pcap` | IPv4, IKEv2, AES-256-GCM / SHA-256 / DH 14, RSA auth, PFS on | 0 | **5 Low** |
| `test_weak.pcap` | IPv4, IKEv1 Aggressive, 3DES / MD5 / DH 2, PSK, PFS off, VoIP-shaped traffic | 8 | **82 Critical** |

The first three ship with their Contract A analysis and Contract B report.
`tests/test_pipeline.py` fails if any of these scores changes.

## Repository layout

```
backend/        parser.py, rules.py, main.py         capture -> Contract A
ai_engine/      main.py, scorer.py, explainer.py,     Contract A -> Contract B
                traffic_model.py, report_builder.py,
                models/ (Random Forest + training data)
frontend/       app.py, pipeline.py                   dashboard, PDF export
sample_data/    generate_samples.py, captures and their outputs
tests/          pytest suite
docs/           CONTRACTS.md
config.py       settings
logging_setup.py
```

See [`ai_engine/README.md`](ai_engine/README.md) for the engine and its model,
[`docs/CONTRACTS.md`](docs/CONTRACTS.md) for both data contracts, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how the team works.
