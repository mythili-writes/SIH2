# IPsec VPN Security Analyser

Reads a packet capture of an IPsec VPN, works out how the tunnel was actually
negotiated, and produces a scored security report with an executive and a
technical view.

**This tool identifies, scores and explains IPsec vulnerabilities and recommends
fixes. It does not modify or auto-patch any VPN device.**

Everything runs offline. No API key is required, and no packet payload is ever
decrypted.

---

## Quick start

```bash
pip install -r requirements.txt
streamlit run frontend/app.py
```

Then pick a bundled sample in the sidebar and press **Analyze**. To open straight
onto a populated dashboard: `http://localhost:8501/?sample=weak` (also `strong`,
`mixed`).

## Architecture

```
                 .pcap / .pcapng
                        |
                        v
   +----------------------------------------------+
   |  backend/                                     |
   |                                               |
   |  parser.py   Scapy dissection                 |
   |              - split IKE / ESP / AH / other   |
   |              - IPv4 + IPv6                    |
   |              - one session per peer pair      |
   |              - IKEv1 + IKEv2 transform sets   |
   |              - traffic_features from packet   |
   |                size + timing + direction only |
   |                                               |
   |  rules.py    deterministic rule engine        |
   |              - 11 categories, 4 severities    |
   +----------------------------------------------+
                        |
                 Contract A (JSON)
             file_name, total_packets,
             ip_version, packet_summary,
             sessions[], findings[]
                        |
                        v
   +----------------------------------------------+
   |  ai_engine/            (unchanged, imported)  |
   |                                               |
   |  - risk score 0-100 + risk level              |
   |  - explanation + remediation per finding      |
   |  - traffic classification from metadata       |
   |  - threat matrix (likelihood x impact)        |
   |  - executive + technical report               |
   |                                               |
   |  offline: deterministic rule-based narrative  |
   |  online : Claude rewrites 3 prose fields      |
   |           iff ANTHROPIC_API_KEY is set        |
   +----------------------------------------------+
                        |
                 Contract B (JSON)
                        |
                        v
   +----------------------------------------------+
   |  frontend/                                    |
   |  app.py       Streamlit dashboard             |
   |  pipeline.py  glue + executive PDF export     |
   |                                               |
   |  Overview | Findings | Sessions | Traffic     |
   |  Threat Matrix | Executive | Technical        |
   +----------------------------------------------+
```

The frontend imports `backend.main.analyze()` and `ai_engine.main.run()` directly
in-process. Nothing shells out.

## Command line

Each stage also runs standalone:

```bash
# capture -> Contract A
python backend/main.py sample_data/sample_weak.pcap analysis.json

# Contract A -> Contract B
python ai_engine/main.py analysis.json report.json --offline
```

Regenerate the synthetic captures:

```bash
python sample_data/generate_samples.py
```

## Sample captures

| Capture | Configuration | Findings | Risk |
|---|---|---|---|
| `sample_weak.pcap` | IPv4, IKEv1 Aggressive, 3DES-CBC / MD5 / DH2, PSK, 48h lifetime, PFS off, identity exposed, ESP sequence regression | 10 | **78.2 Critical** |
| `sample_mixed.pcap` | IPv6, IKEv1 Main, AES-128-CBC / SHA-1 / DH5, RSA auth, transport mode, 120s lifetime | 7 | **43.6 Medium** |
| `sample_strong.pcap` | IPv4, IKEv2, AES-256-GCM / SHA-256 / DH14, RSA auth, PFS on, ESN on | 0 | **0.0 Low** |

Each ships with its Contract A analysis and Contract B report alongside it.

## What the parser can and cannot see

It reports only what is on the wire. Anything it cannot determine comes back as
`"Unknown"` (or `null` for booleans and numbers) and lowers that session's
confidence score — it is never guessed, and no key is ever omitted.

- **Read from IKE:** protocol version, exchange mode, cipher, integrity
  algorithm, DH group, authentication method, SA lifetime, PFS, NAT traversal,
  identity exposure, encapsulation mode.
- **Inferred from ESP:** encapsulation mode where IKE did not state it, and
  anti-replay from whether sequence numbers per SPI increase monotonically.
- **Never read:** ESP payload content. Traffic classification uses packet size,
  timing and direction only.

In a real capture the payloads that a live peer encrypts (IKEv1 quick mode,
IKEv2 `SK`) are unreadable, so those parameters will legitimately come back as
`Unknown`. The bundled samples write them in the clear so the full path is
exercised.

## Rule table

| Weak value | Severity | Category |
|---|---|---|
| DES / NULL | Critical | Encryption |
| 3DES, RC5, IDEA, CAST, Blowfish | High | Encryption |
| AES-*-CBC | Low | Encryption (prefer GCM) |
| MD5 | High | Hash |
| SHA-1 | Medium | Hash |
| DH group 1 or 2 | High | KeyExchange |
| DH group 5 | Medium | KeyExchange |
| IKEv1 | Medium | Protocol |
| IKEv1 Aggressive Mode | High | Protocol |
| Pre-Shared Key | Medium | Authentication |
| PFS disabled | Medium | PFS |
| lifetime > 86400s or < 300s | Low | Lifetime |
| Transport mode, site-to-site | Low | Mode |
| Anti-replay disabled | Medium | ReplayProtection |
| Identity exposed | Medium | MetadataExposure |
| Suite outside AES-GCM / AES-256 + SHA-256 | Medium | Compliance |

## Scoring

Severity weights are Critical 40 / High 22 / Medium 10 / Low 3. Repeats of a
severity decay at `0.55^n`, so a long tail of Medium findings never outranks one
Critical. The total is squashed to 0-100 with `100 * (1 - e^(-raw/45))`. Bands:
Critical >= 75, High >= 50, Medium >= 25, Low below.

## Layout

```
backend/      parser.py, rules.py, main.py       pcap -> Contract A
ai_engine/    main.py, contracts.py,             Contract A -> Contract B
              knowledge.py, traffic.py
frontend/     app.py, pipeline.py                dashboard + PDF export
sample_data/  generate_samples.py + 3 captures,  demo fixtures
              their analyses and reports
```

## Requirements

`scapy` for parsing, `streamlit` for the dashboard, `fpdf2` for the executive
PDF (optional — the JSON download works without it), and `anthropic` only if you
want the LLM narrative pass. Python 3.9+.
