# AI Engine

Turns the parser's analysis JSON (**Contract A**) into the final report JSON (**Contract B**):

- **Risk scoring** (`scorer.py`): a 0–100 risk score and level, an AI confidence score and a threat matrix.
- **Explanations** (`explainer.py`): a plain-English explanation, recommendation and standard reference for every finding. It uses Claude if an API key is set and falls back to built-in rules otherwise.
- **Traffic classification** (`traffic_model.py`): guesses what each encrypted session carries (VoIP, video, and so on) from packet sizes and timing only. The ESP payload is never read.
- **Reports** (`report_builder.py`): an executive report, a technical report and a one-line summary.

## Install

```bash
pip install -r ai_engine/requirements.txt
```

Tested with Python 3.13 and scikit-learn 1.9.0.

## Command line

Run from the repo root:

```bash
python ai_engine/main.py <analysis.json> <report.json> [--offline]
```

Example:

```bash
python ai_engine/main.py ai_engine/test_data/test_analysis.json ai_engine/test_data/test_report.json --offline
python ai_engine/test_data/check_contract_b.py ai_engine/test_data/test_report.json
```

If the input file is missing or is not valid JSON, it prints an error and exits with code 1.

## Using it from the frontend

```python
from ai_engine.main import run

report = run(analysis_dict)                # Contract B dict
report = run(analysis_dict, offline=True)  # never calls the LLM
```

The repo root must be on `sys.path` (it is when you start Python from the repo root). If one step fails, `run()` prints a warning and uses a safe default for that step, so it still returns a valid Contract B report. It does not modify the input dict.

## `--offline` and the LLM

| Setting | Effect |
|---|---|
| `ANTHROPIC_API_KEY` | If set, explanations come from one Claude API call. If the call fails (no internet, bad key, timeout), the built-in rules are used. |
| `ANTHROPIC_MODEL` | Optional. The default is `claude-haiku-4-5-20251001`. |
| `AI_OFFLINE=1`, `--offline` or `offline=True` | Always use the built-in rules, even if a key is set. |

**Never commit the API key.** Set it in your shell. `.env` is in `ai_engine/.gitignore`, but the code does not read `.env` itself, so you have to load it into your environment.

## Traffic model

- **Model:** Random Forest (150 trees, balanced class weights), saved to `models/traffic_model.joblib`.
- **Features (8):** packet count, average, minimum and maximum packet size, average inter-arrival time, duration, total bytes and upstream ratio.
- **Classes (7):** VoIP, WhatsApp, Email, Web Browsing, ICMP, Video Streaming and File Transfer. A session is reported as `Unknown` if the top probability is below 0.4 or there is no traffic data.
- **Training data:** 2,100 synthetic sessions (300 per class) with realistic ESP sizes and timing, noise, overlap between classes, and captures that start or end mid-session. Saved to `models/synthetic_dataset.csv`.
- **Accuracy:** 94.05% on a stratified 20% held-out split. See `models/training_report.json` for full metrics.

| Class | Precision | Recall | F1 |
|---|---|---|---|
| VoIP | 0.97 | 0.98 | 0.98 |
| WhatsApp | 0.86 | 0.93 | 0.90 |
| Email | 0.98 | 0.88 | 0.93 |
| Web Browsing | 0.90 | 0.93 | 0.92 |
| ICMP | 0.95 | 0.92 | 0.93 |
| Video Streaming | 0.95 | 0.95 | 0.95 |
| File Transfer | 0.98 | 0.98 | 0.98 |

These numbers are measured on synthetic data. Accuracy on real captures has not been measured yet.

Retrain with `python ai_engine/traffic_model.py train [extra.csv]`. The optional CSV adds labelled rows with the 8 feature columns plus `traffic_type`. If the model file is missing or was saved by a different scikit-learn version, it retrains automatically. If the model can't be used at all, simple size and timing rules take over.
