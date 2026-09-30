"""Single source of settings for the backend, ai_engine and frontend.

Operational values that someone may reasonably tune live here instead of being
scattered through the code. The scoring *formula* itself (severity points,
weights) stays in ai_engine/scorer.py; only its band thresholds are here.

Secrets never live in this file: ANTHROPIC_API_KEY stays in the environment.
Every environment variable the system reads is listed in .env.example.

Environment overrides are validated. A bad value falls back to the default and
is recorded in CONFIG_WARNINGS, which logging_setup.configure_logging() logs
once logging is available.
"""

import os

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

CONFIG_WARNINGS = []


def _env_int(name, default, minimum=1):
    """Integer from the environment, or `default` if unset or invalid."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        CONFIG_WARNINGS.append(f"{name}={raw!r} is not an integer; using {default}")
        return default
    if value < minimum:
        CONFIG_WARNINGS.append(f"{name}={value} is below {minimum}; using {default}")
        return default
    return value


def _env_choice(name, default, choices):
    """Upper-cased string from the environment if it is one of `choices`, else `default`."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().upper()
    if value not in choices:
        CONFIG_WARNINGS.append(f"{name}={raw!r} is not one of {sorted(choices)}; using {default}")
        return default
    return value


# --------------------------------------------------------------------------
# Input limits (backend.parser, frontend)
# --------------------------------------------------------------------------

# Largest capture accepted, in bytes. Streamlit's own upload cap in
# .streamlit/config.toml (maxUploadSize, in MB) should be kept at least as large.
MAX_CAPTURE_BYTES = _env_int("IPSEC_MAX_CAPTURE_MB", 200) * 1024 * 1024

# Packets read from a capture before parsing stops. Bounds memory and run time
# on huge files; the analysis records that it was truncated.
MAX_PACKETS = _env_int("IPSEC_MAX_PACKETS", 200_000)

# --------------------------------------------------------------------------
# Risk scoring (ai_engine.scorer)
# --------------------------------------------------------------------------

# Lower bound of each risk band on the 0-100 overall score, checked in order.
# Anything below the last band is "Low".
RISK_LEVEL_THRESHOLDS = (("Critical", 80), ("High", 60), ("Medium", 35))

# --------------------------------------------------------------------------
# Traffic model (ai_engine.traffic_model)
# --------------------------------------------------------------------------

# A session is reported as "Unknown" when the model's top probability is lower.
TRAFFIC_MIN_CONFIDENCE = 0.4

TRAFFIC_MODEL_DIR = os.path.join(REPO_ROOT, "ai_engine", "models")
TRAFFIC_MODEL_PATH = os.path.join(TRAFFIC_MODEL_DIR, "traffic_model.joblib")
TRAFFIC_DATASET_PATH = os.path.join(TRAFFIC_MODEL_DIR, "synthetic_dataset.csv")
TRAFFIC_REPORT_PATH = os.path.join(TRAFFIC_MODEL_DIR, "training_report.json")

# --------------------------------------------------------------------------
# Rule engine policy (backend.rules)
# --------------------------------------------------------------------------

# SA lifetimes outside this window raise a Low "Lifetime" finding.
SA_LIFETIME_MAX_SECONDS = 86400
SA_LIFETIME_MIN_SECONDS = 300

# --------------------------------------------------------------------------
# LLM explanations (ai_engine.explainer)
# --------------------------------------------------------------------------

# ANTHROPIC_MODEL in the environment overrides this per run.
LLM_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
LLM_TIMEOUT_SECONDS = 20
LLM_MAX_TOKENS = 2000

# --------------------------------------------------------------------------
# Logging (logging_setup)
# --------------------------------------------------------------------------

LOG_LEVEL = _env_choice(
    "IPSEC_LOG_LEVEL", "INFO", {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)
LOG_DIR = os.path.join(REPO_ROOT, "logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")
LOG_MAX_BYTES = 1_000_000
LOG_BACKUP_COUNT = 3
