"""Classifies encrypted session traffic (e.g. VoIP, video) from traffic_features.

Only packet sizes and timing are used; the ESP payload is never read.

Usage:
  python ai_engine/traffic_model.py train [extra.csv]
  python ai_engine/traffic_model.py predict <analysis.json>
"""

import csv
import json
import math
import os
import sys
import warnings

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:  # also works when this file is run as a script
    sys.path.insert(0, _REPO_ROOT)

import config  # noqa: E402  (repo-root config.py: the single source of settings)

FEATURES = ["packet_count", "avg_packet_size", "min_packet_size", "max_packet_size",
            "avg_inter_arrival_ms", "duration_seconds", "bytes_total", "upstream_ratio"]
CLASSES = ["VoIP", "WhatsApp", "Email", "Web Browsing", "ICMP", "Video Streaming", "File Transfer"]

# Artifact paths and the "Unknown" confidence threshold come from config.py.
RULE_CONFIDENCE = 0.5
MAX_PACKET_SIZE = 1500
MIN_PACKET_SIZE = 40
NO_TRAFFIC_TEXT = "Not enough ESP traffic to infer the application."
TRAINING_NOTE = "Trained on synthetic size/timing data; ESP payload is never used."

# Per class: avg packet size in bytes (includes ~60 bytes ESP overhead), inter-arrival in ms,
# upstream ratio, duration in s, and how far min/max sit below/above the average (fraction of avg).
PROFILES = {
    "VoIP": {"size": (130, 230), "iat": (18, 22), "up": (0.45, 0.55), "dur": (10, 120),
             "below": (0.10, 0.35), "above": (0.10, 0.40)},
    "WhatsApp": {"size": (200, 700), "iat": (40, 400), "up": (0.30, 0.60), "dur": (5, 60),
                 "below": (0.60, 0.85), "above": (0.50, 1.50)},
    "Email": {"size": (500, 1200), "iat": (5, 60), "up": (0.55, 0.85), "dur": (1, 10),
              "below": (0.80, 0.92), "above": (0.30, 1.00)},
    "Web Browsing": {"size": (500, 1000), "iat": (5, 50), "up": (0.10, 0.30), "dur": (2, 40),
                     "below": (0.80, 0.92), "above": (0.50, 1.50)},
    "ICMP": {"size": (90, 140), "iat": (900, 1100), "up": (0.45, 0.55), "dur": (3, 30),
             "below": (0.00, 0.03), "above": (0.00, 0.03)},
    "Video Streaming": {"size": (1100, 1350), "iat": (2, 12), "up": (0.02, 0.08), "dur": (30, 300),
                        "below": (0.60, 0.90), "above": (0.05, 0.25)},
    "File Transfer": {"size": (1350, 1420), "iat": (0.3, 3), "up": (0.01, 0.05), "dur": (5, 120),
                      "below": (0.05, 0.25), "above": (0.00, 0.06)},
}

# Share of sessions blended part-way toward another class (mixed or unusual traffic),
# and the log-normal sigma of measurement jitter on every value. Together they keep accuracy realistic.
OVERLAP_RATE = 0.12
NOISE = 0.08

# A capture often starts or stops mid-session, so this share of sessions is cut to a capture window
# (seconds, log-uniform). Without it, short captures of long sessions (e.g. 7 s of video) are misread.
CAPTURE_CUT_RATE = 0.5
CAPTURE_WINDOW = (1, 60)

# One sentence per class, filled with the session's real numbers.
SENTENCES = {
    "VoIP": "Small, regular packets (about {size} bytes) about {gap} ms apart with balanced traffic "
            "({up}% upstream), typical of a voice call.",
    "WhatsApp": "Medium packets (about {size} bytes) in bursts about {gap} ms apart with {up}% upstream, "
                "typical of a messaging app such as WhatsApp.",
    "Email": "Medium to large packets (about {size} bytes) about {gap} ms apart, mostly upstream ({up}%), "
             "typical of sending email.",
    "Web Browsing": "Mixed packet sizes (about {size} bytes on average) about {gap} ms apart, mostly downstream "
                    "({up}% upstream), typical of web browsing.",
    "ICMP": "Small, same-size packets (about {size} bytes) about {gap} ms apart with {up}% upstream, "
            "typical of ping (ICMP) checks.",
    "Video Streaming": "Large packets (about {size} bytes) about {gap} ms apart, almost all downstream "
                       "({up}% upstream), typical of video streaming.",
    "File Transfer": "Near-full-size packets (about {size} bytes) about {gap} ms apart, almost all one way "
                     "({up}% upstream), typical of a large file transfer.",
    "Unknown": "Packets averaging {size} bytes, about {gap} ms apart with {up}% upstream, "
               "do not clearly match one application.",
}


def generate_synthetic_data(n_per_class=300, seed=42):
    """Return a list of dicts with the 8 FEATURES plus "traffic_type"."""
    import numpy as np

    rng = np.random.default_rng(seed)

    def sample(profile):
        return {key: rng.uniform(*limits) for key, limits in profile.items()}

    def jitter():
        return rng.lognormal(0.0, NOISE)

    rows = []
    for traffic_type in CLASSES:
        others = [c for c in CLASSES if c != traffic_type]
        for _ in range(n_per_class):
            p = sample(PROFILES[traffic_type])
            if rng.random() < OVERLAP_RATE:
                other = sample(PROFILES[others[rng.integers(len(others))]])
                w = rng.uniform(0.2, 0.7)
                for key in p:
                    if key in ("iat", "dur"):
                        # These span orders of magnitude, so blend on a log scale.
                        p[key] = p[key] ** (1 - w) * other[key] ** w
                    else:
                        p[key] = (1 - w) * p[key] + w * other[key]

            avg = min(MAX_PACKET_SIZE, p["size"] * jitter())
            gap = p["iat"] * jitter()
            duration = p["dur"] * jitter()
            if rng.random() < CAPTURE_CUT_RATE:
                window = math.exp(rng.uniform(math.log(CAPTURE_WINDOW[0]), math.log(CAPTURE_WINDOW[1])))
                duration = min(duration, window)
            upstream = min(1.0, p["up"] * jitter())
            count = max(5, int(round(duration * 1000 / gap)))
            min_size = min(avg, max(MIN_PACKET_SIZE, avg * (1 - p["below"])))
            max_size = max(avg, min(MAX_PACKET_SIZE, avg * (1 + p["above"])))

            rows.append({
                "packet_count": count,
                "avg_packet_size": round(avg, 1),
                "min_packet_size": int(min_size),
                "max_packet_size": min(MAX_PACKET_SIZE, math.ceil(max_size)),
                "avg_inter_arrival_ms": round(gap, 2),
                "duration_seconds": round(duration, 2),
                "bytes_total": int(round(count * avg)),
                "upstream_ratio": round(upstream, 3),
                "traffic_type": traffic_type,
            })
    return rows


def _read_extra_csv(path):
    rows, skipped = [], 0
    with open(path, newline="", encoding="utf-8") as f:
        for record in csv.DictReader(f):
            label = (record.get("traffic_type") or "").strip()
            try:
                row = {name: float(record[name]) for name in FEATURES}
            except (KeyError, TypeError, ValueError):
                skipped += 1
                continue
            if label not in CLASSES:
                skipped += 1
                continue
            row["traffic_type"] = label
            rows.append(row)
    if skipped:
        print(f"Warning: skipped {skipped} row(s) in {path} with missing values or an unknown traffic_type.")
    return rows


def _print_confusion_matrix(matrix):
    print("Confusion matrix (rows = actual, columns = predicted):")
    print(" " * 17 + "".join(f"{name.split()[0]:>10}" for name in CLASSES))
    for name, counts in zip(CLASSES, matrix):
        print(f"{name:<17}" + "".join(f"{int(n):>10}" for n in counts))


def train(extra_csv=None):
    """Train on synthetic data (plus extra_csv rows if given), save model, dataset and report. Returns the model."""
    import joblib
    import numpy as np
    import sklearn
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split

    rows = generate_synthetic_data()
    if extra_csv:
        extra = _read_extra_csv(extra_csv)
        print(f"Added {len(extra)} row(s) from {extra_csv}.")
        rows += extra

    os.makedirs(os.path.dirname(config.TRAFFIC_MODEL_PATH), exist_ok=True)
    with open(config.TRAFFIC_DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURES + ["traffic_type"])
        writer.writeheader()
        writer.writerows(rows)

    X = np.array([[row[name] for name in FEATURES] for row in rows], dtype=float)
    y = np.array([row["traffic_type"] for row in rows])
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, labels=CLASSES, output_dict=True, zero_division=0)
    matrix = confusion_matrix(y_test, y_pred, labels=CLASSES)

    print(f"Accuracy: {accuracy:.4f}  ({len(y_test)} test sessions out of {len(rows)})\n")
    print(classification_report(y_test, y_pred, labels=CLASSES, digits=3, zero_division=0))
    _print_confusion_matrix(matrix)

    joblib.dump(model, config.TRAFFIC_MODEL_PATH, compress=3)
    training_report = {
        "accuracy": round(float(accuracy), 4),
        "per_class": {
            name: {
                "precision": round(float(report[name]["precision"]), 4),
                "recall": round(float(report[name]["recall"]), 4),
                "f1": round(float(report[name]["f1-score"]), 4),
                "support": int(report[name]["support"]),
            }
            for name in CLASSES
        },
        "confusion_matrix": matrix.tolist(),
        "classes": CLASSES,
        "features": FEATURES,
        "feature_importances": {name: round(float(v), 4) for name, v in zip(FEATURES, model.feature_importances_)},
        "n_samples": len(rows),
        "sklearn_version": sklearn.__version__,
        "note": TRAINING_NOTE,
    }
    with open(config.TRAFFIC_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(training_report, f, indent=2)

    print(f"\nSaved {config.TRAFFIC_MODEL_PATH}")
    return model


def load_model():
    """Load the saved model, retraining if it is missing or cannot be loaded.

    Returns None only if retraining also fails. Never raises.
    """
    try:
        import joblib
        from sklearn.exceptions import InconsistentVersionWarning

        with warnings.catch_warnings():
            # A model saved by another scikit-learn version can load but predict wrongly; retrain instead.
            warnings.simplefilter("error", InconsistentVersionWarning)
            return joblib.load(config.TRAFFIC_MODEL_PATH)
    except FileNotFoundError:
        print("Warning: traffic model not found; training a new one.", file=sys.stderr)
    except Exception as exc:
        print(f"Warning: could not load traffic model ({type(exc).__name__}); training a new one.", file=sys.stderr)

    try:
        return train()
    except Exception as exc:
        print(f"Warning: training the traffic model failed ({type(exc).__name__}).", file=sys.stderr)
        return None


def _to_float(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _model_rankings(rows):
    """Return, for each feature row, [(traffic_type, probability), ...] sorted best first."""
    import numpy as np

    model = load_model()
    if model is None:
        raise RuntimeError("no traffic model")
    probabilities = model.predict_proba(np.array(rows, dtype=float))
    classes = [str(c) for c in model.classes_]
    return [sorted(zip(classes, map(float, p)), key=lambda pair: pair[1], reverse=True) for p in probabilities]


def _rule_type(values):
    """Rough guess from average packet size and inter-arrival time only; used when the model is unavailable."""
    size, gap = values["avg_packet_size"], values["avg_inter_arrival_ms"]
    if gap >= 500:
        return "ICMP"
    if size < 300 and 10 <= gap <= 30:
        return "VoIP"
    if size >= 1340 and gap < 3:
        return "File Transfer"
    if size >= 1050 and gap < 15:
        return "Video Streaming"
    if gap >= 40:
        return "WhatsApp"
    if size >= 500:
        return "Web Browsing"
    return "Unknown"


def _describe(traffic_type, values):
    gap = values["avg_inter_arrival_ms"]
    return SENTENCES[traffic_type].format(
        size=f"{values['avg_packet_size']:.0f}",
        gap=f"{gap:.1f}".removesuffix(".0") if gap < 10 else f"{gap:.0f}",
        up=f"{values['upstream_ratio'] * 100:.0f}",
    )


def _result(session_id, traffic_type, confidence, top_predictions, metadata_inference):
    return {
        "session_id": session_id,
        "predicted_traffic_type": traffic_type,
        "traffic_confidence": round(min(1.0, max(0.0, confidence)), 2),
        "top_predictions": top_predictions,
        "metadata_inference": metadata_inference,
    }


def predict_sessions(sessions):
    """Return one dict per session with session_id, predicted_traffic_type, traffic_confidence,
    top_predictions and metadata_inference. Falls back to simple rules if the model fails. Never raises
    for model problems."""
    rows = {}
    for index, session in enumerate(sessions):
        features = session.get("traffic_features")
        if isinstance(features, dict) and _to_float(features.get("packet_count")) > 0:
            rows[index] = [_to_float(features.get(name)) for name in FEATURES]

    rankings = None
    if rows:
        try:
            rankings = dict(zip(rows, _model_rankings(list(rows.values()))))
        except Exception as exc:
            print(f"Warning: traffic model unavailable ({type(exc).__name__}); using simple rules.", file=sys.stderr)

    results = []
    for index, session in enumerate(sessions):
        session_id = session.get("session_id")
        if index not in rows:
            results.append(_result(session_id, "Unknown", 0.0, [], NO_TRAFFIC_TEXT))
            continue

        values = dict(zip(FEATURES, rows[index]))
        if rankings is not None:
            ranking = rankings[index]
            best_type, confidence = ranking[0]
            predicted = best_type if confidence >= config.TRAFFIC_MIN_CONFIDENCE else "Unknown"
            top = [{"type": t, "probability": round(p, 2)} for t, p in ranking[:3]]
        else:
            predicted = _rule_type(values)
            confidence = RULE_CONFIDENCE if predicted != "Unknown" else 0.0
            top = [{"type": predicted, "probability": confidence}] if predicted != "Unknown" else []
        results.append(_result(session_id, predicted, confidence, top, _describe(predicted, values)))
    return results


def main():
    args = sys.argv[1:]
    if len(args) in (1, 2) and args[0] == "train":
        train(args[1] if len(args) == 2 else None)
    elif len(args) == 2 and args[0] == "predict":
        with open(args[1], encoding="utf-8") as f:
            analysis = json.load(f)
        for result in predict_sessions(analysis.get("sessions", [])):
            top = ", ".join(f"{p['type']} {p['probability']:.2f}" for p in result["top_predictions"]) or "-"
            print(f"\nSession {result['session_id']}")
            print(f"  Predicted:  {result['predicted_traffic_type']} (confidence {result['traffic_confidence']:.2f})")
            print(f"  Top 3:      {top}")
            print(f"  Inference:  {result['metadata_inference']}")
    else:
        print("Usage:\n  python ai_engine/traffic_model.py train [extra.csv]\n"
              "  python ai_engine/traffic_model.py predict <analysis.json>")
        sys.exit(2)


if __name__ == "__main__":
    main()
