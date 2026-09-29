"""Encrypted-traffic classification from metadata only.

ESP payloads are encrypted, so nothing here reads packet content. The classifier
scores each candidate traffic type against packet size, timing and directionality
features and normalises the scores into probabilities.
"""

from .contracts import TRAFFIC_TYPES


def _get(features, key, default=0.0):
    value = features.get(key)
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _score_profiles(f):
    """Heuristic score per traffic type. Higher is a better match."""
    avg = _get(f, "avg_packet_size")
    mn = _get(f, "min_packet_size")
    mx = _get(f, "max_packet_size")
    iat = _get(f, "avg_inter_arrival_ms")
    dur = _get(f, "duration_seconds")
    count = _get(f, "packet_count")
    total = _get(f, "bytes_total")
    up = _get(f, "upstream_ratio", 0.5)

    spread = max(0.0, mx - mn)
    rate = count / dur if dur > 0 else 0.0
    throughput = total / dur if dur > 0 else 0.0
    symmetry = 1.0 - abs(up - 0.5) * 2.0  # 1.0 == perfectly bidirectional

    scores = {t: 0.35 for t in TRAFFIC_TYPES}

    # VoIP: small, uniform packets at a steady high rate, symmetric.
    voip = 0.0
    if 60 <= avg <= 260:
        voip += 1.6
    if spread <= 160:
        voip += 1.2
    if 5 <= iat <= 40:
        voip += 1.5
    if rate >= 20:
        voip += 0.8
    voip += symmetry * 1.0
    scores["VoIP"] += voip

    # Video streaming: large packets, high sustained throughput, downstream heavy.
    video = 0.0
    if avg >= 700:
        video += 1.4
    if throughput >= 40000:
        video += 1.3
    if up <= 0.35:
        video += 1.2
    if 1 <= iat <= 60:
        video += 0.6
    if dur >= 5:
        video += 0.5
    scores["Video Streaming"] += video

    # Bulk transfer: near-MTU packets, back-to-back, strongly one-directional.
    bulk = 0.0
    if avg >= 1000:
        bulk += 1.7
    if mx >= 1300:
        bulk += 0.8
    if iat <= 8:
        bulk += 1.3
    if up >= 0.75 or up <= 0.2:
        bulk += 1.1
    if total >= 500000:
        bulk += 0.7
    scores["Bulk File Transfer"] += bulk

    # Web: bursty, wide size spread, moderate volume, downstream skewed.
    web = 0.0
    if 300 <= avg <= 900:
        web += 1.3
    if spread >= 500:
        web += 1.2
    if 20 <= iat <= 400:
        web += 1.1
    if 0.2 <= up <= 0.45:
        web += 0.8
    scores["Web Browsing"] += web

    # Interactive shell: tiny packets, irregular human-paced timing, upstream keystrokes.
    shell = 0.0
    if avg <= 180:
        shell += 1.5
    if iat >= 60:
        shell += 1.4
    if spread <= 400:
        shell += 0.6
    if up >= 0.5:
        shell += 0.7
    if rate <= 15:
        shell += 0.6
    scores["Interactive/Remote Shell"] += shell

    # Keepalive/idle: very little traffic, long gaps, uniform size.
    idle = 0.0
    if count <= 25:
        idle += 1.3
    if iat >= 500:
        idle += 1.7
    if total <= 20000:
        idle += 0.9
    if spread <= 80:
        idle += 0.7
    scores["Keepalive/Idle"] += idle

    return scores


def classify(features):
    """Classify one session's traffic_features block.

    Returns (predicted_type, confidence, top_predictions) where top_predictions
    is a list of the three best {traffic_type, probability} entries.
    """
    features = features or {}
    if not features or _get(features, "packet_count") <= 0:
        return (
            "Unknown",
            0.0,
            [{"traffic_type": "Unknown", "probability": 0.0}],
        )

    scores = _score_profiles(features)
    total = sum(scores.values()) or 1.0
    probs = sorted(
        ({"traffic_type": t, "probability": round(s / total, 4)} for t, s in scores.items()),
        key=lambda p: p["probability"],
        reverse=True,
    )
    top = probs[:3]
    best = top[0]

    # Confidence blends the winning probability with its margin over runner-up,
    # then is damped when there is very little data to judge from.
    margin = best["probability"] - (top[1]["probability"] if len(top) > 1 else 0.0)
    confidence = min(0.97, best["probability"] * 1.7 + margin * 1.5)
    if _get(features, "packet_count") < 10:
        confidence *= 0.6
    if _get(features, "duration_seconds") <= 0:
        confidence *= 0.7

    return best["traffic_type"], round(max(0.05, confidence), 3), top


def infer_metadata(features, session):
    """What a passive observer could deduce from this flow without decrypting it."""
    features = features or {}
    session = session or {}
    avg = _get(features, "avg_packet_size")
    iat = _get(features, "avg_inter_arrival_ms")
    dur = _get(features, "duration_seconds")
    count = _get(features, "packet_count")
    total = _get(features, "bytes_total")
    up = _get(features, "upstream_ratio", 0.5)

    if up >= 0.65:
        direction = "Predominantly upstream (client is sending; upload or push pattern)"
    elif up <= 0.35:
        direction = "Predominantly downstream (client is receiving; download or stream pattern)"
    else:
        direction = "Bidirectional and roughly symmetric (conversational pattern)"

    if iat and iat <= 30:
        periodicity = "Regular, high-frequency cadence — consistent with real-time media"
    elif iat and iat >= 500:
        periodicity = "Sparse and widely spaced — consistent with keepalives or idle polling"
    else:
        periodicity = "Irregular / bursty cadence — consistent with request-response activity"

    if dur >= 300:
        longevity = "Long-lived session (>5 min) — persistent tunnel or streaming session"
    elif dur >= 30:
        longevity = "Medium-lived session (30s-5min)"
    else:
        longevity = "Short-lived session (<30s) — transactional or test traffic"

    observations = [
        "Packet size distribution leaks the application class even though the payload is encrypted",
        direction,
        periodicity,
        longevity,
        "Endpoint pair and tunnel timing are visible to any on-path observer",
    ]

    if session.get("identity_exposed") is True:
        observations.append(
            "IKE identity payload is transmitted in the clear — peer identity is directly readable"
        )
    if session.get("nat_traversal") is True:
        observations.append(
            "NAT-T (UDP 4500) in use — indicates at least one endpoint sits behind NAT"
        )

    # A flow is easier to fingerprint when it is uniform and sustained.
    uniformity = 1.0
    spread = max(0.0, _get(features, "max_packet_size") - _get(features, "min_packet_size"))
    if spread > 800:
        uniformity = 0.6
    volume_factor = min(1.0, count / 100.0) if count else 0.0
    leakage = round(min(0.95, 0.35 + 0.4 * uniformity + 0.25 * volume_factor), 2)

    if leakage >= 0.75:
        privacy_risk = "High"
    elif leakage >= 0.5:
        privacy_risk = "Medium"
    else:
        privacy_risk = "Low"

    return {
        "observations": observations,
        "directionality": direction,
        "session_longevity": longevity,
        "estimated_throughput_bps": int((total * 8 / dur)) if dur > 0 else 0,
        "avg_packet_size": round(avg, 2),
        "metadata_leakage_score": leakage,
        "privacy_risk": privacy_risk,
        "note": (
            "All inferences are derived from packet size, timing and direction only. "
            "No ESP payload was decrypted or inspected."
        ),
    }
