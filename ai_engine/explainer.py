"""Generates plain-language explanations for findings.

Rule-based explanations always work offline. If ANTHROPIC_API_KEY is set and AI_OFFLINE is not "1",
one Claude API call is tried first; anything it misses falls back to the rules.

Usage: python ai_engine/explainer.py <analysis.json>
"""

import json
import logging
import os
import re
import sys
import time

import requests

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:  # also works when this file is run as a script
    sys.path.insert(0, _REPO_ROOT)

import config  # noqa: E402  (repo-root config.py: the single source of settings)

log = logging.getLogger("ai_engine.explainer")

API_URL = "https://api.anthropic.com/v1/messages"

FIELDS = ("explanation", "recommendation", "reference")
PROMPT_KEYS = ("finding_id", "category", "issue", "severity", "evidence")

# Checked in order; the first rule with a matching keyword wins.
# "3des" must come before "des", and "aggressive" before "ikev1".
RULES = [
    {
        "keywords": ["3des", "triple des", "triple-des"],
        "explanation": "3DES uses a small 64-bit block, so an attacker who records enough traffic "
                       "can recover data (the Sweet32 attack).",
        "recommendation": "Replace 3DES with AES-256-GCM.",
        "reference": "NIST SP 800-131A",
    },
    {
        "keywords": ["des"],
        "explanation": "DES has only a 56-bit key and can be broken quickly with today's hardware.",
        "recommendation": "Replace DES with AES-256-GCM.",
        "reference": "NIST SP 800-131A",
    },
    {
        "keywords": ["cbc"],
        "explanation": "CBC mode still keeps data secret, but it has no built-in integrity check "
                       "and depends on a separate hash.",
        "recommendation": "Prefer AES-GCM, which encrypts and protects integrity in one step.",
        "reference": "RFC 8221",
    },
    {
        "keywords": ["md5"],
        "explanation": "MD5 is a broken hash; attackers can create collisions and forge data.",
        "recommendation": "Use SHA-256 or stronger (for example HMAC-SHA-256).",
        "reference": "RFC 8221",
    },
    {
        "keywords": ["sha1", "sha-1"],
        "explanation": "SHA-1 is a weak hash and practical collision attacks against it exist.",
        "recommendation": "Use SHA-256 or stronger.",
        "reference": "NIST SP 800-131A",
    },
    {
        "keywords": ["dh_group=1", "dh_group=2", "dh group 1", "dh group 2"],
        "explanation": "DH groups 1 and 2 use 768-bit and 1024-bit keys, which are too short "
                       "and open to the Logjam attack.",
        "recommendation": "Use DH group 14, 19 or 20.",
        "reference": "RFC 8247",
    },
    {
        "keywords": ["dh_group=5", "dh group 5"],
        "explanation": "DH group 5 uses a 1536-bit key, which is below current security guidance.",
        "recommendation": "Use DH group 14, 19 or 20.",
        "reference": "RFC 8247",
    },
    {
        "keywords": ["aggressive"],
        "explanation": "Aggressive Mode sends the peer identity and a hash of the pre-shared key "
                       "without protection. An attacker can capture it and crack the key offline.",
        "recommendation": "Use IKEv2, or Main Mode if IKEv1 cannot be removed yet.",
        "reference": "NIST SP 800-77r1",
    },
    {
        "keywords": ["ikev1"],
        "explanation": "IKEv1 is a legacy protocol with known weaknesses and is no longer recommended.",
        "recommendation": "Migrate to IKEv2.",
        "reference": "RFC 8247",
    },
    {
        "keywords": ["pre-shared", "psk"],
        "explanation": "A pre-shared key can be guessed if it is weak, and the same key is often "
                       "shared across many devices.",
        "recommendation": "Use certificate-based authentication.",
        "reference": "NIST SP 800-77r1",
    },
    {
        "keywords": ["pfs", "forward secrecy"],
        "explanation": "Without Perfect Forward Secrecy, anyone who later steals a key can decrypt "
                       "old recorded traffic.",
        "recommendation": "Enable PFS with DH group 19 or 20.",
        "reference": "NIST SP 800-77r1",
    },
    {
        "keywords": ["lifetime"],
        "explanation": "The key lifetime is outside the normal range, so a key is used for too long "
                       "or is changed too often.",
        "recommendation": "Use 28800 seconds for the IKE SA and 3600 seconds for the IPsec SA.",
        "reference": "NIST SP 800-77r1",
    },
    {
        "keywords": ["replay"],
        "explanation": "Without anti-replay protection, an attacker can capture packets and send them again.",
        "recommendation": "Enable the ESP anti-replay window.",
        "reference": "RFC 4303",
    },
    {
        "keywords": ["identity", "metadata"],
        "explanation": "The peer identity is sent unencrypted, so eavesdroppers can see who is connecting.",
        "recommendation": "Use IKEv2, which encrypts peer identities.",
        "reference": "RFC 7296",
    },
    {
        "keywords": ["transport", "mode"],
        "explanation": "Transport mode leaves the original IP headers visible, so eavesdroppers can see "
                       "which hosts are talking.",
        "recommendation": "Use tunnel mode for site-to-site VPNs.",
        "reference": "NIST SP 800-77r1",
    },
    {
        "keywords": ["compliance", "compliant", "fips"],
        "explanation": "This cryptographic suite is not on the approved list, so the connection "
                       "does not meet compliance rules.",
        "recommendation": "Use a NIST-approved suite, such as AES-256-GCM with SHA-256 and DH group 19 or 20.",
        "reference": "NIST SP 800-77r1",
    },
]

SYSTEM_PROMPT = (
    "You explain IPsec security findings to people who are not security experts. "
    "Reply with ONLY a JSON list and no other text."
)

USER_PROMPT = (
    "For each finding below, write:\n"
    "- explanation: 1 to 2 short sentences in simple English saying what is wrong and why it matters\n"
    "- recommendation: one short sentence saying what to change\n"
    "- reference: one standard, for example \"RFC 8247\" or \"NIST SP 800-77r1\"\n"
    "Return ONLY a JSON list of objects with the keys finding_id, explanation, recommendation, reference. "
    "Include one object per finding and copy finding_id exactly.\n\n"
    "Findings:\n"
)


def _keyword_pattern(keywords):
    # A keyword must stand alone, so "des" does not match inside "3des"
    # and "dh_group=1" does not match inside "dh_group=14".
    alternatives = "|".join(re.escape(k) for k in keywords)
    return re.compile(rf"(?<![a-z0-9])(?:{alternatives})(?![a-z0-9])")


_RULE_PATTERNS = [(_keyword_pattern(rule["keywords"]), rule) for rule in RULES]


def _match_rule(finding):
    """Return the first rule matching the finding's issue, else its issue plus evidence, or None.

    The issue is tried on its own first because evidence often quotes other algorithms:
    a Compliance finding's evidence names the weak cipher, and matching on the combined
    text would pick that cipher's rule instead of the finding's own.
    """
    issue = str(finding.get("issue") or "").lower()
    evidence = str(finding.get("evidence") or "").lower()
    for text in (issue, f"{issue} {evidence}"):
        for pattern, rule in _RULE_PATTERNS:
            if pattern.search(text):
                return rule
    return None


def rule_explanation(finding):
    """Return {"explanation", "recommendation", "reference"} for one finding. Always works offline."""
    rule = _match_rule(finding)
    if rule is not None:
        return {key: rule[key] for key in FIELDS}

    category = finding.get("category") or "security"
    severity = str(finding.get("severity") or "unknown").lower()
    return {
        "explanation": f"This {category} setting has a {severity}-severity weakness that makes "
                       f"the IPsec connection less safe.",
        "recommendation": f"Review the {category} setting and change it to a value recommended by current NIST guidance.",
        "reference": "NIST SP 800-77r1",
    }


def _model_name():
    """The Claude model to call: ANTHROPIC_MODEL if set, else config.LLM_DEFAULT_MODEL."""
    return os.environ.get("ANTHROPIC_MODEL") or config.LLM_DEFAULT_MODEL


def _llm_enabled():
    return bool(os.environ.get("ANTHROPIC_API_KEY")) and os.environ.get("AI_OFFLINE") != "1"


def _ask_llm(findings):
    """Make one Claude API call for all findings.

    Returns {finding_id: {"explanation", "recommendation", "reference"}} for every usable item
    in the reply. Raises on any failure (network, HTTP status, bad JSON, nothing usable).
    """
    slim = [{key: f[key] for key in PROMPT_KEYS if key in f} for f in findings]
    response = requests.post(
        API_URL,
        headers={
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": _model_name(),
            "max_tokens": config.LLM_MAX_TOKENS,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": USER_PROMPT + json.dumps(slim, indent=2)}],
        },
        timeout=config.LLM_TIMEOUT_SECONDS,
    )
    response.raise_for_status()

    blocks = response.json()["content"]
    text = "".join(block.get("text", "") for block in blocks if block.get("type") == "text")
    # Tolerate a ```json fence or a stray sentence around the list.
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end < start:
        raise ValueError("reply has no JSON list")
    items = json.loads(text[start:end + 1])
    if not isinstance(items, list):
        raise ValueError("reply is not a JSON list")

    results = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        values = {key: item.get(key) for key in FIELDS}
        if all(isinstance(v, str) and v.strip() for v in values.values()):
            results[str(item.get("finding_id"))] = {key: v.strip() for key, v in values.items()}
    if not results:
        raise ValueError("reply has no usable items")
    return results


def _error_reason(exc):
    # Only the status code or the exception type: short, and never contains the API key.
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return f"HTTP {exc.response.status_code}"
    return type(exc).__name__


def explain_findings(findings):
    """Return (new_findings, mode).

    new_findings are copies of the input findings with "explanation", "recommendation" and
    "reference" added. The input is not changed. mode is "llm" if any text came from the LLM,
    otherwise "rule".
    """
    llm_results = {}
    if findings and _llm_enabled():
        started = time.perf_counter()
        log.info("LLM explanation request model=%s findings=%d", _model_name(), len(findings))
        try:
            llm_results = _ask_llm(findings)
        except Exception as exc:
            # Only the status code or exception type: never the key or the reply body.
            log.warning(
                "LLM explanations unavailable reason=%s seconds=%.2f; using rule-based explanations",
                _error_reason(exc),
                time.perf_counter() - started,
            )
            llm_results = {}
        else:
            log.info(
                "LLM explanations received usable=%d/%d seconds=%.2f",
                len(llm_results),
                len(findings),
                time.perf_counter() - started,
            )
    elif findings:
        reason = "offline" if os.environ.get("AI_OFFLINE") == "1" else "no_api_key"
        log.info("explanations are rule-based reason=%s findings=%d", reason, len(findings))

    new_findings = []
    missed = []
    for finding in findings:
        copy = dict(finding)
        text = llm_results.get(str(finding.get("finding_id")))
        if text is None:
            text = rule_explanation(finding)
            missed.append(str(finding.get("finding_id")))
        copy.update(text)
        new_findings.append(copy)

    used_llm = len(missed) < len(findings)
    if used_llm and missed:
        log.warning(
            "LLM gave no usable text for findings=%s; used rule-based text for those",
            ",".join(missed),
        )
    return new_findings, "llm" if used_llm else "rule"


def main():
    """CLI: print the explanation for every finding in a Contract A file."""
    from logging_setup import configure_logging

    configure_logging()
    if len(sys.argv) != 2:
        print("Usage: python ai_engine/explainer.py <analysis.json>")
        sys.exit(2)

    with open(sys.argv[1], encoding="utf-8") as f:
        analysis = json.load(f)

    # LLM text can contain characters the Windows console code page cannot print.
    sys.stdout.reconfigure(errors="replace")

    findings, mode = explain_findings(analysis.get("findings", []))
    print(f"Mode: {mode}")
    for finding in findings:
        print(f"\n{finding.get('finding_id')}  {finding.get('issue')}")
        print(f"  Explanation:    {finding['explanation']}")
        print(f"  Recommendation: {finding['recommendation']}")
        print(f"  Reference:      {finding['reference']}")


if __name__ == "__main__":
    main()
