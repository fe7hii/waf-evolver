"""
fitness.py
Turns a WAF/application response into a success score. Heuristic by design;
for a specific category the dominant reward comes from VALIDATION (for SQLi,
active boolean/time confirmation when a prober is available), not from merely
not being blocked. Over-encoded payloads are penalized because they bypass
the filter without reaching the backend as an attack.
"""
import urllib.parse
from dataclasses import dataclass

from . import validators

WAF_BLOCK_SIGNATURES = [
    "access denied", "request blocked", "security violation",
    "mod_security", "modsecurity", "forbidden", "not acceptable",
    "you have been blocked", "attack detected", "malicious request",
    "cloudflare", "incapsula", "sucuri", "imperva", "akamai",
    "web application firewall", "waf", "your request has been blocked",
]

WAF_HEADER_SIGNATURES = [
    "cf-ray", "x-sucuri-id", "x-waf-status", "x-akamai-transformed",
    "x-iinfo", "x-cdn", "server: cloudflare",
]


@dataclass
class FitnessResult:
    score: float
    status_code: int
    blocked: bool
    reason: str
    validated: bool | None = None


def _encoding_depth(payload: str) -> int:
    depth, s = 0, payload
    for _ in range(6):
        if "%" not in s:
            break
        try:
            dec = urllib.parse.unquote(s)
        except Exception:
            break
        if dec == s:
            break
        s, depth = dec, depth + 1
    return depth


def calculate_fitness(
    response,
    baseline_response,
    payload: str,
    category: str = "generic",
    use_dynamic_validation: bool = False,
    browser_session=None,
    prober=None,
    baseline_stats=None,
    xss_target=None,
) -> FitnessResult:
    score = 0.0
    reasons = []
    specific = category != "generic"

    body_lower = response.text.lower()
    matched_sigs = [sig for sig in WAF_BLOCK_SIGNATURES if sig in body_lower]
    blocked = response.status_code in (403, 406) or bool(matched_sigs)

    if blocked:
        score -= 50
        if response.status_code in (403, 406):
            reasons.append(f"{response.status_code} looks blocked (-50)")
        else:
            reasons.append(f"WAF block signature in body: {matched_sigs[:2]} (-50)")
    elif response.status_code == 429:
        score -= 20
        reasons.append("429 rate-limited (-20)")
    elif response.status_code >= 500:
        score += 20
        reasons.append("5xx - triggered a server error, potentially interesting (+20)")
    elif response.status_code == 200:
        if specific:
            score += 10
            reasons.append("200 OK - passed the filter (+10, not sufficient alone)")
        else:
            score += 40
            reasons.append("200 OK (+40)")
    else:
        score += 5
        reasons.append(f"{response.status_code} - not blocked (+5)")

    depth = _encoding_depth(payload)
    if depth >= 2:
        penalty = min(12 * (depth - 1), 48)
        score -= penalty
        reasons.append(f"over-encoded x{depth} - backend likely won't decode it (-{penalty:.0f})")

    baseline_len = len(baseline_response.text)
    resp_len = len(response.text)
    size_diff_ratio = abs(resp_len - baseline_len) / max(baseline_len, 1)
    if not specific:
        if size_diff_ratio < 0.05:
            score += 20
            reasons.append("size very close to baseline, likely a normal page (+20)")
        elif size_diff_ratio > 0.5:
            score -= 10
            reasons.append("size very different, could be a block page (-10)")

    headers_str = str(response.headers).lower()
    matched_headers = [h for h in WAF_HEADER_SIGNATURES if h in headers_str]
    if matched_headers:
        score -= 5
        reasons.append(f"WAF header detected: {matched_headers} (-5, informational)")

    time_diff = abs(response.elapsed.total_seconds() - baseline_response.elapsed.total_seconds())
    if time_diff > 1.0:
        score -= 8
        reasons.append(f"response-time anomaly: {time_diff:.2f}s difference (-8)")

    payload_reflected = bool(payload and len(payload) > 5 and payload in response.text)
    if payload_reflected and not specific:
        score += 8
        reasons.append("payload reflected in response (+8, weak signal)")

    validated = None
    if specific:
        if category == "xss" and use_dynamic_validation and browser_session is not None \
                and getattr(browser_session, "available", False):
            if xss_target and xss_target.get("live") and not blocked:
                validated, val_reason = browser_session.check_live(
                    xss_target["url"], xss_target["method"],
                    xss_target["param"], payload, xss_target.get("headers"),
                    stored=xss_target.get("stored", False),
                )
            else:
                validated, val_reason = browser_session.check(response.text)
            val_reason = f"[dynamic authoritative] {val_reason}"
        else:
            validated, val_reason = validators.validate(
                category, response.text, payload, use_dynamic=False,
                prober=(prober if not blocked else None),
                baseline_stats=baseline_stats,
            )
        if validated is True:
            score += 80
            reasons.append(f"VALIDATED ({category}): {val_reason} (+80)")
        elif validated is False:
            score -= 15
            reasons.append(f"NOT validated ({category}): {val_reason} (-15)")

    return FitnessResult(
        score=score,
        status_code=response.status_code,
        blocked=blocked,
        reason="; ".join(reasons),
        validated=validated,
    )
