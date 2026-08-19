# Python reference port of lua-nginx-edge-backend for CI testing
# Mirrors the Lua logic without requiring OpenResty

import re
import json
import base64
import hmac
import hashlib
import time
from dataclasses import dataclass
from typing import Optional, List

WAF_RULES = [
    {"id": "sql-1", "pattern": r"(?i)(union|select|insert|update|delete|drop)\s+.*\s+(from|into|table)"},
    {"id": "sql-2", "pattern": r"(?i)('|\bOR\b|\bAND\b)\s*=\s*['\"]?\s*['\"]?"},
    {"id": "xss-1", "pattern": r"(?i)<script[^>]*>.*</script>"},
    {"id": "xss-2", "pattern": r"(?i)on(load|error|click|mouseover)\s*="},
    {"id": "lfi-1", "pattern": r"\.\./"},
    {"id": "rce-1", "pattern": r"(?i)(system|exec|shell_exec|passthru)\s*\("},
]

SUSPICIOUS_HEADERS = {
    "x-forwarded-for", "x-real-ip", "x-forwarded-host", "x-forwarded-proto",
    "x-original-url", "x-rewrite-url", "forwarded"
}

SANITIZE_PATTERNS = [
    (re.compile(r"[<>]"), ""),
    (re.compile(r"javascript:"), ""),
    (re.compile(r"vbscript:"), ""),
    (re.compile(r"on\w+\s*="), ""),
]


def match_waf_rules(text: str) -> List[str]:
    hits = []
    for rule in WAF_RULES:
        if re.search(rule["pattern"], text):
            hits.append(rule["id"])
    return hits


def inspect_request(args: dict, body: str = "", method: str = "GET") -> List[str]:
    hits = []
    for k, v in args.items():
        val = ",".join(v) if isinstance(v, list) else v
        hits.extend(match_waf_rules(f"{k}={val}"))
    if method == "POST" and body:
        hits.extend(match_waf_rules(body))
    return hits


@dataclass
class RateLimitState:
    counts: dict = None
    def __post_init__(self):
        if self.counts is None:
            self.counts = {}


def rate_limit_check(state: RateLimitState, key: str, max_requests: int = 100, window_seconds: int = 60) -> bool:
    # Simplified: in-memory count (no real window sliding)
    count = state.counts.get(key, 0)
    if count >= max_requests:
        return False
    state.counts[key] = count + 1
    return True


def b64url_decode(input_str: str) -> bytes:
    rem = len(input_str) % 4
    if rem > 0:
        input_str += "=" * (4 - rem)
    input_str = input_str.replace("-", "+").replace("_", "/")
    return base64.urlsafe_b64decode(input_str)


def verify_hs256(payload: str, signature: bytes, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def validate_jwt(token: str, secret: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    if header.get("alg") != "HS256":
        raise ValueError(f"unsupported algorithm: {header.get('alg')}")
    signing_input = f"{header_b64}.{payload_b64}"
    signature = b64url_decode(sig_b64)
    if not verify_hs256(signing_input, signature, secret):
        raise ValueError("invalid signature")
    now = int(time.time())
    if payload.get("exp") and now > payload["exp"]:
        raise ValueError("token expired")
    if payload.get("nbf") and now < payload["nbf"]:
        raise ValueError("token not yet valid")
    return payload


def sanitize_input(input_str: str) -> str:
    out = input_str
    for pattern, repl in SANITIZE_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def sanitize_headers(headers: dict) -> dict:
    clean = {}
    for k, v in headers.items():
        if k.lower() not in SUSPICIOUS_HEADERS:
            clean[k] = v
    return clean