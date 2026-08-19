import time
import base64
import hmac
import hashlib
import json

from python_ref import (
    inspect_request,
    match_waf_rules,
    rate_limit_check,
    RateLimitState,
    validate_jwt,
    sanitize_input,
    sanitize_headers,
)


def make_jwt(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def test_waf_sql_injection():
    hits = match_waf_rules("id=1' OR '1'='1")
    assert "sql-2" in hits
    hits = match_waf_rules("union select * from users")
    assert "sql-1" in hits


def test_waf_xss():
    hits = match_waf_rules("<script>alert(1)</script>")
    assert "xss-1" in hits
    hits = match_waf_rules("onload=alert(1)")
    assert "xss-2" in hits


def test_waf_lfi():
    hits = match_waf_rules("../../etc/passwd")
    assert "lfi-1" in hits


def test_inspect_request_get():
    args = {"id": "1", "search": "test"}
    hits = inspect_request(args, method="GET")
    assert hits == []


def test_inspect_request_post():
    args = {"id": "1"}
    body = "user=admin' OR '1'='1"
    hits = inspect_request(args, body=body, method="POST")
    assert "sql-2" in hits


def test_rate_limit_allows():
    state = RateLimitState()
    assert rate_limit_check(state, "user1", max_requests=5)
    assert state.counts["user1"] == 1


def test_rate_limit_blocks():
    state = RateLimitState()
    for _ in range(5):
        rate_limit_check(state, "user2", max_requests=5)
    assert not rate_limit_check(state, "user2", max_requests=5)


def test_jwt_valid():
    token = make_jwt({"sub": "alice", "exp": int(time.time()) + 3600}, "secret")
    payload = validate_jwt(token, "secret")
    assert payload["sub"] == "alice"


def test_jwt_expired():
    token = make_jwt({"sub": "alice", "exp": int(time.time()) - 10}, "secret")
    try:
        validate_jwt(token, "secret")
        assert False
    except ValueError as e:
        assert "expired" in str(e)


def test_jwt_wrong_secret():
    token = make_jwt({"sub": "alice"}, "secret")
    try:
        validate_jwt(token, "wrong")
        assert False
    except ValueError as e:
        assert "signature" in str(e)


def test_jwt_unsupported_alg():
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "alice"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    token = f"{header_b64}.{payload_b64}."
    try:
        validate_jwt(token, "secret")
        assert False
    except ValueError as e:
        assert "unsupported algorithm" in str(e)


def test_sanitize_input():
    assert sanitize_input("<script>alert(1)</script>") == "scriptalert(1)/script"
    assert sanitize_input("javascript:alert(1)") == "alert(1)"
    assert sanitize_input("onclick=alert(1)") == "alert(1)"
    assert sanitize_input("normal text") == "normal text"


def test_sanitize_headers():
    headers = {"X-Forwarded-For": "1.2.3.4", "Content-Type": "text/html", "X-Real-IP": "5.6.7.8"}
    clean = sanitize_headers(headers)
    assert "X-Forwarded-For" not in clean
    assert "X-Real-IP" not in clean
    assert clean["Content-Type"] == "text/html"