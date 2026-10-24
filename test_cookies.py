"""
Tests for cookie attribute parsing and security flag evaluation in SecureSite Auditor.
"""

from scanner.cookie_scanner import assess_cookies


def test_no_cookies_observed():
    result = assess_cookies([], is_https=True)
    assert result["total_cookies"] == 0
    assert any(f["id"] == "NO_COOKIES_OBSERVED" for f in result["findings"])


def test_insecure_cookie_on_https():
    raw_cookies = ["sessionid=xyz123; Path=/; HttpOnly"]
    result = assess_cookies(raw_cookies, is_https=True)
    
    assert result["total_cookies"] == 1
    assert result["secure_count"] == 0
    assert result["httponly_count"] == 1

    finding_ids = [f["id"] for f in result["findings"]]
    assert "COOKIE_NO_SECURE_sessionid" in finding_ids
    
    secure_finding = next(f for f in result["findings"] if f["id"] == "COOKIE_NO_SECURE_sessionid")
    assert secure_finding["severity"] == "HIGH"


def test_missing_httponly_flag():
    raw_cookies = ["auth_token=abc; Path=/; Secure; SameSite=Strict"]
    result = assess_cookies(raw_cookies, is_https=True)

    assert result["httponly_count"] == 0
    assert result["secure_count"] == 1

    finding_ids = [f["id"] for f in result["findings"]]
    assert "COOKIE_NO_HTTPONLY_auth_token" in finding_ids
    
    httponly_finding = next(f for f in result["findings"] if f["id"] == "COOKIE_NO_HTTPONLY_auth_token")
    assert httponly_finding["severity"] == "MEDIUM"


def test_samesite_none_without_secure():
    raw_cookies = ["tracking=123; SameSite=None; HttpOnly"]
    result = assess_cookies(raw_cookies, is_https=True)

    finding_ids = [f["id"] for f in result["findings"]]
    assert "COOKIE_SAMESITE_NONE_INSECURE_tracking" in finding_ids


def test_fully_hardened_cookie():
    raw_cookies = ["jwt=secret; Path=/; Secure; HttpOnly; SameSite=Strict"]
    result = assess_cookies(raw_cookies, is_https=True)

    assert result["total_cookies"] == 1
    assert result["secure_count"] == 1
    assert result["httponly_count"] == 1
    assert result["samesite_count"] == 1
    assert any(f["id"] == "ALL_COOKIES_HARDENED" for f in result["findings"])
