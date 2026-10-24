"""
Tests for HTTP security header inspection and analysis in SecureSite Auditor.
"""

from scanner.header_scanner import assess_security_headers


def test_missing_all_security_headers():
    headers = {"Content-Type": "text/html"}
    result = assess_security_headers(headers, is_https=True)
    findings = result["findings"]
    
    finding_ids = [f["id"] for f in findings]
    assert "HEADER_CSP_MISSING" in finding_ids
    assert "HEADER_HSTS_MISSING" in finding_ids
    assert "HEADER_CLICKJACKING_RISK" in finding_ids
    assert "HEADER_XCTO_MISSING" in finding_ids
    assert "HEADER_REFERRER_MISSING" in finding_ids


def test_fully_hardened_headers():
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    }
    result = assess_security_headers(headers, is_https=True)
    findings = result["findings"]

    for f in findings:
        assert f["severity"] == "PASS"


def test_csp_weak_directives():
    headers = {
        "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval';",
        "X-Content-Type-Options": "nosniff",
    }
    result = assess_security_headers(headers, is_https=True)
    findings = result["findings"]

    csp_findings = [f for f in findings if f["id"] == "HEADER_CSP_WEAK"]
    assert len(csp_findings) == 1
    assert csp_findings[0]["severity"] == "MEDIUM"
    assert "unsafe-inline" in csp_findings[0]["description"]


def test_modern_csp_frame_ancestors_satisfies_clickjacking():
    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self';",
        "X-Content-Type-Options": "nosniff",
    }
    result = assess_security_headers(headers, is_https=True)
    findings = result["findings"]

    frame_ancestor_findings = [f for f in findings if f["id"] == "HEADER_FRAME_ANCESTORS_ACTIVE"]
    assert len(frame_ancestor_findings) == 1
    assert frame_ancestor_findings[0]["severity"] == "PASS"

    # Confirm that clickjacking risk is not raised
    assert not any(f["id"] == "HEADER_CLICKJACKING_RISK" for f in findings)


def test_short_hsts_warning():
    headers = {
        "Strict-Transport-Security": "max-age=3600",
        "X-Content-Type-Options": "nosniff",
    }
    result = assess_security_headers(headers, is_https=True)
    findings = result["findings"]

    hsts_findings = [f for f in findings if f["id"] == "HEADER_HSTS_SHORT_DURATION"]
    assert len(hsts_findings) == 1
    assert hsts_findings[0]["severity"] == "LOW"


def test_unsafe_referrer_policy():
    headers = {
        "Referrer-Policy": "unsafe-url",
        "X-Content-Type-Options": "nosniff",
    }
    result = assess_security_headers(headers, is_https=True)
    findings = result["findings"]

    rp_findings = [f for f in findings if f["id"] == "HEADER_REFERRER_UNSAFE"]
    assert len(rp_findings) == 1
    assert rp_findings[0]["severity"] == "MEDIUM"
