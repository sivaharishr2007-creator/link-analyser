"""
Tests for URL validation and SSRF defense in SecureSite Auditor.
"""

import pytest
from scanner.url_validator import (
    validate_target_url,
    normalize_url,
    is_safe_redirect_target,
    URLValidationError,
    SSRFBlockedError,
)


def test_normalize_url_prefixes_https():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("http://example.com") == "http://example.com"
    assert normalize_url("https://example.com/test") == "https://example.com/test"


def test_reject_empty_or_none_url():
    with pytest.raises(URLValidationError):
        normalize_url("")
    with pytest.raises(URLValidationError):
        normalize_url(None)


def test_reject_unsupported_schemes():
    unsupported = [
        "ftp://example.com",
        "file:///etc/passwd",
        "gopher://example.com",
        "javascript:alert(1)",
        "data:text/html,test",
    ]
    for url in unsupported:
        with pytest.raises(URLValidationError):
            validate_target_url(url)


def test_reject_embedded_credentials():
    credentials = [
        "http://admin:password@example.com",
        "https://user:pass@1.1.1.1",
        "http://root@example.com",
    ]
    for url in credentials:
        with pytest.raises(URLValidationError, match="embedded user credentials"):
            validate_target_url(url)


def test_reject_loopback_ips():
    loopback_targets = [
        "http://127.0.0.1",
        "https://127.0.0.2",
        "http://127.255.255.254",
        "http://localhost",
        "http://[::1]",
    ]
    for target in loopback_targets:
        with pytest.raises(SSRFBlockedError):
            validate_target_url(target)


def test_reject_private_rfc1918_ips():
    private_targets = [
        "http://10.0.0.1",
        "http://10.254.1.5",
        "http://172.16.0.1",
        "http://172.31.255.254",
        "http://192.168.1.1",
        "http://192.168.100.50",
    ]
    for target in private_targets:
        with pytest.raises(SSRFBlockedError):
            validate_target_url(target)


def test_reject_cloud_metadata():
    metadata_targets = [
        "http://169.254.169.254",
        "http://169.254.169.254/latest/meta-data",
        "http://metadata.google.internal",
        "http://metadata.goog",
        "http://100.100.100.200",
    ]
    for target in metadata_targets:
        with pytest.raises(SSRFBlockedError):
            validate_target_url(target)


def test_valid_public_url():
    # Public domain validation (example.com is standard RFC 2606 reserved public test domain)
    result = validate_target_url("https://example.com")
    assert result["scheme"] == "https"
    assert result["hostname"] == "example.com"
    assert result["port"] == 443
    assert len(result["resolved_ips"]) > 0


def test_redirect_safety_verification():
    base = "https://example.com"
    # Safe redirect
    is_safe, msg, info = is_safe_redirect_target("/login", base)
    assert is_safe is True
    assert info["hostname"] == "example.com"

    # Unsafe redirect to internal SSRF target
    is_safe, msg, info = is_safe_redirect_target("http://127.0.0.1/admin", base)
    assert is_safe is False
    assert "SSRF" in msg or "restricted" in msg or "blocked" in msg

    # Unsafe redirect to cloud metadata
    is_safe, msg, info = is_safe_redirect_target("http://169.254.169.254/latest", base)
    assert is_safe is False
