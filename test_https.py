"""
Tests for HTTPS and TLS assessment functions in SecureSite Auditor.
"""

from scanner.https_scanner import parse_certificate, assess_https_and_tls


def test_parse_certificate_fields():
    mock_cert = {
        "subject": ((("commonName", "example.com"),), (("organizationName", "Example Corp"),)),
        "issuer": ((("commonName", "DigiCert Global Root CA"),), (("organizationName", "DigiCert Inc"),)),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Dec 31 23:59:59 2026 GMT",
        "serialNumber": "1234567890ABCDEF",
    }
    
    parsed = parse_certificate(mock_cert, "example.com")
    
    assert parsed["subject_cn"] == "example.com"
    assert parsed["subject_org"] == "Example Corp"
    assert parsed["issuer_cn"] == "DigiCert Global Root CA"
    assert "www.example.com" in parsed["sans"]
    assert "2026" in parsed["valid_to"]


def test_assess_https_on_unreachable_port():
    # Attempting TLS assessment on an unused port/host should return cleanly with HTTPS_UNAVAILABLE
    result = assess_https_and_tls("192.0.2.1", port=443)  # TEST-NET-1 non-routable IP
    assert result["https_supported"] is False
    assert len(result["findings"]) > 0
    assert any(f["id"] in ("HTTPS_UNAVAILABLE", "TLS_CONNECTION_TIMEOUT") for f in result["findings"])
