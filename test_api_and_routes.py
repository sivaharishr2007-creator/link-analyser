"""
Integration tests for Flask routes, REST API endpoints, and report exports.
"""

import json
from database import get_scan, save_scan


def test_dashboard_route(test_client):
    response = test_client.get("/")
    assert response.status_code == 200
    assert b"SecureSite Auditor" in response.data
    assert b"Security Posture Dashboard" in response.data


def test_pages_routes(test_client):
    routes = ["/scan", "/history", "/knowledge-base", "/methodology"]
    for route in routes:
        resp = test_client.get(route)
        assert resp.status_code == 200


def test_api_scan_empty_payload(test_client):
    resp = test_client.post("/api/scan", json={})
    assert resp.status_code == 400
    data = json.loads(resp.data)
    assert data["success"] is False


def test_api_scan_ssrf_rejection(test_client):
    resp = test_client.post("/api/scan", json={"url": "http://127.0.0.1:8080"})
    data = json.loads(resp.data)
    assert data["success"] is False or data["error_message"] is not None
    assert any("SSRF" in f.get("title", "") or "SSRF" in f.get("category", "") for f in data.get("findings", []))


def test_ephemeral_mode_does_not_persist(test_client):
    resp = test_client.post("/api/scan", json={
        "url": "http://127.0.0.1",
        "ephemeral": True
    })
    data = json.loads(resp.data)
    scan_id = data["scan_id"]
    
    # Confirm it is NOT in database
    retrieved = get_scan(scan_id, db_path=test_client.application.config["DATABASE_PATH"])
    assert retrieved is None


def test_persistent_mode_persists_to_database(test_client):
    # Create mock scan
    mock_scan = {
        "scan_id": "test-uuid-12345",
        "input_url": "https://example.com",
        "normalized_url": "https://example.com",
        "target_host": "example.com",
        "timestamp": "2026-10-19T12:00:00Z",
        "security_score": 85,
        "letter_grade": "B",
        "grade_label": "Good Security Baseline",
        "duration_seconds": 1.2,
        "is_ephemeral": False,
        "findings_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 1, "INFO": 1, "PASS": 4},
        "findings": [
            {
                "id": "TEST_FINDING",
                "title": "Test Finding Title",
                "category": "HTTP Security Headers",
                "severity": "PASS",
                "description": "Test description",
                "remediation": "Test remediation code",
            }
        ],
    }

    db_path = test_client.application.config["DATABASE_PATH"]
    stored = save_scan(mock_scan, db_path=db_path)
    assert stored is True

    # Retrieve from DB
    retrieved = get_scan("test-uuid-12345", db_path=db_path)
    assert retrieved is not None
    assert retrieved["target_host"] == "example.com"
    assert retrieved["security_score"] == 85

    # Test report export routes for this scan
    html_export = test_client.get("/export/test-uuid-12345/html")
    assert html_export.status_code == 200
    assert b"Security Audit Report" in html_export.data
    assert b"example.com" in html_export.data

    csv_export = test_client.get("/export/test-uuid-12345/csv")
    assert csv_export.status_code == 200
    assert b"TEST_FINDING" in csv_export.data
    assert b"Finding Title" in csv_export.data
