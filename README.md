# SecureSite Auditor — Web Application Security Scanner
> **Defensive Web Application Security Assessment & Hardening Framework**  
> *Cybersecurity Training Project for B.Tech Computer Science Engineering (AI & Data Science)*

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask%203.x-green.svg)
![Tests](https://img.shields.io/badge/Tests-28%20Passed-brightgreen.svg)
![Security](https://img.shields.io/badge/SSRF%20Guard-Enforced-cyan.svg)

---

## 1. Project Overview & Objective

**SecureSite Auditor** is an educational, defensive web application security scanner designed to evaluate authorized web applications for transport configuration issues, missing security response headers, cookie vulnerabilities, and information disclosure risks.

### Educational Intent for B.Tech CSE (AI & Data Science)
Students specializing in AI and Data Science often deploy web dashboards, inference APIs, and interactive machine learning models (e.g. Flask/FastAPI/Streamlit/Graduio applications). In production, these services are frequently exposed to automated web crawlers without essential defensive controls. 

SecureSite Auditor bridges this knowledge gap by providing:
1. **Passive Defensive Auditing:** Non-intrusive evaluation that avoids destructive exploitation.
2. **Actionable Remediation Guidance:** Multi-server configuration snippets (Nginx, Apache, Express, Flask, Caddy).
3. **SSRF Defense Architecture:** Hardened against Server-Side Request Forgery attacks, demonstrating how to securely accept and resolve untrusted user URLs.
4. **Transparent Scoring Formula:** 0–100 posture score and letter grades (A+ to F) with clear deduction breakdowns.

---

## 2. Mandatory Defensive Assessment Boundary

> [!IMPORTANT]
> **No Claim of Absolute Security:** SecureSite Auditor performs external transport and response header configuration auditing. A high score (e.g., 95/100 or Grade A+) indicates strong baseline encryption and browser defense-in-depth headers. It does **NOT** certify that a website is free of application-layer vulnerabilities such as SQL injection, Cross-Site Scripting (XSS), insecure deserialization, broken object-level authorization (BOLA), or 0-day flaws.

---

## 3. Core Architecture & Key Modules

```
cy/
├── app.py                     # Flask application routes, REST API, report export endpoints
├── config.py                  # Security settings, timeouts, blocked SSRF CIDR ranges
├── database.py                # SQLite persistence layer with ephemeral (in-memory) mode
├── requirements.txt           # Dependencies (Flask, requests, beautifulsoup4, pytest)
├── scanner/
│   ├── __init__.py            # Scanner package entrypoint
│   ├── url_validator.py       # SSRF guard, URL normalization, DNS resolution, IP filtering
│   ├── https_scanner.py       # TLS verification, certificate parsing, expiration tracking
│   ├── header_scanner.py      # HTTP security headers (CSP, HSTS, XFO vs frame-ancestors, etc.)
│   ├── cookie_scanner.py      # Cookie inspection (Secure, HttpOnly, SameSite, prefixes)
│   ├── response_scanner.py    # Latency, server banners, security.txt, robots.txt, HTML checks
│   ├── scoring.py             # Weighted deduction scoring engine (0-100, A+ to F)
│   └── engine.py              # Orchestrates the 7-phase scanning pipeline
├── reports/
│   ├── __init__.py
│   └── exporter.py            # Standalone printable HTML report and RFC 4180 CSV export
├── static/
│   ├── css/
│   │   └── style.css          # Premium dark cybersecurity dashboard design
│   └── js/
│       ├── app.js             # Client controller, live scan checklist, filters, accordions
│       └── charts.js          # SVG radial score meters and severity donut helpers
├── templates/
│   ├── base.html              # Layout, sidebar navigation, topbar, alerts
│   ├── index.html             # Dashboard overview, quick scan form, metrics, curriculum
│   ├── scan.html              # Dedicated scanner page with live phase checklist
│   ├── results.html           # Full interactive report with remediation and filters
│   ├── history.html           # Historical scan repository with search and deletion
│   ├── knowledge_base.html    # Academic reference handbook with server code snippets
│   └── methodology.html       # Methodology, pipeline breakdown, and security boundary
└── tests/
    ├── conftest.py            # Pytest test client and isolated SQLite database fixture
    ├── test_url_validator.py  # Tests SSRF protection, IP ranges, invalid schemes
    ├── test_headers.py        # Tests CSP, HSTS, X-Frame-Options, X-Content-Type
    ├── test_cookies.py        # Tests Secure, HttpOnly, SameSite cookie evaluation
    ├── test_https.py          # Tests TLS verification and certificate parsing
    └── test_api_and_routes.py # Tests Flask endpoints, ephemeral toggle, CSV/HTML exports
```

---

## 4. Security Scanning Features & Defense Mechanics

### A. URL Validation & SSRF Prevention (`scanner/url_validator.py`)
- **Protocol Whitelisting:** Permits strictly `http://` and `https://`. Rejects `file://`, `ftp://`, `gopher://`, `javascript:`, `data:`.
- **Embedded Credential Rejection:** Rejects smuggling attempts such as `http://user:pass@host/`.
- **DNS Resolution & Subnet Filtering:** Resolves hostnames to underlying IPv4 and IPv6 addresses.
- **Blocked Address Ranges:**
  - Loopback (`127.0.0.0/8`, `::1`)
  - RFC 1918 Private Subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Link-Local (`169.254.0.0/16`, `fe80::/10`)
  - Cloud Instance Metadata Services (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`)
  - Carrier-grade NAT (`100.64.0.0/10`), Multicast, Reserved, and Documentation IPs.
- **Safe Redirection Loop:** Evaluates `Location` headers at every redirect hop through the SSRF filter before initiating a request.

### B. HTTPS & TLS Assessment (`scanner/https_scanner.py`)
- **Strict Certificate Verification:** Always uses `verify_mode=CERT_REQUIRED` and `check_hostname=True`. Never disables verification to force a scan to succeed.
- **Peer Certificate Inspection:** Extracts Subject CN, Organization, Issuer, SAN domains, and serial number.
- **Expiration Thresholds:** Flags certificates expired (`CRITICAL`) or expiring within 30 days (`MEDIUM`).
- **Negotiated Protocol & Cipher:** Checks negotiated TLS protocol (flags legacy TLS 1.0/1.1) and cipher suite.

### C. HTTP Security Headers (`scanner/header_scanner.py`)
- **Content-Security-Policy (CSP):** Audits `default-src`, `script-src`, flags `unsafe-inline` or `unsafe-eval`, checks `object-src 'none'`.
- **Strict-Transport-Security (HSTS):** Checks `max-age` (warns if < 1 year), `includeSubDomains`, `preload`.
- **X-Frame-Options vs Modern CSP frame-ancestors:** Explains Clickjacking / UI Redressing. Prioritizes modern `frame-ancestors` while accounting for legacy XFO.
- **X-Content-Type-Options:** Evaluates `nosniff` to protect against MIME confusion attacks.
- **Referrer-Policy:** Audits `strict-origin-when-cross-origin` vs unsafe policies like `unsafe-url`.
- **Permissions-Policy:** Restricts camera, microphone, and geolocation APIs.

### D. Cookie Security Attributes (`scanner/cookie_scanner.py`)
- **Secure Flag:** Ensures cookies are only transmitted over TLS encryption.
- **HttpOnly Flag:** Blocks JavaScript `document.cookie` access to mitigate XSS token theft.
- **SameSite Attribute:** Evaluates `Strict`, `Lax`, and `None` (requiring Secure) for CSRF defense.
- **Limitations:** Explains that only initial unauthenticated response cookies are inspected.

### E. Information Leakage & Reconnaissance (`scanner/response_scanner.py`)
- **Server Banners:** Flags detailed version disclosures (e.g. `Apache/2.4.41 (Ubuntu)`).
- **Backend Headers:** Flags `X-Powered-By` (e.g. `PHP/7.4`, `Express`).
- **RFC 9116 `security.txt`:** Checks `/.well-known/security.txt` and `/security.txt`.
- **Robots.txt Analysis:** Checks for sensitive exposed administrative routes.

---

## 5. Storage Modes: Ephemeral vs. Persistent (SQLite)

SecureSite Auditor gives students and security auditors full control over scan data retention:

- **Persistent Mode (Default):** Saves scan results, scores, metadata, and full findings JSON into SQLite (`scans.db`). Scans are visible in the **Scan History** tab and can be retrieved, re-scanned, or deleted at any time.
- **Ephemeral Mode (In-Memory Only):** When the "Ephemeral Mode" checkbox is enabled, the scan runs purely in memory. Zero rows are written to SQLite, protecting privacy for sensitive internal test targets. Ephemeral reports can still be exported to HTML/CSV directly from client memory!

---

## 6. Installation & Quick Start

### Prerequisites
- Python 3.10+
- pip

### Step-by-Step Setup
```bash
# 1. Clone repository
git clone https://github.com/your-username/securesite-auditor.git
cd securesite-auditor

# 2. Create virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run automated test suite
python -m pytest -v

# 5. Launch web application
python app.py
```

Open your browser to:
**http://127.0.0.1:5000**

---

## 7. Running Tests

The test suite covers unit tests and integration tests across URL validation, SSRF checks, HTTP headers, cookies, TLS certificates, Flask routes, and report generators:

```bash
python -m pytest -v
```

Expected output:
```text
============================= test session starts =============================
collected 28 items

tests/test_api_and_routes.py::test_dashboard_route PASSED                [  3%]
tests/test_api_and_routes.py::test_pages_routes PASSED                   [  7%]
tests/test_api_and_routes.py::test_api_scan_empty_payload PASSED         [ 10%]
tests/test_api_and_routes.py::test_api_scan_ssrf_rejection PASSED        [ 14%]
tests/test_api_and_routes.py::test_ephemeral_mode_does_not_persist PASSED [ 17%]
tests/test_api_and_routes.py::test_persistent_mode_persists_to_database PASSED [ 21%]
tests/test_cookies.py::test_no_cookies_observed PASSED                   [ 25%]
tests/test_cookies.py::test_insecure_cookie_on_https PASSED              [ 28%]
tests/test_cookies.py::test_missing_httponly_flag PASSED                 [ 32%]
tests/test_cookies.py::test_samesite_none_without_secure PASSED          [ 35%]
tests/test_cookies.py::test_fully_hardened_cookie PASSED                 [ 39%]
tests/test_headers.py::test_missing_all_security_headers PASSED          [ 42%]
tests/test_headers.py::test_fully_hardened_headers PASSED                [ 46%]
tests/test_headers.py::test_csp_weak_directives PASSED                   [ 50%]
tests/test_headers.py::test_modern_csp_frame_ancestors_satisfies_clickjacking PASSED [ 53%]
tests/test_headers.py::test_short_hsts_warning PASSED                    [ 57%]
tests/test_headers.py::test_unsafe_referrer_policy PASSED                [ 60%]
tests/test_https.py::test_parse_certificate_fields PASSED                [ 64%]
tests/test_https.py::test_assess_https_on_unreachable_port PASSED        [ 67%]
tests/test_url_validator.py::test_normalize_url_prefixes_https PASSED    [ 71%]
tests/test_url_validator.py::test_reject_empty_or_none_url PASSED        [ 75%]
tests/test_url_validator.py::test_reject_unsupported_schemes PASSED      [ 78%]
tests/test_url_validator.py::test_reject_embedded_credentials PASSED     [ 82%]
tests/test_url_validator.py::test_reject_loopback_ips PASSED             [ 85%]
tests/test_url_validator.py::test_reject_private_rfc1918_ips PASSED      [ 89%]
tests/test_url_validator.py::test_reject_cloud_metadata PASSED           [ 92%]
tests/test_url_validator.py::test_valid_public_url PASSED                [ 96%]
tests/test_url_validator.py::test_redirect_safety_verification PASSED    [100%]

============================= 28 passed in 9.10s ==============================
```

---

## 8. REST API Reference

### 1. Launch Security Audit
**Endpoint:** `POST /api/scan`  
**Request Payload:**
```json
{
  "url": "https://example.com",
  "ephemeral": false
}
```
**Response (200 OK):**
```json
{
  "scan_id": "7f8490a2-...",
  "normalized_url": "https://example.com",
  "target_host": "example.com",
  "security_score": 85,
  "letter_grade": "B",
  "grade_label": "Good Security Baseline",
  "findings_summary": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 1,
    "INFO": 1,
    "PASS": 4
  },
  "findings": [...]
}
```

### 2. Retrieve Scan by ID
**Endpoint:** `GET /api/scan/<scan_id>`  
**Response (200 OK):** Full scan results JSON.

### 3. Delete Scan Record
**Endpoint:** `POST /api/scan/<scan_id>/delete`

### 4. Clear All History
**Endpoint:** `POST /api/history/clear`

### 5. Report Exports
- `GET /export/<scan_id>/html`: Download standalone HTML report.
- `GET /export/<scan_id>/csv`: Download RFC 4180 CSV findings report.
- `POST /export/ephemeral/html`: Export in-memory ephemeral scan to HTML.
- `POST /export/ephemeral/csv`: Export in-memory ephemeral scan to CSV.

---

## 9. Academic Training Alignment (AI & Data Science)

| Curriculum Area | Web Security Vulnerability | Defensive Hardening Concept |
|:---|:---|:---|
| Model Serving (REST APIs) | SSRF via remote image/data fetch | IP filtering, DNS pre-resolution, CIDR blocking |
| Web Dashboards | Cross-Site Scripting (XSS) | Content-Security-Policy with strict nonces |
| Interactive Web Apps | Clickjacking / UI Redressing | CSP `frame-ancestors 'self'` and `X-Frame-Options` |
| User Authentication | Session Hijacking & MITM | `Secure`, `HttpOnly`, `SameSite=Strict`, HSTS |
| Reconnaissance Defense | Exploit Footprinting | Stripping `Server` and `X-Powered-By` banners |
| Responsible Disclosure | Uncoordinated Bug Leakage | RFC 9116 `security.txt` publishing |

---

## 10. License
This project is open-source under the MIT License. Developed for educational, research, and defensive security training purposes.
