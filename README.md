# Domain Security Console & Auditor

An enterprise-grade, high-performance **Python Full-Stack** web application that provides real-time threat intelligence, email authentication analysis, and external attack surface audits.

---

## Key Features

- **Email Spoofing Defense:** Detailed analysis of SPF policies (`-all`, `~all`), DMARC enforcement levels (`reject`, `quarantine`), and DKIM signature detection.
- **DNS & Routing Integrity:** DNSSEC cryptographic chain verification and MX record route inspection.
- **Web & Transport Security:** TLS/SSL certificate health, HTTPS redirection checks, and HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`).
- **External Attack Surface Audit:** High-speed concurrent port scanning across 16 critical network services.
- **Multi-threaded Parallel Engine:** Queries DNS, Web, and Ports concurrently via `ThreadPoolExecutor` (cutting scan duration from ~15s to < 2s).
- **Executive PDF Reporting:** Automated server-side generation of styled PDF security assessment reports.
- **Interactive SOC Cyber UI:** Responsive dark-mode dashboard with quick-test domain chips, real-time radar scan progression, remediation guides, and metric explanation modals.

---

## Architecture Overview

```text
Domain_Security_Scanner/
├── backend/
│   ├── app/
│   │   ├── __init__.py               # Flask Application Factory
│   │   ├── config.py                 # Central configuration
│   │   ├── routes/
│   │   │   ├── web.py                # Web view blueprint (SSR / UI)
│   │   │   └── api.py                # JSON REST API (/api/scan, /api/report/pdf)
│   │   ├── services/                 # Decoupled Domain Services
│   │   │   ├── scanner_orchestrator.py # Concurrent multi-threaded task coordinator
│   │   │   ├── dns_service.py        # MX, TXT, DMARC, DNSSEC lookups
│   │   │   ├── email_security.py     # SPF/DMARC parsing & scoring algorithms
│   │   │   ├── web_security.py       # HTTPS, SSL & HTTP security headers
│   │   │   ├── port_scanner.py       # High-speed concurrent socket scanner
│   │   │   └── report_service.py     # PDF report compilation & remediation logic
│   │   └── utils/
│   │       └── validators.py         # RFC domain sanitization and validation
│   ├── tests/                        # Automated unit & integration tests
│   │   ├── test_validators.py
│   │   ├── test_email_security.py
│   │   └── test_api.py
│   ├── dns_utils.py                  # Backward-compatibility facade
│   └── app.py                        # Backend entrypoint
├── frontend/
│   ├── static/
│   │   ├── style.css                 # SOC cyber theme & animations
│   │   └── script.js                 # Async scan controller & UI interactivity
│   └── templates/
│       ├── index.html                # Main scanner & interactive dashboard
│       └── report_pdf.html           # Print-optimized PDF template
├── run.py                            # Project root launcher
├── requirements.txt
└── README.md
```

---

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Indraik/Domain_Security_Scanner.git
   cd Domain_Security_Scanner
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   You can start the app from the root or the backend folder:
   ```bash
   python run.py
   # or
   python backend/app.py
   ```

4. **Access the Console:**
   Open your browser at:
   ```
   http://127.0.0.1:5000
   ```

---

## Running Automated Tests

Execute the test suite to verify validators, scoring algorithms, and API endpoints:
```bash
python -m unittest discover -s backend/tests -p "test_*.py" -v
```

---

## API Endpoints

- `GET /` — Serves the interactive Security Console.
- `POST /api/scan` — Accepts `{ "domain": "example.com" }`, executes parallel scan, returns JSON payload.
- `POST /api/report/pdf` — Accepts scan JSON data, compiles and streams a downloadable PDF report.
