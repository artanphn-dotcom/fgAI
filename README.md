# NetOps Multi-Tool Dashboard

Multi-tool web application for network operations and security diagnostics with a single-page dashboard.

Included tool modules:
- DNS Tools
- Network Scanner (nmap-like behavior)
- IP Calculator
- Port Scanner
- Security Tools
- Subnet Visualizer
- Packet Analyzer (future-ready placeholder)

Legacy FortiGate AI analysis endpoint remains available at `POST /analyze`.

---

## 1) Quick Start

### Prerequisites
- Python 3.10+ (recommended 3.11+)
- `pip`
- Optional: Gemini API key

### Install (Windows PowerShell)

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Install (Linux/macOS/WSL)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If you get `externally-managed-environment` on Linux/WSL:

```bash
sudo apt update
sudo apt install -y python3-venv python3-full
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Do not use `sudo pip install` and avoid `--break-system-packages` unless you intentionally want to modify system Python.

### Configure

Create `.env` in project root:

```dotenv
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-2.5-flash
```

### Run

```bash
uvicorn app.main:app --reload
```

Open: `http://127.0.0.1:8000`

The dashboard is single-page and switches modules without full page reload.

---

## 2) Main Dashboard Modules

- **DNS Tools**: A/AAAA/MX/NS/TXT/CNAME lookup, reverse DNS, WHOIS, propagation checks, domain IP resolve
- **Network Scanner**: host discovery, async TCP scanning, basic banner/service hints, OS guess heuristic
- **IP Calculator**: subnet math, CIDR conversion, network/broadcast/usable range, binary view, VLSM plan
- **Port Scanner**: quick host port state checks
- **Security Tools**: banner risk analyzer, SSL cert checker, hash generator, password strength checker
- **Subnet Visualizer**: compact subnet boundary visualization

## 3) API Endpoints

- `GET /` → web UI
- `GET /health` → service metadata and AI mode status
- `POST /analyze` → FortiGate packet-sniffer analysis

### DNS
- `POST /api/dns/lookup`
- `POST /api/dns/reverse`
- `POST /api/dns/whois`
- `POST /api/dns/propagation`
- `POST /api/dns/resolve-ip`

### Network Scanner
- `POST /api/network/scan/start`
- `GET /api/network/scan/{job_id}`

### IP Calculator
- `POST /api/ip/calculate`
- `POST /api/ip/cidr-mask`
- `POST /api/ip/vlsm`

### Security
- `POST /api/security/port-status`
- `POST /api/security/banner-analyze`
- `POST /api/security/ssl-check`
- `POST /api/security/hash`
- `POST /api/security/password-strength`

### Example request

```bash
curl -X POST "http://127.0.0.1:8000/analyze" \
  -H "Content-Type: application/json" \
  -d "{\"logs\":\"id=20085 trace_id=123 func=print_pkt_detail line=5899 msg=\\\"vd-root:0 received a packet (proto=6, 10.1.1.10:51514->172.16.20.15:443)\\\"\"}"
```

---

## 4) Operational Notes

- Input shorter than 20 characters is rejected (`400`).
- If Gemini parsing fails, the service automatically falls back to heuristic analysis.
- `confidence_score` is normalized to `0-100`.
- Severity is normalized to one of: `low`, `medium`, `high`, `critical`.
- Network scans are asynchronous and expose progress through scan job status.
- Network scanner limits: max 1024 hosts per scan and max 1024 ports per scan request.
- Security module is educational and defensive only; no exploit tooling is included.

---

## 5) Recommended Next Steps (Senior Network Ops Track)

### Phase 1: Reliability and Control (Do first)
1. Add request/response logging with a correlation ID per analysis.
2. Add rate limiting (e.g., per IP) for `/analyze`.
3. Add basic auth or SSO before exposing beyond localhost.
4. Add unit tests for regex heuristics and JSON normalization.

### Phase 2: FortiGate Domain Accuracy
1. Expand parsing for policy ID, interface pair, NAT mode, and session state clues.
2. Add a knowledge map for common FortiGate failure signatures:
   - policy deny
   - RPF/route mismatch
   - asymmetric return path
   - SNAT/VIP mismatch
   - MSS/MTU fragmentation issues
3. Add confidence weighting by evidence count, not only pattern hit.

### Phase 3: Production Readiness
1. Containerize service and deploy behind a reverse proxy.
2. Add centralized logs and metrics (`/health`, latency, error rate, fallback rate).
3. Add audit-safe log handling (sanitize sensitive IP/user data if required).
4. Introduce regression test corpus using anonymized real incident snippets.

---

## 6) Project Layout

```text
fortigate-ai/
├── app/
│   ├── main.py
│   ├── ai_engine.py
│   ├── models.py
│   ├── tool_models.py
│   ├── config.py
│   ├── routers/
│   │   ├── dns_tools.py
│   │   ├── network_tools.py
│   │   ├── ip_tools.py
│   │   └── security_tools.py
│   ├── services/
│   │   ├── dns_service.py
│   │   ├── network_scan_service.py
│   │   ├── ip_calc_service.py
│   │   └── security_service.py
│   ├── static/
│   │   ├── css/dashboard.css
│   │   └── js/dashboard.js
│   └── templates/
│       └── index.html
├── requirements.txt
├── .env
└── README.md
```

---

## 7) Troubleshooting

### Missing Gemini key
- Keep running in heuristic mode, or set `GEMINI_API_KEY` in `.env`.

### Analysis call fails
- Check `GET /health`.
- Validate input has meaningful FortiGate packet-sniffer lines.
- Verify internet/API access if Gemini mode is enabled.

### Import issues
- Ensure virtual environment is active.
- Reinstall dependencies:

```bash
python -m pip install -r requirements.txt
```

### `externally-managed-environment` (PEP 668)
- This means you are installing into system Python (common in Debian/Ubuntu/WSL).
- Create and activate a virtual environment, then install using `python -m pip`.
