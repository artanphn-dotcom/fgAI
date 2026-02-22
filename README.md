# FortiGate AI Troubleshooter

Analyze FortiGate CLI packet sniffer logs and get:
- likely issue summary
- root cause
- severity
- actionable fix recommendations
- next FortiGate CLI commands to verify/fix

## 1) Prerequisites

Install these first:
- Python 3.10+ (recommended 3.11 or newer)
- `pip`
- A Gemini API key

## 2) Clone the project

```bash
git clone <your-repo-url>
cd fortigate-ai
```

## 3) Create a virtual environment

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 4) Install dependencies

```bash
pip install -r requirements.txt
```

## 5) Configure environment variables

Create or edit `.env` in the project root:

```dotenv
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

> Important: Never commit real API keys to GitHub.

## 6) Run the application

From the project root (`fortigate-ai`):

```bash
uvicorn app.main:app --reload
```

You should see server output with a local URL.

## 7) Open in browser

Open:
- http://127.0.0.1:8000

Paste FortiGate packet sniffer logs and click **Analyze Logs**.

## 8) API usage (optional)

### Endpoint
- `POST /analyze`

### Example request
```bash
curl -X POST "http://127.0.0.1:8000/analyze" \
  -H "Content-Type: application/json" \
  -d "{\"logs\":\"id=20085 trace_id=123 func=print_pkt_detail line=5899 msg=\\\"vd-root:0 received a packet (proto=6, 10.1.1.10:51514->172.16.20.15:443)\\\"\"}"
```

## 9) Project structure

```text
fortigate-ai/
├── app/
│   ├── main.py
│   ├── ai_engine.py
│   ├── models.py
│   ├── config.py
│   └── templates/
│       └── index.html
├── requirements.txt
├── .env
└── README.md
```

## 10) Troubleshooting

### `Import ... could not be resolved`
- Ensure your virtual environment is activated.
- Reinstall dependencies:

```bash
pip install -r requirements.txt
```

### `GEMINI_API_KEY` missing or invalid
- Confirm `.env` exists in the project root.
- Check key format and permissions.

### App starts but analysis fails
- Verify internet access for Gemini API calls.
- Try a different model in `.env` using `GEMINI_MODEL`.
- Provide more complete packet sniffer logs (both directions if possible).

---

If you plan to publish to GitHub, add `.env` to `.gitignore` before pushing.
# fgAI
