import logging
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from app.models import LogRequest, AnalysisResponse
from app.ai_engine import analyze_logs
from app.config import APP_NAME, APP_VERSION, GEMINI_MODEL, GEMINI_API_KEY
from app.routers.dns_tools import router as dns_router
from app.routers.network_tools import router as network_router
from app.routers.ip_tools import router as ip_router
from app.routers.security_tools import router as security_router

logger = logging.getLogger("fortigate_ai")

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="AI-assisted analysis of FortiGate packet-sniffer logs with deterministic fallback heuristics."
)

templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(dns_router)
app.include_router(network_router)
app.include_router(ip_router)
app.include_router(security_router)


@app.on_event("startup")
async def on_startup():
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting %s v%s", APP_NAME, APP_VERSION)
    logger.info("Gemini model: %s | AI enabled: %s", GEMINI_MODEL, bool(GEMINI_API_KEY))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "ai_enabled": bool(GEMINI_API_KEY),
        "model": GEMINI_MODEL,
    }


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: LogRequest):
    logs = request.logs.strip()
    if len(logs) < 20:
        raise HTTPException(status_code=400, detail="Provide at least 20 characters of FortiGate log data.")

    try:
        return analyze_logs(logs)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error during log analysis")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")