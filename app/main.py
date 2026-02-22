from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.models import LogRequest, AnalysisResponse
from app.ai_engine import analyze_logs

app = FastAPI(title="FortiGate AI Troubleshooter")

templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: LogRequest):
    return analyze_logs(request.logs)