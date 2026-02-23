from fastapi import APIRouter, HTTPException

from app.services.network_scan_service import start_network_scan, get_network_scan_status
from app.tool_models import NetworkScanStartRequest


router = APIRouter(prefix="/api/network", tags=["Network Scanner"])


@router.post("/scan/start")
async def start_scan(payload: NetworkScanStartRequest):
    try:
        job_id = start_network_scan(payload.target, payload.ports, payload.timeout_seconds)
        return {"job_id": job_id, "status": "running"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to start scan: {exc}")


@router.get("/scan/{job_id}")
async def get_scan_status(job_id: str):
    try:
        return get_network_scan_status(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan job not found")
