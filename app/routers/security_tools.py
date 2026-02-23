from fastapi import APIRouter, HTTPException

from app.services.security_service import (
    port_status_check,
    analyze_banner_risk,
    ssl_certificate_check,
    generate_hashes,
    password_strength,
)
from app.tool_models import (
    PortStatusRequest,
    BannerAnalyzeRequest,
    SSLCertRequest,
    HashRequest,
    PasswordStrengthRequest,
)


router = APIRouter(prefix="/api/security", tags=["Security Tools"])


@router.post("/port-status")
async def port_status(payload: PortStatusRequest):
    try:
        return await port_status_check(payload.host, payload.ports, payload.timeout_seconds)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Port status check failed: {exc}")


@router.post("/banner-analyze")
async def banner_analyze(payload: BannerAnalyzeRequest):
    try:
        return analyze_banner_risk(payload.banner)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Banner analysis failed: {exc}")


@router.post("/ssl-check")
async def ssl_check(payload: SSLCertRequest):
    try:
        return ssl_certificate_check(payload.hostname, payload.port)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"SSL certificate check failed: {exc}")


@router.post("/hash")
async def hash_values(payload: HashRequest):
    try:
        return generate_hashes(payload.text)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Hash generation failed: {exc}")


@router.post("/password-strength")
async def password_checker(payload: PasswordStrengthRequest):
    try:
        return password_strength(payload.password)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Password strength check failed: {exc}")
