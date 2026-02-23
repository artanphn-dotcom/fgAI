from fastapi import APIRouter, HTTPException

from app.services.ip_calc_service import calculate_subnet, cidr_to_mask, vlsm_plan
from app.tool_models import IPCalculateRequest, CIDRMaskRequest, VLSMRequest


router = APIRouter(prefix="/api/ip", tags=["IP Calculator"])


@router.post("/calculate")
async def calculate(payload: IPCalculateRequest):
    try:
        return calculate_subnet(payload.network)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"IP calculation failed: {exc}")


@router.post("/cidr-mask")
async def cidr_mask(payload: CIDRMaskRequest):
    try:
        return cidr_to_mask(payload.cidr)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"CIDR conversion failed: {exc}")


@router.post("/vlsm")
async def vlsm(payload: VLSMRequest):
    try:
        return vlsm_plan(payload.base_network, payload.host_requirements)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"VLSM planning failed: {exc}")
