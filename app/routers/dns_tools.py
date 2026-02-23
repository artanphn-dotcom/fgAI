import asyncio

import dns.exception
from fastapi import APIRouter, HTTPException

from app.services.dns_service import (
    dns_lookup,
    reverse_dns_lookup,
    whois_lookup,
    dns_propagation_check,
    domain_ip_resolver,
)
from app.tool_models import (
    DNSLookupRequest,
    ReverseDNSRequest,
    WhoisRequest,
    DNSPropagationRequest,
    DomainIPRequest,
)


router = APIRouter(prefix="/api/dns", tags=["DNS Tools"])


@router.post("/lookup")
async def lookup(payload: DNSLookupRequest):
    try:
        return await asyncio.to_thread(dns_lookup, payload.domain, payload.record_type)
    except dns.exception.DNSException as exc:
        raise HTTPException(status_code=400, detail=f"DNS lookup failed: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/reverse")
async def reverse(payload: ReverseDNSRequest):
    try:
        return await asyncio.to_thread(reverse_dns_lookup, payload.ip_address)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Reverse DNS failed: {exc}")


@router.post("/whois")
async def whois(payload: WhoisRequest):
    try:
        return await asyncio.to_thread(whois_lookup, payload.domain)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"WHOIS lookup failed: {exc}")


@router.post("/propagation")
async def propagation(payload: DNSPropagationRequest):
    try:
        return await asyncio.to_thread(dns_propagation_check, payload.domain, payload.record_type)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Propagation check failed: {exc}")


@router.post("/resolve-ip")
async def resolve_ip(payload: DomainIPRequest):
    try:
        return await asyncio.to_thread(domain_ip_resolver, payload.domain)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Domain IP resolve failed: {exc}")
