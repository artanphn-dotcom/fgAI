from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class DNSLookupRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    record_type: str = Field(default="A", min_length=1, max_length=10)

    @field_validator("record_type")
    @classmethod
    def normalize_record_type(cls, value: str) -> str:
        normalized = value.strip().upper()
        allowed = {"A", "AAAA", "MX", "NS", "TXT", "CNAME"}
        if normalized not in allowed:
            raise ValueError(f"record_type must be one of: {', '.join(sorted(allowed))}")
        return normalized


class ReverseDNSRequest(BaseModel):
    ip_address: str = Field(..., min_length=7, max_length=45)


class WhoisRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)


class DNSPropagationRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    record_type: str = Field(default="A", min_length=1, max_length=10)

    @field_validator("record_type")
    @classmethod
    def normalize_record_type(cls, value: str) -> str:
        normalized = value.strip().upper()
        allowed = {"A", "AAAA", "MX", "NS", "TXT", "CNAME"}
        if normalized not in allowed:
            raise ValueError(f"record_type must be one of: {', '.join(sorted(allowed))}")
        return normalized


class DomainIPRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)


class NetworkScanStartRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=64)
    ports: str = Field(default="22,53,80,443,3389", min_length=1, max_length=500)
    timeout_seconds: float = Field(default=0.8, ge=0.1, le=5.0)


class IPCalculateRequest(BaseModel):
    network: str = Field(..., min_length=3, max_length=64)


class CIDRMaskRequest(BaseModel):
    cidr: int = Field(..., ge=0, le=32)


class VLSMRequest(BaseModel):
    base_network: str = Field(..., min_length=3, max_length=64)
    host_requirements: List[int] = Field(..., min_length=1, max_length=32)


class PortStatusRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    ports: str = Field(default="22,80,443", min_length=1, max_length=500)
    timeout_seconds: float = Field(default=1.0, ge=0.1, le=5.0)


class BannerAnalyzeRequest(BaseModel):
    banner: str = Field(..., min_length=1, max_length=8000)


class SSLCertRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


class HashRequest(BaseModel):
    text: str = Field(..., min_length=0, max_length=100000)


class PasswordStrengthRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=1024)
