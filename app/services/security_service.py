import asyncio
import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List

from app.services.network_scan_service import parse_ports


BANNER_RISK_PATTERNS = [
    (r"openssh[_\s-]?([0-6]\.|7\.[0-2])", "Potentially outdated OpenSSH version detected"),
    (r"apache/2\.2", "Apache 2.2 is end-of-life"),
    (r"nginx/1\.(0|1|2|3|4|5|6|7|8|9)", "Very old Nginx major/minor version detected"),
    (r"tlsv1\.0|tlsv1\.1", "Legacy TLS version reference found"),
    (r"iis/6\.0", "IIS 6.0 is legacy and unsupported"),
]


async def port_status_check(host: str, ports_spec: str, timeout_seconds: float) -> Dict:
    ports = parse_ports(ports_spec)
    results: List[Dict] = []

    async def check_one(port: int):
        status = "closed"
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_seconds)
            writer.close()
            await writer.wait_closed()
            status = "open"
        except Exception:
            status = "closed"

        results.append({"port": port, "status": status})

    await asyncio.gather(*[check_one(port) for port in ports])
    results.sort(key=lambda item: item["port"])

    return {
        "host": host,
        "results": results,
        "open_ports": [entry["port"] for entry in results if entry["status"] == "open"],
    }


def analyze_banner_risk(banner: str) -> Dict:
    lowered = banner.lower()
    findings = []

    for pattern, finding in BANNER_RISK_PATTERNS:
        if re.search(pattern, lowered):
            findings.append(finding)

    risk = "low"
    if len(findings) >= 3:
        risk = "high"
    elif len(findings) >= 1:
        risk = "medium"

    return {
        "risk_level": risk,
        "findings": findings,
        "recommendations": [
            "Verify detected banner versions against vendor support lifecycle.",
            "Disable unnecessary service banners where possible.",
            "Patch/upgrade services with known EOL versions.",
        ],
    }


def ssl_certificate_check(hostname: str, port: int) -> Dict:
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            cert = secure_sock.getpeercert()

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")

    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after else None
    now = datetime.now(timezone.utc)
    days_to_expiry = (expiry_date - now).days if expiry_date else None

    status = "valid"
    if days_to_expiry is not None and days_to_expiry < 0:
        status = "expired"
    elif days_to_expiry is not None and days_to_expiry <= 30:
        status = "expiring_soon"

    return {
        "hostname": hostname,
        "port": port,
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "serial_number": cert.get("serialNumber"),
        "not_before": not_before,
        "not_after": not_after,
        "days_to_expiry": days_to_expiry,
        "status": status,
    }


def generate_hashes(text: str) -> Dict:
    payload = text.encode("utf-8")
    return {
        "md5": hashlib.md5(payload).hexdigest(),
        "sha1": hashlib.sha1(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def password_strength(password: str) -> Dict:
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 12 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numeric characters")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add symbols")

    if re.search(r"(.)\1{2,}", password):
        score -= 1
        feedback.append("Avoid repeated character sequences")

    if password.lower() in {"password", "admin", "qwerty", "welcome", "fortigate"}:
        score = max(score - 2, 0)
        feedback.append("Avoid common passwords")

    if score <= 2:
        strength = "weak"
    elif score <= 4:
        strength = "moderate"
    elif score <= 6:
        strength = "strong"
    else:
        strength = "very_strong"

    return {
        "strength": strength,
        "score": max(score, 0),
        "max_score": 7,
        "feedback": feedback,
    }
