import asyncio
import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Set


SCAN_JOBS: Dict[str, Dict] = {}


COMMON_SERVICE_MAP = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
}


def parse_ports(port_spec: str) -> List[int]:
    ports: Set[int] = set()
    for chunk in [part.strip() for part in port_spec.split(",") if part.strip()]:
        if "-" in chunk:
            start_str, end_str = chunk.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {chunk}")
            ports.update(range(start, end + 1))
        else:
            port = int(chunk)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {chunk}")
            ports.add(port)

    if not ports:
        raise ValueError("At least one port is required")

    if len(ports) > 1024:
        raise ValueError("Port list too large. Maximum allowed ports per scan is 1024")

    return sorted(ports)


def parse_target(target: str) -> List[str]:
    candidate = target.strip()
    if "/" in candidate:
        network = ipaddress.ip_network(candidate, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        if len(hosts) > 1024:
            raise ValueError("Target subnet too large. Maximum hosts per scan is 1024")
        return hosts

    ipaddress.ip_address(candidate)
    return [candidate]


async def is_host_up(host: str, timeout_seconds: float) -> bool:
    discovery_ports = [80, 443, 22, 3389]
    for port in discovery_ports:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_seconds)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            continue

    return False


async def grab_banner(host: str, port: int, timeout_seconds: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_seconds)
        if port in {80, 8080}:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=timeout_seconds)
        writer.close()
        await writer.wait_closed()
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


async def scan_host_ports(host: str, ports: List[int], timeout_seconds: float) -> List[Dict]:
    open_ports = []

    async def scan_one(port: int):
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_seconds)
            writer.close()
            await writer.wait_closed()
            banner = await grab_banner(host, port, timeout_seconds)
            open_ports.append(
                {
                    "port": port,
                    "state": "open",
                    "service_guess": COMMON_SERVICE_MAP.get(port, "unknown"),
                    "banner": banner[:200],
                }
            )
        except Exception:
            return

    tasks = [scan_one(port) for port in ports]
    await asyncio.gather(*tasks)
    return sorted(open_ports, key=lambda item: item["port"])


def guess_os(open_ports: List[Dict]) -> str:
    port_set = {entry["port"] for entry in open_ports}
    if 3389 in port_set and 445 in port_set:
        return "Likely Windows host (heuristic)"
    if 22 in port_set and 3389 not in port_set:
        return "Likely Linux/Unix host (heuristic)"
    if not port_set:
        return "Unknown (no open ports discovered)"
    return "Unknown (insufficient fingerprint data)"


async def _run_scan_job(job_id: str, target: str, ports: List[int], timeout_seconds: float):
    job = SCAN_JOBS[job_id]
    try:
        hosts = parse_target(target)
        total_hosts = len(hosts)
        scanned = 0

        results = []
        for host in hosts:
            host_up = await is_host_up(host, timeout_seconds)
            open_ports = await scan_host_ports(host, ports, timeout_seconds) if host_up else []

            results.append(
                {
                    "host": host,
                    "status": "up" if host_up else "down",
                    "open_ports": open_ports,
                    "os_guess": guess_os(open_ports),
                }
            )

            scanned += 1
            job["progress"] = int((scanned / total_hosts) * 100)
            job["message"] = f"Scanned {scanned}/{total_hosts} hosts"

        job["status"] = "completed"
        job["finished_at"] = datetime.now(timezone.utc).isoformat()
        job["result"] = {
            "target": target,
            "requested_ports": ports,
            "summary": {
                "hosts_total": total_hosts,
                "hosts_up": sum(1 for item in results if item["status"] == "up"),
                "hosts_down": sum(1 for item in results if item["status"] == "down"),
            },
            "hosts": results,
        }
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = str(exc)
        job["finished_at"] = datetime.now(timezone.utc).isoformat()


def start_network_scan(target: str, ports_spec: str, timeout_seconds: float) -> str:
    ports = parse_ports(ports_spec)
    _ = parse_target(target)

    job_id = str(uuid.uuid4())
    SCAN_JOBS[job_id] = {
        "id": job_id,
        "status": "running",
        "progress": 0,
        "message": "Starting scan",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
        "error": None,
    }

    asyncio.create_task(_run_scan_job(job_id, target, ports, timeout_seconds))
    return job_id


def get_network_scan_status(job_id: str) -> Dict:
    if job_id not in SCAN_JOBS:
        raise KeyError("Scan job not found")
    return SCAN_JOBS[job_id]
