import ipaddress
import socket
from typing import Dict, List

import dns.exception
import dns.resolver


PUBLIC_RESOLVERS = {
    "Cloudflare-1.1.1.1": "1.1.1.1",
    "Google-8.8.8.8": "8.8.8.8",
    "Quad9-9.9.9.9": "9.9.9.9",
    "OpenDNS-208.67.222.222": "208.67.222.222",
}


def _validate_domain(domain: str) -> str:
    candidate = domain.strip().rstrip(".")
    if not candidate or len(candidate) > 253:
        raise ValueError("Invalid domain")
    return candidate


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    resolver.timeout = 3
    return resolver


def dns_lookup(domain: str, record_type: str) -> Dict:
    safe_domain = _validate_domain(domain)
    resolver = _resolver()

    answers = resolver.resolve(safe_domain, record_type)
    records: List[str] = []

    for item in answers:
        if record_type == "MX":
            records.append(f"{item.preference} {item.exchange}")
        else:
            records.append(str(item))

    return {
        "domain": safe_domain,
        "record_type": record_type,
        "records": records,
        "ttl": getattr(answers.rrset, "ttl", None),
    }


def reverse_dns_lookup(ip_address: str) -> Dict:
    ipaddress.ip_address(ip_address)
    host, aliases, addresses = socket.gethostbyaddr(ip_address)
    return {
        "ip_address": ip_address,
        "hostname": host,
        "aliases": aliases,
        "addresses": addresses,
    }


def domain_ip_resolver(domain: str) -> Dict:
    safe_domain = _validate_domain(domain)
    infos = socket.getaddrinfo(safe_domain, None)
    ip_set = sorted({entry[4][0] for entry in infos})
    return {
        "domain": safe_domain,
        "ip_addresses": ip_set,
    }


def dns_propagation_check(domain: str, record_type: str) -> Dict:
    safe_domain = _validate_domain(domain)
    result = []

    for label, nameserver in PUBLIC_RESOLVERS.items():
        resolver = _resolver()
        resolver.nameservers = [nameserver]
        try:
            answers = resolver.resolve(safe_domain, record_type)
            values = [str(item) for item in answers]
            result.append({
                "resolver": label,
                "nameserver": nameserver,
                "status": "ok",
                "values": values,
                "ttl": getattr(answers.rrset, "ttl", None),
            })
        except dns.exception.DNSException as exc:
            result.append({
                "resolver": label,
                "nameserver": nameserver,
                "status": "error",
                "error": str(exc),
                "values": [],
            })

    return {
        "domain": safe_domain,
        "record_type": record_type,
        "results": result,
    }


def _query_whois_server(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=8) as sock:
        sock.sendall((query + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def whois_lookup(domain: str) -> Dict:
    safe_domain = _validate_domain(domain)

    iana_response = _query_whois_server("whois.iana.org", safe_domain)
    refer_server = "whois.iana.org"

    for line in iana_response.splitlines():
        if line.lower().startswith("refer:"):
            refer_server = line.split(":", 1)[1].strip()
            break

    final_response = _query_whois_server(refer_server, safe_domain)

    important_lines = []
    for line in final_response.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("%") or stripped.startswith("#"):
            continue
        if any(
            stripped.lower().startswith(prefix)
            for prefix in [
                "domain name",
                "registrar",
                "creation date",
                "registry expiry date",
                "updated date",
                "name server",
                "status",
            ]
        ):
            important_lines.append(stripped)

    return {
        "domain": safe_domain,
        "whois_server": refer_server,
        "summary": important_lines[:40],
        "raw_excerpt": final_response[:4000],
    }
