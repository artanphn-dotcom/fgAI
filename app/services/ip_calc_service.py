import ipaddress
from typing import Dict, List


def _binary_ip(ip: ipaddress.IPv4Address) -> str:
    return ".".join(f"{octet:08b}" for octet in map(int, str(ip).split(".")))


def calculate_subnet(network_value: str) -> Dict:
    interface = ipaddress.ip_interface(network_value)
    if not isinstance(interface.ip, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 is supported for this calculator")

    network = interface.network
    network_address = network.network_address
    broadcast_address = network.broadcast_address
    hosts = list(network.hosts())

    first_host = str(hosts[0]) if hosts else str(network_address)
    last_host = str(hosts[-1]) if hosts else str(broadcast_address)

    total_addresses = network.num_addresses
    usable_hosts = max(total_addresses - 2, 0) if network.prefixlen <= 30 else total_addresses

    return {
        "input": network_value,
        "ip_address": str(interface.ip),
        "cidr": network.prefixlen,
        "subnet_mask": str(network.netmask),
        "wildcard_mask": str(network.hostmask),
        "network_address": str(network_address),
        "broadcast_address": str(broadcast_address),
        "first_host": first_host,
        "last_host": last_host,
        "total_addresses": total_addresses,
        "usable_hosts": usable_hosts,
        "binary": {
            "ip": _binary_ip(interface.ip),
            "subnet_mask": _binary_ip(network.netmask),
            "network": _binary_ip(network_address),
            "broadcast": _binary_ip(broadcast_address),
        },
    }


def cidr_to_mask(cidr: int) -> Dict:
    network = ipaddress.ip_network(f"0.0.0.0/{cidr}", strict=False)
    return {
        "cidr": cidr,
        "subnet_mask": str(network.netmask),
        "wildcard_mask": str(network.hostmask),
    }


def vlsm_plan(base_network: str, host_requirements: List[int]) -> Dict:
    network = ipaddress.ip_network(base_network, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 VLSM is supported")

    sorted_requirements = sorted(host_requirements, reverse=True)
    current_ip = int(network.network_address)
    allocations = []

    for required_hosts in sorted_requirements:
        if required_hosts < 2:
            raise ValueError("Each VLSM subnet must request at least 2 hosts")

        needed = required_hosts + 2
        prefix = 32
        while prefix >= 0 and (2 ** (32 - prefix)) < needed:
            prefix -= 1

        if prefix < 0:
            raise ValueError("Unable to allocate requested host block")

        block_size = 2 ** (32 - prefix)

        if current_ip % block_size != 0:
            current_ip = ((current_ip // block_size) + 1) * block_size

        subnet = ipaddress.ip_network((current_ip, prefix), strict=False)

        if subnet.network_address < network.network_address or subnet.broadcast_address > network.broadcast_address:
            raise ValueError("Insufficient address space for requested VLSM plan")

        hosts = list(subnet.hosts())
        allocations.append(
            {
                "required_hosts": required_hosts,
                "subnet": str(subnet),
                "subnet_mask": str(subnet.netmask),
                "network_address": str(subnet.network_address),
                "broadcast_address": str(subnet.broadcast_address),
                "first_host": str(hosts[0]) if hosts else str(subnet.network_address),
                "last_host": str(hosts[-1]) if hosts else str(subnet.broadcast_address),
                "usable_hosts": max(subnet.num_addresses - 2, 0),
            }
        )

        current_ip = int(subnet.broadcast_address) + 1

    return {
        "base_network": str(network),
        "allocations": allocations,
    }
