"""Host discovery routines."""
from __future__ import annotations

import ipaddress
import platform
import subprocess
from typing import Iterable, List


def expand_targets(targets: str) -> List[str]:
    if "/" in targets:
        net = ipaddress.ip_network(targets, strict=False)
        return [str(ip) for ip in net.hosts()]
    if "-" in targets:
        start, end = targets.split("-", 1)
        start_ip = ipaddress.ip_address(start.strip())
        end_ip = ipaddress.ip_address(end.strip())
        if end_ip < start_ip:
            raise ValueError("End IP must be >= start IP")
        current = start_ip
        out = []
        while current <= end_ip:
            out.append(str(current))
            current += 1
        return out
    return [targets.strip()]


def ping_host(host: str, timeout: float) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False


def tcp_probe(host: str, timeout: float) -> bool:
    import socket

    for port in (80, 443, 22, 3389):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            continue
    return False


def arp_scan(hosts: Iterable[str], timeout: float) -> List[str]:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except Exception:
        return []

    target_list = list(hosts)
    if not target_list:
        return []

    ip_range = f"{target_list[0].rsplit('.', 1)[0]}.0/24"
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(packet, timeout=timeout, verbose=False)
    live = []
    for _, recv in answered:
        live.append(recv.psrc)
    return live


def discover_hosts(targets: str, methods: List[str], timeout: float = 1.0) -> List[str]:
    hosts = expand_targets(targets)
    discovered = set()

    if "ping" in methods:
        for host in hosts:
            if ping_host(host, timeout):
                discovered.add(host)

    if "tcp" in methods:
        for host in hosts:
            if tcp_probe(host, timeout):
                discovered.add(host)

    if "arp" in methods:
        discovered.update(arp_scan(hosts, timeout))

    if not discovered:
        return hosts
    return sorted(discovered)
