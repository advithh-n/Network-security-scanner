"""Port scanning and service detection."""
from __future__ import annotations

import json
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List


def load_service_signatures() -> Dict[str, str]:
    base = Path(__file__).resolve().parents[1]
    sig_path = base / "data" / "service_signatures.json"
    if not sig_path.exists():
        return {}
    with sig_path.open("r", encoding="ascii") as f:
        return json.load(f)


def probe_banner(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in (80, 8080, 8000):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(512)
            return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def infer_service_from_banner(banner: str) -> str:
    b = banner.lower()
    if "ssh" in b:
        return "ssh"
    if "smtp" in b or "esmtp" in b:
        return "smtp"
    if "ftp" in b:
        return "ftp"
    if "http" in b:
        return "http"
    if "mysql" in b:
        return "mysql"
    if "postgres" in b:
        return "postgres"
    if "redis" in b:
        return "redis"
    if "nginx" in b:
        return "http"
    if "apache" in b:
        return "http"
    if "microsoft-iis" in b:
        return "http"
    return "unknown"


def extract_product_version(banner: str) -> tuple[str, str]:
    patterns = [
        r"(openssh)[/_-]([0-9][^\s;]*)",
        r"(apache)[/_-]([0-9][^\s;]*)",
        r"(nginx)[/_-]([0-9][^\s;]*)",
        r"(openssl)[/_-]([0-9][^\s;]*)",
        r"(microsoft-iis)[/_-]([0-9][^\s;]*)",
        r"(mysql)[/_-]([0-9][^\s;]*)",
        r"(postgresql)[/_-]([0-9][^\s;]*)",
        r"(redis)[/_-]([0-9][^\s;]*)",
    ]
    for pat in patterns:
        match = re.search(pat, banner, re.IGNORECASE)
        if match:
            return match.group(1).lower(), match.group(2)
    return "", ""


def scan_tcp_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_udp_port(host: str, port: int, timeout: float) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (host, port))
        try:
            data, _ = sock.recvfrom(1024)
            if data:
                return "open"
        except socket.timeout:
            return "open|filtered"
        finally:
            sock.close()
    except Exception:
        return "closed"
    return "closed"


def scan_host_ports(
    host: str,
    tcp_ports: List[int],
    udp_ports: List[int],
    threads: int,
    timeout: float,
    delay: float,
) -> Dict[str, object]:
    signatures = load_service_signatures()

    result = {
        "tcp_open": {},
        "udp_open": {},
    }

    lock = threading.Lock()

    def tcp_worker(port: int) -> None:
        if delay:
            time.sleep(delay)
        if scan_tcp_port(host, port, timeout):
            banner = probe_banner(host, port, timeout)
            service = signatures.get(str(port), "unknown")
            if banner:
                inferred = infer_service_from_banner(banner)
                if inferred != "unknown":
                    service = inferred
            product, version = extract_product_version(banner)
            with lock:
                result["tcp_open"][port] = {
                    "service": service,
                    "banner": banner,
                    "product": product,
                    "version": version,
                }

    def udp_worker(port: int) -> None:
        if delay:
            time.sleep(delay)
        state = scan_udp_port(host, port, timeout)
        if state in ("open", "open|filtered"):
            with lock:
                result["udp_open"][port] = {
                    "state": state,
                }

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(tcp_worker, p) for p in tcp_ports]
        futures += [executor.submit(udp_worker, p) for p in udp_ports]
        for _ in as_completed(futures):
            pass

    return result
