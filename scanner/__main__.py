"""CLI entrypoint for the scanner."""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from .host_discovery import discover_hosts
from .port_scanner import scan_host_ports
from .vulnerability_detector import detect_vulnerabilities
from .report_generator import generate_html_report, write_json_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Network Security Scanner (educational)")
    parser.add_argument("--targets", required=True, help="CIDR or IP range, e.g. 192.168.1.0/24 or 192.168.1.1-192.168.1.50")
    parser.add_argument("--ports", default="22,80,443,3389", help="Comma-separated TCP ports")
    parser.add_argument("--udp-ports", default="", help="Comma-separated UDP ports (optional)")
    parser.add_argument("--timing", default="normal", choices=["paranoid", "slow", "normal", "fast"], help="Timing profile")
    parser.add_argument("--discovery", default="ping,tcp", help="Discovery methods: ping,tcp,arp")
    parser.add_argument("--threads", type=int, default=200, help="Worker threads for port scans")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("--no-vuln", action="store_true", help="Disable vulnerability detection")
    parser.add_argument("--out-json", default="", help="Path to write JSON report")
    parser.add_argument("--out-html", default="", help="Path to write HTML report")
    parser.add_argument("--out-pdf", default="", help="Path to write PDF report (requires reportlab)")
    return parser.parse_args()


def timing_profile(timing: str) -> tuple[int, float]:
    if timing == "paranoid":
        return 50, 0.2
    if timing == "slow":
        return 100, 0.1
    if timing == "fast":
        return 400, 0.0
    return 200, 0.05


def main() -> None:
    args = parse_args()
    threads, delay = timing_profile(args.timing)
    if args.threads:
        threads = args.threads

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    udp_ports = [int(p) for p in args.udp_ports.split(",") if p.strip()]

    discovery_methods = [m.strip() for m in args.discovery.split(",") if m.strip()]

    targets = discover_hosts(args.targets, discovery_methods, timeout=args.timeout)

    results = {
        "scan_started": datetime.utcnow().isoformat() + "Z",
        "targets": args.targets,
        "discovered_hosts": [],
        "host_results": {},
    }

    for host in targets:
        host_result = scan_host_ports(
            host,
            tcp_ports=ports,
            udp_ports=udp_ports,
            threads=threads,
            timeout=args.timeout,
            delay=delay,
        )
        results["discovered_hosts"].append(host)
        results["host_results"][host] = host_result

        if not args.no_vuln:
            vulns = detect_vulnerabilities(host_result)
            results["host_results"][host]["vulnerabilities"] = vulns

    results["scan_finished"] = datetime.utcnow().isoformat() + "Z"

    base = Path(__file__).resolve().parents[1]
    scan_dir = base / "data" / "scan_results"
    scan_dir.mkdir(parents=True, exist_ok=True)

    json_out = args.out_json or str(scan_dir / f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    html_out = args.out_html or str(base / "reports" / f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html")
    pdf_out = args.out_pdf or str(base / "reports" / f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf")

    write_json_report(results, json_out)
    generate_html_report(results, html_out)
    try:
        from .report_generator import generate_pdf_report
        generate_pdf_report(results, pdf_out)
    except Exception as exc:
        print(f"PDF report skipped: {exc}")

    print(f"JSON report: {json_out}")
    print(f"HTML report: {html_out}")
    print(f"PDF report: {pdf_out}")


if __name__ == "__main__":
    main()
