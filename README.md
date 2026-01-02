# Network Security Scanner

Educational, multi-threaded network scanner for host discovery, port enumeration, service detection, and basic CVE matching.

Use this only on systems you own or have explicit permission to test.

## Features
- Host discovery: ping sweep, TCP connect sweep, optional ARP scan (scapy)
- Port scanning: TCP/UDP enumeration with basic service detection
- Vulnerability detection: offline CVE matching from local JSON rules
- Reporting: HTML, JSON, and PDF output with risk ratings
- Timing profiles: paranoid/slow/normal/fast

## Quick start
1) Create a virtual environment and install dependencies (optional).
2) Run a scan:

```bash
python -m scanner --targets 192.168.1.0/24 --ports 22,80,443 --timing normal
```

Outputs go to `data/scan_results` and HTML to `reports` by default.
PDF output uses `reportlab` and is skipped if not installed.

## Notes
- ARP scanning requires scapy and admin privileges; otherwise it is skipped.
- UDP scans are best-effort and may report `open|filtered` when no response is received.
- CVE checks are local rules; update `data/cve_database.json` to expand coverage.

## Repository layout
- `scanner/` core modules
- `data/` signatures and CVE rules
- `reports/` generated reports
- `tests/` placeholder for unit tests

## Web UI
Run the webapp locally:

```bash
python app.py
```

Then open `http://127.0.0.1:5000`.
The UI lets you launch scans, view results, and download JSON/HTML/PDF reports.
