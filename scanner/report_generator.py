"""Report generation utilities."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict


def risk_score(vuln_count: int) -> str:
    if vuln_count >= 5:
        return "High"
    if vuln_count >= 2:
        return "Medium"
    if vuln_count >= 1:
        return "Low"
    return "Informational"


def write_json_report(data: Dict[str, object], out_path: str) -> None:
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="ascii") as f:
        json.dump(data, f, indent=2)


def generate_html_report(data: Dict[str, object], out_path: str) -> None:
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    rows = []
    host_results = data.get("host_results", {})
    for host, info in host_results.items():
        tcp_open = info.get("tcp_open", {})
        udp_open = info.get("udp_open", {})
        vulns = info.get("vulnerabilities", [])
        risk = risk_score(len(vulns))

        tcp_lines = "<br>".join([f"{p} ({d.get('service')})" for p, d in tcp_open.items()]) or "-"
        udp_lines = "<br>".join([f"{p} ({d.get('state')})" for p, d in udp_open.items()]) or "-"
        vuln_lines = "<br>".join([f"{v.get('cve')}: {v.get('title')}" for v in vulns]) or "-"

        rows.append(
            f"<tr><td>{host}</td><td>{tcp_lines}</td><td>{udp_lines}</td><td>{risk}</td><td>{vuln_lines}</td></tr>"
        )

    html = f"""
<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>Network Security Scan Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; }}
header {{ margin-bottom: 16px; }}
section {{ margin-top: 16px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
th {{ background: #f2f2f2; }}
</style>
</head>
<body>
<header>
  <h1>Network Security Scan Report</h1>
  <div>Generated: {datetime.utcnow().isoformat()}Z</div>
  <div>Targets: {data.get('targets', '')}</div>
</header>
<section>
  <table>
    <thead>
      <tr>
        <th>Host</th>
        <th>TCP Open Ports</th>
        <th>UDP Open Ports</th>
        <th>Risk</th>
        <th>Vulnerabilities</th>
      </tr>
    </thead>
    <tbody>
      {"".join(rows)}
    </tbody>
  </table>
</section>
</body>
</html>
"""

    with open(out_path, "w", encoding="ascii") as f:
        f.write(html)


def generate_pdf_report(data: Dict[str, object], out_path: str) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except Exception as exc:
        raise RuntimeError("reportlab is not installed") from exc

    doc = SimpleDocTemplate(out_path, pagesize=letter)
    styles = getSampleStyleSheet()

    elements = []
    elements.append(Paragraph("Network Security Scan Report", styles["Title"]))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles["Normal"]))
    elements.append(Paragraph(f"Targets: {data.get('targets', '')}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    table_data = [["Host", "TCP Open Ports", "UDP Open Ports", "Risk", "Vulnerabilities"]]
    host_results = data.get("host_results", {})
    for host, info in host_results.items():
        tcp_open = info.get("tcp_open", {})
        udp_open = info.get("udp_open", {})
        vulns = info.get("vulnerabilities", [])
        risk = risk_score(len(vulns))

        tcp_lines = ", ".join([f"{p} ({d.get('service')})" for p, d in tcp_open.items()]) or "-"
        udp_lines = ", ".join([f"{p} ({d.get('state')})" for p, d in udp_open.items()]) or "-"
        vuln_lines = "; ".join([f"{v.get('cve')}: {v.get('title')}" for v in vulns]) or "-"

        table_data.append([host, tcp_lines, udp_lines, risk, vuln_lines])

    table = Table(table_data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    elements.append(table)
    doc.build(elements)
