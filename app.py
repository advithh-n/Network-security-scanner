from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for

BASE_DIR = Path(__file__).resolve().parent
SCAN_DIR = BASE_DIR / "data" / "scan_results"
REPORT_DIR = BASE_DIR / "reports"
INDEX_PATH = SCAN_DIR / "index.json"
DEMO_JSON = BASE_DIR / "data" / "demo_scan.json"
DEMO_HTML = BASE_DIR / "reports" / "sample_reports" / "demo_report.html"
LOCK = threading.Lock()

app = Flask(__name__)
app.secret_key = os.environ.get("NSS_SECRET_KEY", "change-this-secret")

USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "analyst": {"password": "analyst123", "role": "analyst"},
    "viewer": {"password": "viewer123", "role": "viewer"},
}

ROLE_ORDER = {"viewer": 1, "analyst": 2, "admin": 3}


def _ensure_dirs() -> None:
    SCAN_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def load_index() -> List[Dict[str, Any]]:
    if not INDEX_PATH.exists():
        return []
    try:
        return json.loads(INDEX_PATH.read_text(encoding="ascii"))
    except Exception:
        return []


def save_index(items: List[Dict[str, Any]]) -> None:
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    INDEX_PATH.write_text(json.dumps(items, indent=2), encoding="ascii")


def update_record(scan_id: str, updates: Dict[str, Any]) -> None:
    with LOCK:
        items = load_index()
        for item in items:
            if item.get("id") == scan_id:
                item.update(updates)
                break
        save_index(items)


def clean_ports(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    value = re.sub(r"[^0-9,]", "", value)
    value = re.sub(r",+", ",", value).strip(",")
    return value


def clean_discovery(value: str) -> str:
    allowed = {"ping", "tcp", "arp"}
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return ",".join([p for p in parts if p in allowed]) or "ping,tcp"


def current_user() -> Dict[str, str]:
    username = session.get("username")
    if not username:
        return {}
    user = USERS.get(username, {})
    return {"username": username, "role": user.get("role", "")}


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def require_role(min_role: str):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if ROLE_ORDER.get(user.get("role", ""), 0) < ROLE_ORDER.get(min_role, 0):
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def build_scan_command(params: Dict[str, Any], json_out: Path, html_out: Path, pdf_out: Path) -> List[str]:
    cmd = [
        sys.executable,
        "-m",
        "scanner",
        "--targets",
        params["targets"],
        "--ports",
        params["ports"],
        "--udp-ports",
        params["udp_ports"],
        "--timing",
        params["timing"],
        "--discovery",
        params["discovery"],
        "--threads",
        str(params["threads"]),
        "--timeout",
        str(params["timeout"]),
        "--out-json",
        str(json_out),
        "--out-html",
        str(html_out),
        "--out-pdf",
        str(pdf_out),
    ]
    if params.get("no_vuln"):
        cmd.append("--no-vuln")
    return cmd


def run_scan(scan_id: str, params: Dict[str, Any]) -> None:
    _ensure_dirs()
    json_out = SCAN_DIR / f"scan_{scan_id}.json"
    html_out = REPORT_DIR / f"report_{scan_id}.html"
    pdf_out = REPORT_DIR / f"report_{scan_id}.pdf"
    log_out = SCAN_DIR / f"scan_{scan_id}.log"

    update_record(
        scan_id,
        {
            "status": "running",
            "started_at": _now_iso(),
            "json": str(json_out),
            "html": str(html_out),
            "pdf": str(pdf_out),
            "log": str(log_out),
        },
    )

    cmd = build_scan_command(params, json_out, html_out, pdf_out)
    try:
        result = subprocess.run(cmd, cwd=str(BASE_DIR), capture_output=True, text=True)
        log_out.write_text(result.stdout + "\n" + result.stderr, encoding="ascii", errors="ignore")
        status = "finished" if result.returncode == 0 else "failed"
    except Exception as exc:
        log_out.write_text(str(exc), encoding="ascii", errors="ignore")
        status = "failed"

    update_record(scan_id, {"status": status, "finished_at": _now_iso()})


@app.route("/")
@login_required
def index() -> str:
    items = load_index()
    items = sorted(items, key=lambda x: x.get("created_at", ""), reverse=True)

    latest_scan = items[0] if items else None
    latest_summary = None
    if latest_scan and Path(latest_scan.get("json", "")).exists():
        try:
            data = json.loads(Path(latest_scan["json"]).read_text(encoding="ascii"))
            host_results = data.get("host_results", {})
            total_hosts = len(host_results)
            total_vulns = sum(len(v.get("vulnerabilities", [])) for v in host_results.values())
            latest_summary = {
                "hosts": total_hosts,
                "vulns": total_vulns,
                "targets": data.get("targets", ""),
            }
        except Exception:
            latest_summary = None

    return render_template("index.html", items=items, latest_summary=latest_summary, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = USERS.get(username)
        if user and user.get("password") == password:
            session["username"] = username
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html", error="")


@app.route("/logout")
def logout() -> Any:
    session.clear()
    return redirect(url_for("login"))


@app.route("/scan", methods=["POST"])
@require_role("analyst")
def start_scan() -> Any:
    targets = request.form.get("targets", "").strip()
    if not targets:
        abort(400, "targets required")

    params = {
        "targets": targets,
        "ports": clean_ports(request.form.get("ports", "22,80,443,3389")),
        "udp_ports": clean_ports(request.form.get("udp_ports", "")),
        "timing": request.form.get("timing", "normal"),
        "discovery": clean_discovery(request.form.get("discovery", "ping,tcp")),
        "threads": int(request.form.get("threads", "200")),
        "timeout": float(request.form.get("timeout", "1.0")),
        "no_vuln": request.form.get("no_vuln") == "on",
    }

    scan_id = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:6]
    record = {
        "id": scan_id,
        "created_at": _now_iso(),
        "status": "queued",
        "targets": params["targets"],
        "ports": params["ports"],
        "udp_ports": params["udp_ports"],
        "timing": params["timing"],
        "discovery": params["discovery"],
    }

    with LOCK:
        items = load_index()
        items.append(record)
        save_index(items)

    thread = threading.Thread(target=run_scan, args=(scan_id, params), daemon=True)
    thread.start()

    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/demo")
@login_required
def load_demo() -> Any:
    if not DEMO_JSON.exists():
        abort(404, "demo scan not found")

    demo_id = "demo"
    record = {
        "id": demo_id,
        "created_at": _now_iso(),
        "status": "finished",
        "targets": "demo (sample data)",
        "ports": "21,22,80,443,445,3389",
        "udp_ports": "53,161",
        "timing": "normal",
        "discovery": "ping,tcp",
        "json": str(DEMO_JSON),
        "html": str(DEMO_HTML) if DEMO_HTML.exists() else "",
        "pdf": "",
        "demo": True,
    }

    with LOCK:
        items = load_index()
        items = [item for item in items if item.get("id") != demo_id]
        items.insert(0, record)
        save_index(items)

    return redirect(url_for("scan_detail", scan_id=demo_id))


@app.route("/scan/<scan_id>")
@login_required
def scan_detail(scan_id: str) -> str:
    items = load_index()
    record = next((i for i in items if i.get("id") == scan_id), None)
    if not record:
        abort(404)

    scan_data = None
    json_path = record.get("json")
    if json_path and Path(json_path).exists():
        try:
            scan_data = json.loads(Path(json_path).read_text(encoding="ascii"))
        except Exception:
            scan_data = None

    return render_template("scan_detail.html", record=record, scan_data=scan_data, user=current_user())


@app.route("/download/<scan_id>/<kind>")
@login_required
def download(scan_id: str, kind: str) -> Any:
    items = load_index()
    record = next((i for i in items if i.get("id") == scan_id), None)
    if not record:
        abort(404)

    path = record.get(kind)
    if not path:
        abort(404)
    file_path = Path(path)
    if not file_path.exists():
        abort(404)

    return send_file(str(file_path), as_attachment=True)


@app.route("/api/scan/<scan_id>")
@login_required
def scan_status(scan_id: str) -> Any:
    items = load_index()
    record = next((i for i in items if i.get("id") == scan_id), None)
    if not record:
        abort(404)
    return jsonify(record)


if __name__ == "__main__":
    _ensure_dirs()
    app.run(host="127.0.0.1", port=5000, debug=True)
