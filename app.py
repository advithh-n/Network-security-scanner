from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
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
DB_PATH = BASE_DIR / "data" / "users.db"
LOCK = threading.Lock()

app = Flask(__name__)
app.secret_key = os.environ.get("NSS_SECRET_KEY", "change-this-secret")

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


def hash_password(password: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return digest.hex()


def create_user_record(username: str, password: str, role: str) -> Dict[str, str]:
    salt = secrets.token_hex(16)
    return {
        "username": username,
        "role": role,
        "salt": salt,
        "password_hash": hash_password(password, salt),
    }


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    with conn:
        conn.execute(
            \"\"\"
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
            \"\"\"
        )
        conn.execute(
            \"\"\"
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                event TEXT NOT NULL,
                user TEXT NOT NULL,
                detail TEXT NOT NULL
            )
            \"\"\"
        )
    conn.close()


def ensure_users() -> None:
    init_db()
    conn = get_db()
    defaults = [
        ("admin", "admin123", "admin"),
        ("analyst", "analyst123", "analyst"),
        ("viewer", "viewer123", "viewer"),
    ]
    with conn:
        for username, password, role in defaults:
            row = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
            if row:
                continue
            record = create_user_record(username, password, role)
            conn.execute(
                "INSERT INTO users (username, role, salt, password_hash) VALUES (?, ?, ?, ?)",
                (record["username"], record["role"], record["salt"], record["password_hash"]),
            )
    conn.close()


def verify_password(password: str, user_record: Dict[str, str]) -> bool:
    salt = user_record.get("salt", "")
    expected = user_record.get("password_hash", "")
    if not salt or not expected:
        return False
    return hash_password(password, salt) == expected


def log_event(event_type: str, detail: str, username: str = "") -> None:
    init_db()
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT INTO audit (time, event, user, detail) VALUES (?, ?, ?, ?)",
            (_now_iso(), event_type, username, detail),
        )
    conn.close()


def fetch_user(username: str) -> Dict[str, str]:
    conn = get_db()
    row = conn.execute("SELECT username, role, salt, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row:
        return {}
    return dict(row)


def list_users() -> List[Dict[str, str]]:
    conn = get_db()
    rows = conn.execute("SELECT username, role FROM users ORDER BY username").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def create_user(username: str, password: str, role: str) -> None:
    record = create_user_record(username, password, role)
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT INTO users (username, role, salt, password_hash) VALUES (?, ?, ?, ?)",
            (record["username"], record["role"], record["salt"], record["password_hash"]),
        )
    conn.close()


def update_password(username: str, password: str) -> None:
    record = create_user_record(username, password, "viewer")
    conn = get_db()
    with conn:
        conn.execute(
            "UPDATE users SET salt = ?, password_hash = ? WHERE username = ?",
            (record["salt"], record["password_hash"], username),
        )
    conn.close()


def delete_user(username: str) -> None:
    conn = get_db()
    with conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.close()


def current_user() -> Dict[str, str]:
    username = session.get("username")
    if not username:
        return {}
    user = fetch_user(username)
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
    log_event("scan_finished", f"id={scan_id} status={status}", params.get("username", ""))


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
        user = fetch_user(username)
        if user and verify_password(password, user):
            session["username"] = username
            log_event("login_success", "user logged in", username)
            return redirect(url_for("index"))
        log_event("login_failed", "invalid credentials", username)
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html", error="")


@app.route("/logout")
def logout() -> Any:
    username = session.get("username", "")
    session.clear()
    if username:
        log_event("logout", "user logged out", username)
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
    username = session.get("username", "")
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

    params["username"] = username
    log_event("scan_started", f"id={scan_id} targets={params['targets']}", username)
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

    log_event("demo_loaded", "demo dataset loaded", session.get("username", ""))
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


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password() -> Any:
    message = ""
    error = ""
    if request.method == "POST":
        current = request.form.get("current_password", "").strip()
        new_pw = request.form.get("new_password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()
        user = fetch_user(session.get("username", ""))
        if not verify_password(current, user):
            error = "Current password is incorrect"
        elif not new_pw or new_pw != confirm:
            error = "New passwords do not match"
        else:
            update_password(user["username"], new_pw)
            log_event("password_change", "user changed password", user["username"])
            message = "Password updated"
    return render_template("change_password.html", message=message, error=error, user=current_user())


@app.route("/admin/users", methods=["GET", "POST"])
@require_role("admin")
def admin_users() -> Any:
    message = request.args.get("message", "")
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()
        if not username or not password:
            error = "Username and password are required"
        elif role not in ROLE_ORDER:
            error = "Invalid role"
        else:
            existing = fetch_user(username)
            if existing:
                error = "User already exists"
            else:
                create_user(username, password, role)
                log_event("user_created", f"created {username} role={role}", session.get("username", ""))
                return redirect(url_for("admin_users", message="User created"))

    user_list = list_users()
    return render_template(
        "admin_users.html",
        users=user_list,
        message=message,
        error=error,
        user=current_user(),
    )


@app.route("/admin/users/<username>/delete", methods=["POST"])
@require_role("admin")
def admin_delete_user(username: str) -> Any:
    current = session.get("username", "")
    if username == current:
        return redirect(url_for("admin_users", message="Cannot delete your own account"))
    user = fetch_user(username)
    if not user:
        abort(404)
    delete_user(username)
    log_event("user_deleted", f"deleted {username}", current)
    return redirect(url_for("admin_users", message="User deleted"))


@app.route("/admin/audit")
@require_role("admin")
def admin_audit() -> Any:
    init_db()
    conn = get_db()
    rows = conn.execute(
        "SELECT time, event, user, detail FROM audit ORDER BY id DESC LIMIT 200"
    ).fetchall()
    conn.close()
    entries = [dict(row) for row in rows]
    return render_template("admin_audit.html", entries=entries, user=current_user())


@app.route("/admin/audit.csv")
@require_role("admin")
def admin_audit_csv() -> Any:
    init_db()
    conn = get_db()
    rows = conn.execute(
        "SELECT time, event, user, detail FROM audit ORDER BY id DESC"
    ).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["time", "event", "user", "detail"])
    for row in rows:
        writer.writerow([row["time"], row["event"], row["user"], row["detail"]])
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="audit_log.csv",
    )


@app.route("/admin/users/reset", methods=["POST"])
@require_role("admin")
def admin_reset_password() -> Any:
    username = request.form.get("reset_username", "").strip()
    new_pw = request.form.get("reset_password", "").strip()
    if not username or not new_pw:
        return redirect(url_for("admin_users", message="Username and password required"))
    user = fetch_user(username)
    if not user:
        return redirect(url_for("admin_users", message="User not found"))
    update_password(username, new_pw)
    log_event("password_reset", f"reset password for {username}", session.get("username", ""))
    return redirect(url_for("admin_users", message="Password reset"))


if __name__ == "__main__":
    _ensure_dirs()
    ensure_users()
    app.run(host="127.0.0.1", port=5000, debug=True)
