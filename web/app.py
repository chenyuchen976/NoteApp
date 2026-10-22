"""NotesApp - a small grades application.

Deliberately insecure teaching app for the EPITA Computer Security course.
Do not deploy this anywhere real.
"""
import os
import csv
import io
import json
import hmac
import time
import base64
import hashlib
import subprocess

import psycopg2
import psycopg2.extras
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, Response, jsonify, abort,
)

# --- Configuration ------------------------------------------------------------
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "notesapp")
DB_USER = os.environ.get("DB_USER", "notesapp")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "notesapp_pg_pw_2024")
JWT_SECRET = os.environ.get("JWT_SECRET", "s3cr3t")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-session-key")

app = Flask(__name__)
app.secret_key = SECRET_KEY


# --- HMAC Helper --------------------------------------------------------------
def calculate_csv_hmac(csv_content_str: str) -> str:
    """Computes the HMAC-SHA256 digest for the given CSV string content using SECRET_KEY."""
    key_bytes = SECRET_KEY.encode("utf-8")
    content_bytes = csv_content_str.encode("utf-8")
    hmac_obj = hmac.new(key_bytes, content_bytes, hashlib.sha256)
    return hmac_obj.hexdigest()


LOG_FILE = os.environ.get("NOTESAPP_LOG", "/var/log/notesapp/app.log")


def log(msg):
    """Very small access log. No rotation, no policy (see flaw #14)."""
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


# --- Database -----------------------------------------------------------------
def get_db():
    conn = psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    conn.autocommit = True
    return conn


# --- Minimal JWT (deliberately weak) ------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def make_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def verify_jwt(token: str):
    """Decode a JWT. Accepts alg:none (no signature) and HS256 with a short key."""
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
    except Exception:
        return None

    alg = header.get("alg", "").lower()
    if alg == "none":
        return payload
    if alg == "hs256":
        signing_input = f"{h_b64}.{p_b64}".encode()
        expected = _b64url(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest())
        if hmac.compare_digest(expected, sig_b64):
            return payload
        return None
    return None


def current_identity():
    """Return the acting identity from a Bearer JWT if present, else the session."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = verify_jwt(auth[7:].strip())
        if payload:
            return payload
    if "user_id" in session:
        return {"user_id": session["user_id"], "username": session.get("username"),
                "role": session.get("role")}
    return None


# --- Auth helpers -------------------------------------------------------------
def login_required(role=None):
    if "user_id" not in session:
        return False
    if role and session.get("role") != role:
        return False
    return True


# --- Routes -------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        role = session.get("role")
        if role == "student":
            return redirect(url_for("dashboard"))
        if role == "teacher":
            return redirect(url_for("teacher"))
        if role == "admin":
            return redirect(url_for("admin"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        query = (
            "SELECT id, username, role FROM users "
            "WHERE username = '" + username + "' AND password = '" + password + "'"
        )
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
        except Exception as e:
            error = f"Query error: {e}"
            row = None
        conn.close()
        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            session["token"] = make_jwt({
                "user_id": row["id"], "username": row["username"], "role": row["role"],
            })
            log(f"login success user={row['username']} role={row['role']}")
            return redirect(url_for("index"))
        if not error:
            error = "Invalid credentials."
        log(f"login failure username={username!r}")
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, c.name AS class_name "
        "FROM notes n JOIN classes c ON c.id = n.class_id "
        "WHERE n.student_id = %s ORDER BY c.name",
        (session["user_id"],),
    )
    notes = cur.fetchall()
    conn.close()
    return render_template("dashboard.html", notes=notes, token=session.get("token"))


@app.route("/api/notes/<int:note_id>")
def api_notes(note_id):
    ident = current_identity()
    if not ident:
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT n.id, n.student_id, n.class_id, n.grade, n.comment, "
        "u.username AS student, c.name AS class_name "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id WHERE n.id = %s",
        (note_id,),
    )
    note = cur.fetchone()
    conn.close()
    if not note:
        return jsonify({"error": "not found"}), 404
    note["grade"] = float(note["grade"]) if note["grade"] is not None else None
    return jsonify(note)


@app.route("/teacher")
def teacher():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY name")
    classes = cur.fetchall()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, n.student_id, n.class_id, "
        "u.username AS student, c.name AS class_name "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
    )
    notes = cur.fetchall()
    cur.execute("SELECT id, username FROM users WHERE role = 'student' ORDER BY username")
    students = cur.fetchall()
    conn.close()
    return render_template("teacher.html", classes=classes, notes=notes, students=students)


@app.route("/grades", methods=["POST"])
def grades():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    note_id = request.form.get("note_id", "").strip()
    student_id = request.form.get("student_id")
    class_id = request.form.get("class_id")
    grade = request.form.get("grade")
    comment = request.form.get("comment", "")
    conn = get_db()
    cur = conn.cursor()
    if note_id:
        cur.execute(
            "UPDATE notes SET grade = %s, comment = %s WHERE id = %s",
            (grade, comment, note_id),
        )
    else:
        cur.execute(
            "INSERT INTO notes (student_id, class_id, grade, comment) "
            "VALUES (%s, %s, %s, %s)",
            (student_id, class_id, grade, comment),
        )
    conn.close()
    log(f"grade write by {session.get('username')} note_id={note_id or 'new'}")
    return redirect(url_for("teacher"))


@app.route("/export.csv")
def export_csv():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    
    class_id = request.args.get("class_id")
    conn = get_db()
    cur = conn.cursor()
    if class_id:
        cur.execute(
            "SELECT u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id WHERE n.class_id = %s "
            "ORDER BY u.username",
            (class_id,),
        )
    else:
        cur.execute(
            "SELECT u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
        )
    rows = cur.fetchall()
    conn.close()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["student", "class", "grade", "comment"])
    for r in rows:
        writer.writerow([r["student"], r["class"], r["grade"], r["comment"]])
    
    # 1. Retrieve the plain CSV content
    raw_csv = buf.getvalue()
    
    # 2. Generate HMAC signature for the plain CSV content
    mac = calculate_csv_hmac(raw_csv)
    
    # 3. Append the HMAC comment line at the end of the file
    final_csv = raw_csv + f"# HMAC: {mac}\n"
    
    return Response(
        final_csv,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=grades.csv"},
    )


@app.route("/verify_csv", methods=["POST"])
def verify_csv():
    if not login_required("teacher"):
        return jsonify({"status": "FAILED", "message": "Unauthorized"}), 401

    file = request.files.get("file")
    if not file:
        return jsonify({"status": "FAILED", "message": "No file provided"}), 400

    content = file.read().decode('utf-8', errors='ignore')
    lines = content.splitlines(keepends=True)

    hmac_line = None
    data_lines = []
    
    # Separate CSV data content from the HMAC header line
    for line in lines:
        if line.startswith("# HMAC:"):
            hmac_line = line.strip()
        else:
            data_lines.append(line)

    if not hmac_line:
        return jsonify({"status": "FAILED", "message": "No HMAC header found in file"}), 400

    # Extract original HMAC and reconstruct the original CSV string
    file_hmac = hmac_line.replace("# HMAC:", "").strip()
    reconstructed_csv = "".join(data_lines)
    computed_hmac = calculate_csv_hmac(reconstructed_csv)

    # Compare signatures in constant time
    if hmac.compare_digest(file_hmac, computed_hmac):
        return jsonify({"status": "SUCCESS", "message": "HMAC Verification Passed! File is intact."})
    else:
        return jsonify({"status": "FAILED", "message": "CHECK FAILED: File has been tampered with!"}), 400


@app.route("/admin")
def admin():
    if not login_required("admin"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    users = cur.fetchall()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    classes = cur.fetchall()
    conn.close()
    return render_template("admin.html", users=users, classes=classes,
                           ping_result=request.args.get("ping_result"))


@app.route("/admin/ping", methods=["POST"])
def admin_ping():
    if not login_required("admin"):
        return redirect(url_for("login"))
    host = request.form.get("host", "")
    cmd = "ping -c 1 " + host
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    log(f"admin ping host={host!r}")
    return render_template("admin.html", users=_all_users(), classes=_all_classes(),
                           ping_result=output)


def _all_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


def _all_classes():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


@app.route("/admin/users", methods=["POST"])
def admin_users():
    if not login_required("admin"):
        return redirect(url_for("login"))
    action = request.form.get("action")
    conn = get_db()
    cur = conn.cursor()
    if action == "create":
        cur.execute(
            "INSERT INTO users (username, password, role, teacher_id) "
            "VALUES (%s, %s, %s, %s)",
            (request.form.get("username"), request.form.get("password"),
             request.form.get("role", "student"), None),
        )
    elif action == "delete":
        cur.execute("DELETE FROM users WHERE id = %s", (request.form.get("user_id"),))
    conn.close()
    return redirect(url_for("admin"))


@app.route("/healthz")
def healthz():
    try:
        conn = get_db()
        conn.close()
        return "ok", 200
    except Exception as e:
        return f"db error: {e}", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)