"""NotesApp - a small grades application.
Deliberately insecure teaching app for the EPITA Computer Security course.
Do not deploy this anywhere real.
"""

from export_integrity import verify_export
import os
import csv
import io
import json
import hmac
import time
import base64
import hashlib
import subprocess
from crypto_utils import encrypt_comment, decrypt_comment, decrypt_rows
from export_integrity import sign_export
from passwords import ph, verify_password
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
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE") == "1"

LOG_FILE = os.environ.get("NOTESAPP_LOG", "/var/log/notesapp/app.log")

def log(msg):
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
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = verify_jwt(auth[7:].strip())
        if payload:
            return payload
    if "user_id" in session:
        return {"user_id": session["user_id"], "username": session.get("username"),
                "role": session.get("role")}
    return None

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
            "SELECT id, username, role, password FROM users "
            "WHERE username = '" + username + "'"
        )
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
        except Exception as e:
            error = f"Query error: {e}"
            row = None
        authenticated = False
        try:
            if row:
                authenticated, replacement = verify_password(row["password"], password)
                if authenticated and replacement:
                    cur.execute(
                        "UPDATE users SET password = %s WHERE id = %s AND password = %s",
                        (replacement, row["id"], row["password"]),
                    )
                    authenticated = cur.rowcount == 1
                    if authenticated:
                        log(f"password upgraded user={row['username']}")
        finally:
            conn.close()
        if authenticated:
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
    notes = decrypt_rows(cur.fetchall())
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
    note["comment"] = decrypt_comment(note["comment"], note["id"])
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
    notes = decrypt_rows(cur.fetchall())
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
    if note_id:
        try:
            note_id = int(note_id)
        except ValueError:
            abort(400)
    conn = get_db()
    conn.autocommit = False
    try:
        with conn:
            with conn.cursor() as cur:
                if note_id:
                    cur.execute(
                        "UPDATE notes SET grade = %s, comment = %s WHERE id = %s",
                        (grade, encrypt_comment(comment, note_id), note_id),
                    )
                else:
                    cur.execute(
                        "INSERT INTO notes (student_id, class_id, grade) "
                        "VALUES (%s, %s, %s) RETURNING id",
                        (student_id, class_id, grade),
                    )
                    note_id = cur.fetchone()["id"]
                    cur.execute("UPDATE notes SET comment = %s WHERE id = %s",
                                (encrypt_comment(comment, note_id), note_id))
    finally:
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
            "SELECT n.id, u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id WHERE n.class_id = %s "
            "ORDER BY u.username",
            (class_id,),
        )
    else:
        cur.execute(
            "SELECT n.id, u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
        )
    rows = decrypt_rows(cur.fetchall())
    conn.close()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["student", "class", "grade", "comment"])
    for r in rows:
        writer.writerow([r["student"], r["class"], r["grade"], r["comment"]])
    return Response(
        sign_export(buf.getvalue().encode("utf-8")), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=grades.csv"},
    )

@app.route("/verify_csv", methods=["POST"])
def verify_csv():
    if not login_required("teacher"):
        return jsonify({"message": "Unauthorized"}), 401
    file = request.files.get("file")
    if not file:
        return jsonify({"message": "No file uploaded"}), 400
    try:
        content = file.read()
        is_valid = verify_export(content)
        if is_valid:
            return jsonify({"message": "HMAC verification passed! File is authentic and unmodified."}), 200
        else:
            return jsonify({"message": "HMAC verification failed! File has been tampered with or is invalid."}), 400
    except Exception as e:
        return jsonify({"message": f"Error verifying file: {str(e)}"}), 500

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
            (request.form.get("username"), ph.hash(request.form.get("password", "")),
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