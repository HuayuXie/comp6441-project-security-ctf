import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import time
from markupsafe import escape
from flask import Flask, make_response, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("CTF_SECRET_KEY", "local-ctf-demo-secret-key")
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"
FILES_DIR = BASE_DIR / "files"

FLAGS = {
    "cookie": "FLAG{client_side_role_is_not_auth}",
    "xss": "FLAG{xss_needs_output_encoding}",
    "path": "FLAG{path_traversal_hidden_file_found}",
    "sqli": "FLAG{sql_queries_need_parameters}",
    "idor": "FLAG{object_ids_are_not_authorisation}",
    "reset": "FLAG{predictable_reset_tokens_enable_takeover}",
}

VULNERABLE_RESET_SUFFIX = "2026"
SECURE_RESET_TOKEN_TTL_SECONDS = 600


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER)")
    cur.execute("INSERT INTO users (username, password, is_admin) VALUES ('student', 'password123', 0)")
    cur.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'not-the-real-password', 1)")
    cur.execute("DROP TABLE IF EXISTS documents")
    cur.execute("CREATE TABLE documents (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, content TEXT)")
    cur.execute(
        "INSERT INTO documents (id, owner, title, content) VALUES (?, ?, ?, ?)",
        (1001, "student", "Student Notes", "My first local CTF note."),
    )
    cur.execute(
        "INSERT INTO documents (id, owner, title, content) VALUES (?, ?, ?, ?)",
        (1002, "admin", "Administrator Incident Note", f"Restricted record. {FLAGS['idor']}"),
    )
    cur.execute("DROP TABLE IF EXISTS reset_tokens")
    cur.execute(
        """
        CREATE TABLE reset_tokens (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.commit()
    conn.close()


def get_completed_challenges():
    return sorted(set(session.get("completed_challenges", [])))


def mark_challenge_completed(challenge_id):
    completed = set(get_completed_challenges())
    completed.add(challenge_id)
    session["completed_challenges"] = sorted(completed)


def locked_defence_response(challenge_id):
    return render_template("defence_locked.html", challenge_id=challenge_id), 403


def contains_xss_payload(value):
    lowered = value.lower()
    script_element = "<script" in lowered and "</script>" in lowered
    event_handler = "<" in lowered and "onerror" in lowered and "=" in lowered
    return script_element or event_handler


def current_username():
    session.setdefault("username", "student")
    return session["username"]


def hash_reset_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@app.route("/")
def index():
    return render_template("index.html", completed=get_completed_challenges())


@app.route("/defence")
def defence():
    return render_template("defence.html", completed=get_completed_challenges())


@app.route("/progress/reset", methods=["POST"])
def reset_progress():
    session.pop("completed_challenges", None)
    return redirect(url_for("index"))


@app.route("/challenge/1")
def challenge1():
    role = request.cookies.get("role", "user")
    if role == "admin":
        mark_challenge_completed(1)
    resp = make_response(render_template("challenge1.html", role=role, flag=FLAGS["cookie"] if role == "admin" else None))
    if "role" not in request.cookies:
        resp.set_cookie("role", "user")
    return resp


@app.route("/challenge/1/reset")
def reset_challenge1():
    resp = make_response(redirect(url_for("challenge1")))
    resp.set_cookie("role", "user")
    return resp


@app.route("/secure/challenge/1")
def secure_challenge1():
    if 1 not in get_completed_challenges():
        return locked_defence_response(1)

    username = current_username()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, is_admin FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()

    role = "admin" if user and user[1] else "user"
    return render_template(
        "secure_example.html",
        title="Secure Cookie Role Design",
        message="The secure version uses a signed session identity and retrieves the role from the backend database.",
        username=user[0] if user else "unknown",
        role=role,
    )


@app.route("/challenge/2")
def challenge2():
    query = request.args.get("q", "")
    show_flag = contains_xss_payload(query)
    if show_flag:
        mark_challenge_completed(2)
    return render_template("challenge2.html", query=query, show_flag=show_flag, flag=FLAGS["xss"])


@app.route("/secure/challenge/2")
def secure_challenge2():
    if 2 not in get_completed_challenges():
        return locked_defence_response(2)

    query = request.args.get("q", "")
    response = make_response(render_template("secure_xss.html", query=query, escaped_query=escape(query)))
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'"
    )
    return response


@app.route("/challenge/3")
def challenge3():
    filename = request.args.get("file", "welcome.txt")
    content = None
    error = None
    try:
        # Vulnerable on purpose for this challenge.
        path = FILES_DIR / filename
        content = path.read_text(errors="replace")
        if FLAGS["path"] in content:
            mark_challenge_completed(3)
    except Exception as exc:
        error = str(exc)
    return render_template("challenge3.html", filename=filename, content=content, error=error)


@app.route("/secure/challenge/3")
def secure_challenge3():
    if 3 not in get_completed_challenges():
        return locked_defence_response(3)

    filename = request.args.get("file", "welcome.txt")
    allowed_files = {"welcome.txt"}
    if filename not in allowed_files:
        return render_template("secure_file.html", filename=filename, content=None, error="Blocked: filename is not in the allowlist.")
    content = (FILES_DIR / filename).read_text(errors="replace")
    return render_template("secure_file.html", filename=filename, content=content, error=None)


@app.route("/challenge/4", methods=["GET", "POST"])
def challenge4():
    message = None
    debug_query = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Vulnerable on purpose for this challenge.
        debug_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        try:
            cur.execute(debug_query)
            user = cur.fetchone()
            if user:
                normal_login = username == user[1] and password == user[2]
                if normal_login:
                    message = "Normal login successful. Bypass the password check to find the flag."
                else:
                    message = f"Authentication bypass successful. {FLAGS['sqli']}"
                    mark_challenge_completed(4)
            else:
                message = "Login failed. Try again."
        except Exception as exc:
            message = f"SQL error: {exc}"
        finally:
            conn.close()
    return render_template("challenge4.html", message=message, debug_query=debug_query)


@app.route("/secure/challenge/4", methods=["GET", "POST"])
def secure_challenge4():
    if 4 not in get_completed_challenges():
        return locked_defence_response(4)

    message = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cur.fetchone()
        conn.close()
        message = "Login successful." if user else "Login failed. SQL injection input is treated as data."
    return render_template("secure_sqli.html", message=message)


@app.route("/challenge/5")
def challenge5():
    document_id = request.args.get("document", "1001")
    document = None
    error = None

    try:
        document_number = int(document_id)
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # Vulnerable on purpose: authentication exists, but object ownership is not checked.
        cur.execute("SELECT id, owner, title, content FROM documents WHERE id = ?", (document_number,))
        document = cur.fetchone()
        conn.close()
        if document and FLAGS["idor"] in document[3]:
            mark_challenge_completed(5)
    except ValueError:
        error = "Document ID must be a number."

    return render_template(
        "challenge5.html",
        document_id=document_id,
        document=document,
        error=error,
    )


@app.route("/secure/challenge/5")
def secure_challenge5():
    if 5 not in get_completed_challenges():
        return locked_defence_response(5)

    document_id = request.args.get("document", "1001")
    username = current_username()
    document = None
    error = None
    status = 200

    try:
        document_number = int(document_id)
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, owner, title, content FROM documents WHERE id = ? AND owner = ?",
            (document_number, username),
        )
        document = cur.fetchone()
        conn.close()
        if document is None:
            error = "Blocked: this document does not belong to the signed-in user."
            status = 403
    except ValueError:
        error = "Document ID must be a number."
        status = 400

    return (
        render_template(
            "secure_idor.html",
            document_id=document_id,
            username=username,
            document=document,
            error=error,
        ),
        status,
    )


@app.route("/challenge/6", methods=["GET", "POST"])
def challenge6():
    message = None
    username = "admin"
    token = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        token = request.form.get("token", "").strip()
        expected = f"{username}-{VULNERABLE_RESET_SUFFIX}"
        if username == "admin" and secrets.compare_digest(token, expected):
            message = f"Predictable reset token accepted. {FLAGS['reset']}"
            mark_challenge_completed(6)
        else:
            message = "Reset token rejected. Look for a token pattern built from public information."

    return render_template(
        "challenge6.html",
        username=username,
        token=token,
        message=message,
    )


@app.route("/secure/challenge/6", methods=["GET", "POST"])
def secure_challenge6():
    if 6 not in get_completed_challenges():
        return locked_defence_response(6)

    message = None
    demo_token = None
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    if request.method == "GET":
        demo_token = secrets.token_urlsafe(32)
        expires_at = time.time() + SECURE_RESET_TOKEN_TTL_SECONDS
        cur.execute("DELETE FROM reset_tokens WHERE username = ?", ("admin",))
        cur.execute(
            "INSERT INTO reset_tokens (token_hash, username, expires_at, used) VALUES (?, ?, ?, 0)",
            (hash_reset_token(demo_token), "admin", expires_at),
        )
        conn.commit()
    else:
        submitted_token = request.form.get("token", "").strip()
        token_hash = hash_reset_token(submitted_token)
        cur.execute(
            """
            SELECT username FROM reset_tokens
            WHERE token_hash = ? AND expires_at >= ? AND used = 0
            """,
            (token_hash, time.time()),
        )
        match = cur.fetchone()
        if match:
            cur.execute("UPDATE reset_tokens SET used = 1 WHERE token_hash = ?", (token_hash,))
            conn.commit()
            message = "Secure token accepted once. A replay of the same token will now fail."
        else:
            message = "Reset rejected: the token is invalid, expired, or already used."

    conn.close()
    return render_template(
        "secure_reset.html",
        demo_token=demo_token,
        ttl_seconds=SECURE_RESET_TOKEN_TTL_SECONDS,
        message=message,
    )


if __name__ == "__main__":
    init_db()
    app.run(
        debug=os.environ.get("FLASK_DEBUG") == "1",
        host="127.0.0.1",
        port=5000,
    )
