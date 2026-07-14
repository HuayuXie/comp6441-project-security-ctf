import os
from pathlib import Path
import sqlite3
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
    "sqli": "FLAG{sql_queries_need_parameters}",
}


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER)")
    cur.execute("INSERT INTO users (username, password, is_admin) VALUES ('student', 'password123', 0)")
    cur.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'not-the-real-password', 1)")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/defence")
def defence():
    return render_template("defence.html")


@app.route("/challenge/1")
def challenge1():
    role = request.cookies.get("role", "user")
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
    session.setdefault("username", "student")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, is_admin FROM users WHERE username = ?", (session["username"],))
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
    show_flag = "<script>" in query.lower() or "onerror" in query.lower() or "alert" in query.lower()
    return render_template("challenge2.html", query=query, show_flag=show_flag, flag=FLAGS["xss"])


@app.route("/secure/challenge/2")
def secure_challenge2():
    query = request.args.get("q", "")
    response = make_response(render_template("secure_xss.html", query=query, escaped_query=escape(query)))
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
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
    except Exception as exc:
        error = str(exc)
    return render_template("challenge3.html", filename=filename, content=content, error=error)


@app.route("/secure/challenge/3")
def secure_challenge3():
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
                message = f"Login successful. {FLAGS['sqli']}"
            else:
                message = "Login failed. Try again."
        except Exception as exc:
            message = f"SQL error: {exc}"
        finally:
            conn.close()
    return render_template("challenge4.html", message=message, debug_query=debug_query)


@app.route("/secure/challenge/4", methods=["GET", "POST"])
def secure_challenge4():
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


if __name__ == "__main__":
    init_db()
    app.run(
        debug=os.environ.get("FLASK_DEBUG") == "1",
        host="127.0.0.1",
        port=5000,
    )
