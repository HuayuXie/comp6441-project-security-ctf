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
    "path": "FLAG{path_traversal_hidden_file_found}",
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


if __name__ == "__main__":
    init_db()
    app.run(
        debug=os.environ.get("FLASK_DEBUG") == "1",
        host="127.0.0.1",
        port=5000,
    )
