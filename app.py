import sqlite3
import base64, time
import secrets
from  flask import Flask, request, jsonify, make_response, session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from db import get_db, close_db, init_db

app = Flask(__name__)
app.teardown_appcontext(close_db)
app.secret_key = "dev"

limiter = Limiter(get_remote_address, app=app, default_limits=[])

@app.route('/')
def home():
    return "<h1>Welcome to Home Page</h1>"

@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Database Initiallized")

@app.post('/register')
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify(error="username and password required"), 400

    db = get_db()

    try:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        db.commit()

    except sqlite3.IntegrityError:
        return jsonify(error=f"User {username} already registered"), 409

    return jsonify(message="registered"), 201

@app.post('/login')
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify(error="username and password required"), 400

    db = get_db()
    
    user = db.execute(
        "SELECT * from users WHERE username= ?", (username,)
        ).fetchone()
    
    if user is None:
        return jsonify(error="No such user"), 404
    
    if not check_password_hash(user['password'], password):
        return jsonify(error="wrong password"), 401

    # resp = make_response(jsonify(message="logged in"))
    # resp.set_cookie("user_id", str(user["id"]))
    # return resp

    session["user_id"] = user["id"]
    return jsonify(message="logged in"), 200


@app.post('/notes')
def create_note():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify(error="not logged in"), 401

    data = request.get_json(silent=True) or {}
    title = data.get("title")
    body  = data.get("body")
    if not title or not body:
        return jsonify(error="title and body required"), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user_id, title, body),
    )
    db.commit()
    return jsonify(id=cur.lastrowid, message="note created"), 201

@app.get('/notes/<int:note_id>')
def get_note(note_id):
    requester_id = session.get("user_id")
    if not requester_id:
        return jsonify(error="not logged in"), 401

    db = get_db()
    note = db.execute(
        "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, requester_id),
    ).fetchone()

    if note is None:
        return jsonify(error="not found"), 404

    return jsonify(id=note["id"], owner_id=note["owner_id"], title=note["title"], body=note["body"])

@app.post('/forgot-password')
def forgot_password():
    data = request.get_json(silent=True) or {}
    username = data.get("username")

    if not username: 
        return jsonify(error="username required"), 400

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if user is None:
        return jsonify(error="No such user"), 404

    token = secrets.token_urlsafe(32)
    expires_at = time.time() + 600  # 10 minutes

    db.execute(
        "INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
        (user["id"], token, expires_at)
    )
    db.commit()

    return jsonify(message="reset token generated", token=token), 201

@app.post('/reset-password')
def reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    new_password = data.get("new_password")


    if not token or not new_password:
        return jsonify(error="token and new_password required"), 400

    db = get_db()
    row = db.execute(
        "SELECT * FROM reset_tokens WHERE token = ? AND used = 0 AND expires_at > ?", (token, time.time())
    ).fetchone()

    if row is None:
        return jsonify(error="invalid or expired token"), 400

    db.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (generate_password_hash(new_password), row["user_id"])
    )
    db.execute(
        "UPDATE reset_tokens SET used = 1 WHERE id = ?",
        (row["id"],)
    )
    db.commit()

    return jsonify(message="password reset successful"), 200

    



