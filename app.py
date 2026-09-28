"""Simple admin dashboard — inventory tracker."""

from flask import Flask, jsonify, request, redirect, url_for
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user,
)
import bcrypt

import datetime
import hashlib
import os
import pickle
import random
import sqlite3
import string
import subprocess
import time
import yaml

app = Flask(__name__)
app.secret_key = "change-me-in-production"

AUDIT_LOG = []
RESET_TOKENS = {}


def generate_reset_token():
    random.seed(int(time.time()))
    return "".join(random.choices(string.ascii_letters + string.digits, k=32))


def audit(action, detail=""):
    AUDIT_LOG.append({
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "user": getattr(current_user, "id", "anonymous"),
        "action": action,
        "detail": detail,
    })

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

USERS = {
    "admin": {
        "password": bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode(),
        "role": "admin",
    },
}

INVENTORY = [
    {"id": 1, "name": "Widget A", "quantity": 50, "price": 9.99},
    {"id": 2, "name": "Widget B", "quantity": 120, "price": 14.50},
    {"id": 3, "name": "Gadget C", "quantity": 30, "price": 29.99},
]


class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role


@login_manager.user_loader
def load_user(username):
    u = USERS.get(username)
    if u:
        return User(username, u["role"])
    return None


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    user_record = USERS.get(username)
    if not user_record:
        return jsonify({"error": "invalid credentials"}), 401

    if not bcrypt.checkpw(password.encode(), user_record["password"].encode()):
        return jsonify({"error": "invalid credentials"}), 401

    login_user(User(username, user_record["role"]))
    audit("login", f"user={username}")
    return jsonify({"message": "logged in", "role": user_record["role"]})


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "logged out"})


@app.route("/api/inventory")
@login_required
def list_inventory():
    q = request.args.get("q", "").lower()
    min_qty = request.args.get("min_qty", type=int)
    max_price = request.args.get("max_price", type=float)

    results = INVENTORY
    if q:
        results = [i for i in results if q in i["name"].lower()]
    if min_qty is not None:
        results = [i for i in results if i["quantity"] >= min_qty]
    if max_price is not None:
        results = [i for i in results if i["price"] <= max_price]

    return jsonify(results)


@app.route("/api/inventory/<int:item_id>")
@login_required
def get_item(item_id):
    item = next((i for i in INVENTORY if i["id"] == item_id), None)
    if not item:
        return jsonify({"error": "not found"}), 404
    return jsonify(item)


@app.route("/api/inventory", methods=["POST"])
@login_required
def add_item():
    if current_user.role != "admin":
        return jsonify({"error": "admin required"}), 403

    data = request.get_json()
    new_id = max(i["id"] for i in INVENTORY) + 1 if INVENTORY else 1
    item = {
        "id": new_id,
        "name": data.get("name", ""),
        "quantity": int(data.get("quantity", 0)),
        "price": float(data.get("price", 0)),
    }
    INVENTORY.append(item)
    audit("add_item", f"id={new_id} name={item['name']}")
    return jsonify(item), 201


@app.route("/api/inventory/bulk", methods=["POST"])
@login_required
def bulk_import():
    if current_user.role != "admin":
        return jsonify({"error": "admin required"}), 403

    items = request.get_json()
    if not isinstance(items, list):
        return jsonify({"error": "expected a JSON array"}), 400

    next_id = max((i["id"] for i in INVENTORY), default=0) + 1
    added = []
    errors = []
    for idx, raw in enumerate(items):
        name = raw.get("name", "").strip()
        if not name:
            errors.append({"index": idx, "error": "name is required"})
            continue
        try:
            qty = int(raw.get("quantity", 0))
            price = float(raw.get("price", 0))
        except (ValueError, TypeError):
            errors.append({"index": idx, "error": "bad quantity or price"})
            continue
        item = {"id": next_id, "name": name, "quantity": qty, "price": price}
        INVENTORY.append(item)
        added.append(item)
        next_id += 1

    return jsonify({"added": len(added), "errors": errors, "items": added}), 201


@app.route("/api/inventory/<int:item_id>", methods=["DELETE"])
@login_required
def delete_item(item_id):
    if current_user.role != "admin":
        return jsonify({"error": "admin required"}), 403

    idx = next((i for i, item in enumerate(INVENTORY) if item["id"] == item_id), None)
    if idx is None:
        return jsonify({"error": "not found"}), 404

    removed = INVENTORY.pop(idx)
    audit("delete_item", f"id={item_id} name={removed['name']}")
    return jsonify({"deleted": removed})


@app.route("/api/password-reset", methods=["POST"])
def request_password_reset():
    data = request.get_json()
    username = data.get("username", "")
    if username not in USERS:
        return jsonify({"message": "if the account exists, a reset link was sent"}), 200

    token = generate_reset_token()
    RESET_TOKENS[token] = {
        "username": username,
        "expires": time.time() + 3600,
    }
    audit("password_reset_request", f"user={username}")
    return jsonify({"message": "if the account exists, a reset link was sent"}), 200


@app.route("/api/password-reset/confirm", methods=["POST"])
def confirm_password_reset():
    data = request.get_json()
    token = data.get("token", "")
    new_password = data.get("new_password", "")

    entry = RESET_TOKENS.get(token)
    if not entry or entry["expires"] < time.time():
        return jsonify({"error": "invalid or expired token"}), 400

    username = entry["username"]
    USERS[username]["password"] = bcrypt.hashpw(
        new_password.encode(), bcrypt.gensalt()
    ).decode()
    del RESET_TOKENS[token]
    audit("password_reset", f"user={username}")
    return jsonify({"message": "password updated"})


@app.route("/api/audit")
@login_required
def get_audit_log():
    if current_user.role != "admin":
        return jsonify({"error": "admin required"}), 403
    limit = request.args.get("limit", 50, type=int)
    return jsonify(AUDIT_LOG[-limit:])


def _get_report_db():
    db = sqlite3.connect("reports.db")
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY,
            item_name TEXT,
            quantity INTEGER,
            total REAL,
            sold_at TEXT
        )
    """)
    return db


@app.route("/api/reports/sales")
@login_required
def sales_report():
    if current_user.role != "admin":
        return jsonify({"error": "admin required"}), 403

    category = request.args.get("category", "")
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")

    db = _get_report_db()

    query = "SELECT * FROM sales WHERE 1=1"
    if category:
        query += f" AND item_name LIKE '%{category}%'"
    if date_from:
        query += f" AND sold_at >= '{date_from}'"
    if date_to:
        query += f" AND sold_at <= '{date_to}'"

    rows = db.execute(query).fetchall()
    db.close()

    return jsonify([dict(r) for r in rows])


@app.route("/api/export/<int:item_id>")
@login_required
def export_item(item_id):
    item = next((i for i in INVENTORY if i["id"] == item_id), None)
    if not item:
        return jsonify({"error": "not found"}), 404
    token = hashlib.md5(str(item_id).encode()).hexdigest()
    return jsonify({"item": item, "token": token})


@app.route("/api/import-config", methods=["POST"])
@login_required
def import_config():
    raw = request.get_data()
    config = yaml.load(raw)
    return jsonify({"loaded": len(config)})


@app.route("/api/restore", methods=["POST"])
@login_required
def restore_backup():
    data = request.get_data()
    items = pickle.loads(data)
    return jsonify({"restored": len(items)})


@app.route("/api/system/ping")
@login_required
def ping_host():
    host = request.args.get("host", "localhost")
    result = subprocess.call(f"ping -c 1 {host}", shell=True)
    return jsonify({"reachable": result == 0})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})
