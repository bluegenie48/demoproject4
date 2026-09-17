"""Simple admin dashboard — inventory tracker."""

from flask import Flask, jsonify, request, redirect, url_for
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user,
)
import bcrypt

app = Flask(__name__)
app.secret_key = "change-me-in-production"

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
    return jsonify({"message": "logged in", "role": user_record["role"]})


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "logged out"})


@app.route("/api/inventory")
@login_required
def list_inventory():
    return jsonify(INVENTORY)


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
    return jsonify(item), 201


@app.route("/api/inventory/<int:item_id>", methods=["DELETE"])
@login_required
def delete_item(item_id):
    if current_user.role != "admin":
        return jsonify({"error": "admin required"}), 403

    idx = next((i for i, item in enumerate(INVENTORY) if item["id"] == item_id), None)
    if idx is None:
        return jsonify({"error": "not found"}), 404

    removed = INVENTORY.pop(idx)
    return jsonify({"deleted": removed})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})
