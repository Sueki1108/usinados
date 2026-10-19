#!/usr/bin/env python3
"""Servidor local do Usinados.

Substitui Firebase Authentication e Cloud Firestore. Contas, materiais e
buchas ficam em data/db.json nesta máquina. Nenhuma chamada sai para o Google.
"""

import hashlib
import json
import os
import re
import secrets
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
DB_PATH = os.path.join(DATA_DIR, "db.json")
LOCK = threading.Lock()
HOST = "0.0.0.0"
PORT = 8080
PBKDF2_ROUNDS = 120_000
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

DEFAULT_MATERIALS = [
    {"name": "Aço 1045", "config": {"margem_lucro": "20", "hora_maquina": "10", "ferramenta": "5", "perda_peca": "5.00"}},
    {"name": "Alumínio", "config": {"margem_lucro": "25", "hora_maquina": "12", "ferramenta": "6", "perda_peca": "4.50"}},
    {"name": "Bronze", "config": {"margem_lucro": "15", "hora_maquina": "8", "ferramenta": "4", "perda_peca": "6.00"}},
]


def empty_db():
    return {"users": {}, "sessions": {}}


def load_db():
    if not os.path.exists(DB_PATH):
        return empty_db()
    with open(DB_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("users", {})
    data.setdefault("sessions", {})
    return data


def save_db(db):
    os.makedirs(DATA_DIR, exist_ok=True)
    temporary = DB_PATH + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(db, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.replace(temporary, DB_PATH)


def hash_password(password, salt):
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS
    )
    return digest.hex()


def normalize_email(value):
    return (value or "").strip().lower()


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, fmt, *args):
        print("[usinados] " + (fmt % args), flush=True)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/"):
            self.handle_api("GET", path)
            return
        super().do_GET()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/"):
            self.handle_api("POST", path)
            return
        self.send_json(404, {"code": "not-found", "message": "Rota não encontrada."})

    def do_PUT(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/"):
            self.handle_api("PUT", path)
            return
        self.send_json(404, {"code": "not-found", "message": "Rota não encontrada."})

    def do_DELETE(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/"):
            self.handle_api("DELETE", path)
            return
        self.send_json(404, {"code": "not-found", "message": "Rota não encontrada."})

    def handle_api(self, method, path):
        try:
            body = self.read_json() if method in {"POST", "PUT"} else {}
        except ValueError:
            self.send_json(400, {"code": "invalid-json", "message": "JSON inválido."})
            return

        with LOCK:
            db = load_db()
            status, payload, changed = self.route(db, method, path, body)
            if changed:
                save_db(db)
        self.send_json(status, payload)

    def route(self, db, method, path, body):
        if method == "GET" and path == "/api/health":
            return 200, {"ok": True}, False

        if method == "POST" and path == "/api/register":
            return self.register(db, body)
        if method == "POST" and path == "/api/login":
            return self.login(db, body)
        if method == "POST" and path == "/api/logout":
            return self.logout(db)

        email = self.current_email(db)
        if not email or email not in db["users"]:
            return 401, {"code": "auth/invalid-credential", "message": "Sessão inválida."}, False

        if method == "GET" and path == "/api/me":
            return 200, {"email": email}, False
        if method == "GET" and path == "/api/materials":
            return 200, {"data": db["users"][email]["materials"]}, False
        if method == "PUT" and path == "/api/materials":
            return self.save_materials(db, email, body)
        if method == "GET" and path == "/api/buchas":
            return 200, {"items": db["users"][email]["buchas"]}, False
        if method == "POST" and path == "/api/buchas":
            return self.add_bucha(db, email, body)
        if method == "DELETE" and path.startswith("/api/buchas/"):
            bucha_id = path[len("/api/buchas/") :]
            return self.delete_bucha(db, email, bucha_id)

        return 404, {"code": "not-found", "message": "Rota não encontrada."}, False

    def register(self, db, body):
        email = normalize_email(body.get("email"))
        password = body.get("password") or ""
        if not EMAIL_RE.match(email):
            return 400, {"code": "auth/invalid-email", "message": "E-mail inválido."}, False
        if len(password) < 6:
            return 400, {"code": "auth/weak-password", "message": "A senha deve ter pelo menos 6 caracteres."}, False
        if email in db["users"]:
            return 400, {"code": "auth/email-already-in-use", "message": "Este e-mail já está em uso."}, False

        salt = secrets.token_hex(16)
        db["users"][email] = {
            "salt": salt,
            "password_hash": hash_password(password, salt),
            "materials": json.loads(json.dumps(DEFAULT_MATERIALS)),
            "buchas": [],
        }
        token = self.open_session(db, email)
        return 201, {"token": token, "email": email}, True

    def login(self, db, body):
        email = normalize_email(body.get("email"))
        password = body.get("password") or ""
        user = db["users"].get(email)
        if not user or user["password_hash"] != hash_password(password, user["salt"]):
            return 401, {"code": "auth/invalid-credential", "message": "E-mail ou senha incorretos."}, False
        token = self.open_session(db, email)
        return 200, {"token": token, "email": email}, True

    def logout(self, db):
        header = self.headers.get("Authorization", "")
        token = header[7:].strip() if header.startswith("Bearer ") else ""
        if token and token in db["sessions"]:
            del db["sessions"][token]
            return 200, {"ok": True}, True
        return 200, {"ok": True}, False

    def save_materials(self, db, email, body):
        materials = body.get("data")
        if not isinstance(materials, list) or len(materials) > 100:
            return 400, {"code": "invalid-materials", "message": "Lista de materiais inválida."}, False
        cleaned = []
        for item in materials:
            if not isinstance(item, dict) or not str(item.get("name", "")).strip():
                return 400, {"code": "invalid-materials", "message": "Material sem nome."}, False
            config = item.get("config") if isinstance(item.get("config"), dict) else {}
            cleaned.append({"name": str(item["name"]).strip(), "config": {key: str(value) for key, value in config.items()}})
        db["users"][email]["materials"] = cleaned
        return 200, {"data": cleaned}, True

    def add_bucha(self, db, email, body):
        buchas = db["users"][email]["buchas"]
        if len(buchas) >= 500:
            return 400, {"code": "limit", "message": "Limite de buchas atingido."}, False
        try:
            bucha = {
                "id": secrets.token_hex(8),
                "material": str(body["material"]).strip(),
                "di": float(body["di"]),
                "de": float(body["de"]),
                "altura": float(body["altura"]),
                "valor": float(body["valor"]),
                "custo_mm": float(body["custo_mm"]),
            }
        except (KeyError, TypeError, ValueError):
            return 400, {"code": "invalid-bucha", "message": "Dados da bucha inválidos."}, False
        if not bucha["material"]:
            return 400, {"code": "invalid-bucha", "message": "Informe o material."}, False
        buchas.append(bucha)
        return 201, bucha, True

    def delete_bucha(self, db, email, bucha_id):
        buchas = db["users"][email]["buchas"]
        remaining = [item for item in buchas if item.get("id") != bucha_id]
        if len(remaining) == len(buchas):
            return 404, {"code": "not-found", "message": "Bucha não encontrada."}, False
        db["users"][email]["buchas"] = remaining
        return 200, {"ok": True}, True

    def open_session(self, db, email):
        token = secrets.token_urlsafe(32)
        db["sessions"][token] = email
        return token

    def current_email(self, db):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return db["sessions"].get(header[7:].strip())

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > 1_000_000:
            raise ValueError("payload")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("payload")
        return data

    def send_json(self, status, payload):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main():
    server = ThreadingHTTPServer((HOST, PORT), AppHandler)
    print(f"Usinados em http://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
