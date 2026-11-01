"""Loopback-only synthetic lab: request handlers live in fixed/vulnerable.py."""

from __future__ import annotations

import copy
import json
import threading
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import fixed, vulnerable


class Store:
    def __init__(self):
        self.passwords = {"alice": "before-alice", "bob": "before-bob"}
        self.orders = {
            "101": {"id": "101", "owner_id": "alice", "memo": "alice-original"},
            "202": {"id": "202", "owner_id": "bob", "memo": "bob-original"},
        }
        self.credits = {"alice": 100, "bob": 100}
        self.purchases = []

    def change_password(self, user_id, password):
        self.passwords[user_id] = password

    def get_order(self, order_id):
        return dict(self.orders[order_id])

    def update_order(self, order_id, memo):
        self.orders[order_id]["memo"] = memo

    def purchase(self, user_id, quantity):
        self.credits[user_id] -= quantity * 10
        self.purchases.append({"user_id": user_id, "quantity": quantity})

    def snapshot(self):
        return copy.deepcopy({
            "passwords": self.passwords,
            "orders": self.orders,
            "credits": self.credits,
            "purchases": self.purchases,
        })


class Lab:
    def __init__(self, variant):
        if variant not in {"vulnerable", "fixed"}:
            raise ValueError("variant must be vulnerable or fixed")
        self.handlers = vulnerable if variant == "vulnerable" else fixed
        self.store = Store()
        # Demonstration credentials only. User identity comes from server state.
        self.sessions = {
            "alice-demo": {"user_id": "alice", "captcha_passed": False},
            "bob-demo": {"user_id": "bob", "captcha_passed": False},
        }

    def dispatch(self, path, body, session_id):
        session = self.sessions.get(session_id)
        if session is None:
            return {"status": 401}
        if path == "/verify":
            # Deterministic stand-in for a server verified CAPTCHA; not real CAPTCHA.
            session["captcha_passed"] = body.get("answer") == "demo-ok"
            return {"status": 200 if session["captcha_passed"] else 403}
        if path in {"/password", "/password-client"}:
            if not isinstance(body.get("password"), str) or not body["password"]:
                return {"status": 400}
            fn = self.handlers.reset_password if path == "/password" else self.handlers.reset_password_client_flag
        elif path == "/order":
            if body.get("order_id") not in self.store.orders or not isinstance(body.get("memo"), str):
                return {"status": 400}
            fn = self.handlers.update_order
        elif path == "/purchase":
            # Transport validation applies to both versions; positive value is the tested business rule.
            if type(body.get("quantity")) is not int or abs(body["quantity"]) > 100:
                return {"status": 400}
            fn = self.handlers.purchase
        else:
            return {"status": 404}
        return fn(body, session, self.store)


@contextmanager
def running_lab(variant):
    lab = Lab(variant)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096:
                    raise ValueError("invalid body size")
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError("JSON object required")
                cookies = SimpleCookie()
                cookies.load(self.headers.get("Cookie", ""))
                session_id = cookies["lab_session"].value if "lab_session" in cookies else ""
                result = lab.dispatch(self.path, body, session_id)
            except (ValueError, KeyError, TypeError):
                result = {"status": 400}
            payload = json.dumps(result).encode("utf-8")
            self.send_response(result["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    # No command line target or bind option: only a random loopback port.
    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    worker.start()
    try:
        yield lab, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)