"""Test-only HTTP server that exposes the SAME core service as the FastAPI app,
using only the standard library. It lets tests/e2e.mjs run without installing FastAPI.
Usage: python tests/harness_server.py [port]"""
import json
import os
import re
import sys
from urllib.parse import parse_qsl, urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.app import config  # noqa: E402
from backend.app.service import AppError, Service  # noqa: E402
from backend.tests.helpers import FakeMailer, fake_google_verifier  # noqa: E402

config.PBKDF2_ITERATIONS = 1000          # faster tests; real servers keep the strong default
config.CODE_COOLDOWN_SECONDS = 0
config.CODE_MAX_PER_HOUR = 1000
mailer = FakeMailer()
svc = Service(":memory:", mailer=mailer, google_client_id="test-client-id")
svc.google_verifier = fake_google_verifier

ROUTES = [
    ("GET", r"/api/config", False, lambda u, m, b, t, q: svc.public_config()),
    ("POST", r"/api/auth/register", False, lambda u, m, b, t, q: svc.register(b.get("email"), b.get("password"), b.get("name"))),
    ("POST", r"/api/auth/verify", False, lambda u, m, b, t, q: svc.verify_email(b.get("email"), b.get("code"), q.get("__ua", ""))),
    ("POST", r"/api/auth/resend", False, lambda u, m, b, t, q: svc.resend_code(b.get("email"))),
    ("POST", r"/api/auth/login", False, lambda u, m, b, t, q: svc.login(b.get("email"), b.get("password"), q.get("__ua", ""))),
    ("POST", r"/api/auth/google", False, lambda u, m, b, t, q: svc.google_login(b.get("credential"), q.get("__ua", ""))),
    ("POST", r"/api/auth/forgot", False, lambda u, m, b, t, q: svc.forgot_password(b.get("email"))),
    ("POST", r"/api/auth/reset", False, lambda u, m, b, t, q: svc.reset_password(b.get("email"), b.get("code"), b.get("new_password"))),
    ("POST", r"/api/auth/logout", False, lambda u, m, b, t, q: svc.logout(t)),
    ("POST", r"/api/account/name", True, lambda u, m, b, t, q: svc.update_name(u, b.get("name"))),
    ("POST", r"/api/account/email/request", True, lambda u, m, b, t, q: svc.request_email_change(u, b.get("new_email"), b.get("password"))),
    ("POST", r"/api/account/email/confirm", True, lambda u, m, b, t, q: svc.confirm_email_change(u, b.get("new_email"), b.get("code"))),
    ("GET", r"/api/account/devices", True, lambda u, m, b, t, q: svc.list_devices(u, t)),
    ("POST", r"/api/account/devices/revoke", True, lambda u, m, b, t, q: svc.revoke_device(u, t, b.get("id"))),
    ("POST", r"/api/account/devices/revoke-others", True, lambda u, m, b, t, q: svc.revoke_other_devices(u, t)),
    ("POST", r"/api/account/delete", True, lambda u, m, b, t, q: svc.delete_account(u, t, b.get("password"))),
    # test-only: read the last code the server "e-mailed" (never exists in the real app)
    ("GET", r"/__test/code", False, lambda u, m, b, t, q: {"code": mailer.last_code(q.get("email", "").strip().lower())}),
    ("GET", r"/api/me", True, lambda u, m, b, t, q: {"user": u}),
    ("GET", r"/api/sessions", True, lambda u, m, b, t, q: svc.list_sessions(u, q.get("archived") == "1")),
    ("POST", r"/api/auth/password", True, lambda u, m, b, t, q: svc.change_password(u, t, b.get("old_password"), b.get("new_password"))),
    ("DELETE", r"/api/sessions/(\d+)", True, lambda u, m, b, t, q: svc.delete_session(u, int(m[0]))),
    ("POST", r"/api/sessions/(\d+)/leave", True, lambda u, m, b, t, q: svc.leave_session(u, int(m[0]))),
    ("POST", r"/api/sessions/(\d+)/hide", True, lambda u, m, b, t, q: svc.set_hidden(u, int(m[0]), True)),
    ("POST", r"/api/sessions/(\d+)/unhide", True, lambda u, m, b, t, q: svc.set_hidden(u, int(m[0]), False)),
    ("POST", r"/api/sessions", True, lambda u, m, b, t, q: svc.create_session(u, b.get("title"), b.get("n_parties"), b.get("metric", "sum"), b.get("decimals", 0))),
    ("GET", r"/api/sessions/(\d+)", True, lambda u, m, b, t, q: svc.get_session(u, int(m[0]))),
    ("GET", r"/api/invite/([^/]+)", True, lambda u, m, b, t, q: svc.preview_invite(u, m[0])),
    ("POST", r"/api/invite/([^/]+)/join", True, lambda u, m, b, t, q: svc.join(u, m[0], b.get("public_key"))),
    ("POST", r"/api/sessions/(\d+)/shares", True, lambda u, m, b, t, q: svc.submit_shares(u, int(m[0]), b.get("shares"))),
    ("GET", r"/api/sessions/(\d+)/my-shares", True, lambda u, m, b, t, q: svc.my_shares(u, int(m[0]))),
    ("POST", r"/api/sessions/(\d+)/partial", True, lambda u, m, b, t, q: svc.submit_partial(u, int(m[0]), b.get("partial"))),
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self, method):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            auth = self.headers.get("Authorization") or ""
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
            parts = urlsplit(self.path)
            query = dict(parse_qsl(parts.query))
            query["__ua"] = self.headers.get("User-Agent", "")
            for rm, pattern, needs_auth, fn in ROUTES:
                m = re.fullmatch(pattern, parts.path)
                if rm == method and m:
                    user = svc.authenticate(token) if needs_auth else None
                    return self._send(200, fn(user, m.groups(), body, token, query))
            self._send(404, {"detail": "Not found"})
        except AppError as e:
            self._send(e.status, {"detail": e.message, **({"code": e.code} if e.code else {})})
        except Exception as e:   # pragma: no cover
            self._send(500, {"detail": f"harness error: {e!r}"})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
