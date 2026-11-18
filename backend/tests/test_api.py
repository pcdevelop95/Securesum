"""API tests for the FastAPI layer. Skipped automatically if fastapi/httpx are not installed.
Run (after `pip install -r requirements.txt`):  python -m unittest discover -s backend/tests -t ."""
import base64
import os
import tempfile
import unittest

try:
    from fastapi.testclient import TestClient
except Exception:           # pragma: no cover
    TestClient = None

from backend.app import config
from backend.tests.helpers import FakeMailer, fake_google_verifier

KEY = base64.b64encode(os.urandom(294)).decode()
CT = base64.b64encode(os.urandom(256)).decode()


@unittest.skipIf(TestClient is None, "fastapi / httpx not installed")
class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from backend.app import main
        from backend.app.service import Service
        cls._saved = (config.PBKDF2_ITERATIONS, config.CODE_COOLDOWN_SECONDS)
        config.PBKDF2_ITERATIONS, config.CODE_COOLDOWN_SECONDS = 1000, 0
        cls.tmp = tempfile.mkdtemp()
        cls.mailer = FakeMailer()
        main.svc = Service(os.path.join(cls.tmp, "test.db"), mailer=cls.mailer, google_client_id="test-client")
        main.svc.google_verifier = fake_google_verifier
        cls.client = TestClient(main.app)

    @classmethod
    def tearDownClass(cls):
        config.PBKDF2_ITERATIONS, config.CODE_COOLDOWN_SECONDS = cls._saved

    def signup(self, name, password="password123"):
        """Register, read the e-mailed code, verify. Returns (email, headers)."""
        email = f"{name}{os.urandom(3).hex()}@example.com"
        r = self.client.post("/api/auth/register", json={"email": email, "password": password, "name": name})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"needs_verification": True, "email": email})
        v = self.client.post("/api/auth/verify", json={"email": email, "code": self.mailer.last_code(email)})
        self.assertEqual(v.status_code, 200, v.text)
        return email, {"Authorization": "Bearer " + v.json()["token"]}

    def auth(self, name):
        return self.signup(name)[1]

    def test_health_and_security_headers(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertIn("default-src 'self'", r.headers["content-security-policy"])
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertEqual(r.headers["cache-control"], "no-store")

    def test_config(self):
        self.assertEqual(self.client.get("/api/config").json(), {"google_client_id": "test-client", "email_delivery": "smtp"})

    def test_requires_login(self):
        r = self.client.get("/api/sessions")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["code"], "session_expired")
        self.assertEqual(self.client.get("/api/sessions", headers={"Authorization": "Bearer nope"}).status_code, 401)

    def test_unverified_account_cannot_log_in(self):
        email = f"u{os.urandom(3).hex()}@example.com"
        self.client.post("/api/auth/register", json={"email": email, "password": "password123", "name": "U"})
        r = self.client.post("/api/auth/login", json={"email": email, "password": "password123"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["code"], "email_not_verified")
        bad = self.client.post("/api/auth/verify", json={"email": email, "code": "000000"})
        self.assertEqual(bad.status_code, 400)

    def test_typo_email_is_rejected(self):
        r = self.client.post("/api/auth/register", json={"email": "x@gmial.com", "password": "password123", "name": "X"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("gmail.com", r.json()["detail"])

    def test_google_login_route(self):
        r = self.client.post("/api/auth/google", json={"credential": "fake:sub9:g9@example.com:Gee:true"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["user"]["google_linked"])
        self.assertEqual(self.client.post("/api/auth/google", json={"credential": "junk"}).status_code, 401)

    def test_forgot_and_reset_routes(self):
        email, _ = self.signup("fr")
        self.assertEqual(self.client.post("/api/auth/forgot", json={"email": "nobody@example.com"}).json(), {"ok": True})
        self.client.post("/api/auth/forgot", json={"email": email})
        r = self.client.post("/api/auth/reset", json={"email": email, "code": self.mailer.last_code(email), "new_password": "freshpass123"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.client.post("/api/auth/login", json={"email": email, "password": "freshpass123"}).status_code, 200)

    def test_account_routes(self):
        email, h = self.signup("acc")
        me = self.client.get("/api/me", headers=h).json()["user"]
        self.assertTrue(me["email_verified"] and me["has_password"] and not me["google_linked"])
        self.assertEqual(self.client.post("/api/account/name", headers=h, json={"name": "New Name"}).json()["user"]["name"], "New Name")
        devices = self.client.get("/api/account/devices", headers=h).json()["devices"]
        self.assertEqual(len(devices), 1)
        self.assertTrue(devices[0]["current"])
        self.assertEqual(self.client.post("/api/account/devices/revoke", headers=h, json={"id": devices[0]["id"]}).status_code, 400)
        self.assertEqual(self.client.post("/api/account/devices/revoke-others", headers=h).status_code, 200)
        self.assertEqual(self.client.post("/api/account/delete", headers=h, json={"password": "wrong-password"}).status_code, 403)
        self.assertEqual(self.client.post("/api/account/delete", headers=h, json={"password": "password123"}).status_code, 200)
        self.assertEqual(self.client.get("/api/me", headers=h).status_code, 401)

    def test_full_flow(self):
        a, b = self.auth("a"), self.auth("b")
        s = self.client.post("/api/sessions", headers=a, json={"title": "T", "n_parties": 2, "metric": "sum", "decimals": 0}).json()
        for h in (a, b):
            r = self.client.post(f"/api/invite/{s['code']}/join", headers=h, json={"public_key": KEY})
            self.assertEqual(r.status_code, 200, r.text)
        for h in (a, b):
            r = self.client.post(f"/api/sessions/{s['id']}/shares", headers=h,
                                 json={"shares": [{"to_idx": 1, "ciphertext": CT}, {"to_idx": 2, "ciphertext": CT}]})
            self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(len(self.client.get(f"/api/sessions/{s['id']}/my-shares", headers=a).json()["shares"]), 2)
        self.client.post(f"/api/sessions/{s['id']}/partial", headers=a, json={"partial": "5"})
        r = self.client.post(f"/api/sessions/{s['id']}/partial", headers=b, json={"partial": "7"})
        self.assertEqual(r.json()["result"]["sum"], "12")

    def test_manage_routes(self):
        a, b = self.auth("m1"), self.auth("m2")
        s = self.client.post("/api/sessions", headers=a, json={"title": "M", "n_parties": 3}).json()
        self.client.post(f"/api/invite/{s['code']}/join", headers=a, json={"public_key": KEY})
        self.client.post(f"/api/invite/{s['code']}/join", headers=b, json={"public_key": KEY})
        self.assertEqual(self.client.post(f"/api/sessions/{s['id']}/leave", headers=b).status_code, 200)
        self.assertEqual(self.client.post(f"/api/sessions/{s['id']}/hide", headers=a).status_code, 409)   # not finished
        self.assertEqual(self.client.delete(f"/api/sessions/{s['id']}", headers=b).status_code, 404)      # outsider now
        self.assertEqual(self.client.delete(f"/api/sessions/{s['id']}", headers=a).status_code, 200)
        self.assertEqual(self.client.get(f"/api/sessions/{s['id']}", headers=a).status_code, 404)
        self.assertEqual(self.client.get("/api/sessions?archived=1", headers=a).json()["sessions"], [])

    def test_change_password_route(self):
        email, h = self.signup("pw", "oldpassword1")
        bad = self.client.post("/api/auth/password", headers=h, json={"old_password": "x", "new_password": "newpassword1"})
        self.assertEqual(bad.status_code, 403)                  # wrong password must not look like an expired login
        self.assertNotEqual(bad.json().get("code"), "session_expired")
        ok = self.client.post("/api/auth/password", headers=h, json={"old_password": "oldpassword1", "new_password": "newpassword1"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(self.client.get("/api/me", headers=h).status_code, 200)

    def test_errors_use_detail_field(self):
        a = self.auth("e")
        r = self.client.post("/api/sessions", headers=a, json={"title": "", "n_parties": 3})
        self.assertEqual(r.status_code, 400)
        self.assertIn("Title", r.json()["detail"])
        r = self.client.get("/api/sessions/99999", headers=a)
        self.assertEqual(r.status_code, 404)

    def test_frontend_is_served(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("SecureSum", r.text)
        js = self.client.get("/js/app.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn("javascript", js.headers["content-type"])


if __name__ == "__main__":
    unittest.main()
