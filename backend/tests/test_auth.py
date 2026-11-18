"""Tests for sign-up, e-mail verification, Google sign-in, password reset, devices and account deletion."""
import os
import sqlite3
import tempfile
import time
import unittest

from backend.app import config, security
from backend.app.service import AppError, Service
from backend.tests.helpers import FakeMailer, fake_google_verifier

PW = "password123"


class AuthTests(unittest.TestCase):
    def setUp(self):
        self._saved = (config.PBKDF2_ITERATIONS, config.CODE_COOLDOWN_SECONDS, config.CODE_MAX_PER_HOUR)
        config.PBKDF2_ITERATIONS, config.CODE_COOLDOWN_SECONDS = 1000, 0
        self.mailer = FakeMailer()
        self.svc = Service(":memory:", mailer=self.mailer, google_client_id="test-client")
        self.svc.google_verifier = fake_google_verifier

    def tearDown(self):
        config.PBKDF2_ITERATIONS, config.CODE_COOLDOWN_SECONDS, config.CODE_MAX_PER_HOUR = self._saved
        self.svc.close()

    def signup(self, email="a@example.com", password=PW, name="Asha"):
        self.svc.register(email, password, name)
        return self.svc.verify_email(email, self.mailer.last_code(email))

    def err(self, fn, *args, **kw):
        with self.assertRaises(AppError) as cm:
            fn(*args, **kw)
        return cm.exception

    # ---- sign-up and verification
    def test_account_is_unusable_until_the_email_code_is_entered(self):
        r = self.svc.register("a@example.com", PW, "Asha")
        self.assertEqual(r, {"needs_verification": True, "email": "a@example.com"})
        self.assertNotIn("token", r)
        self.assertEqual(self.mailer.count("a@example.com"), 1)
        e = self.err(self.svc.login, "a@example.com", PW)           # right password, but not verified
        self.assertEqual((e.status, e.code), (403, "email_not_verified"))
        self.assertEqual(self.mailer.count("a@example.com"), 2)     # login re-sent a code
        code = self.mailer.last_code("a@example.com")
        wrong = "000000" if code != "000000" else "111111"
        self.assertEqual(self.err(self.svc.verify_email, "a@example.com", wrong).status, 400)
        self.assertEqual(self.err(self.svc.verify_email, "a@example.com", "12ab").status, 400)
        done = self.svc.verify_email("a@example.com", code)
        self.assertTrue(done["user"]["email_verified"])
        self.assertEqual(self.svc.authenticate(done["token"])["email"], "a@example.com")
        self.assertEqual(self.err(self.svc.verify_email, "a@example.com", code).status, 400)   # single use
        self.assertEqual(self.svc.login("a@example.com", PW)["user"]["name"], "Asha")

    def test_email_must_look_real_and_typos_are_caught(self):
        for bad in ("nope", "a@b", "a@@b.com", "a..b@x.com", "", " ", "x" * 130 + "@a.com"):
            self.assertEqual(self.err(self.svc.register, bad, PW, "A").status, 400, bad)
        e = self.err(self.svc.register, "asha@gmial.com", PW, "A")
        self.assertEqual(e.status, 400)
        self.assertIn("asha@gmail.com", e.message)
        for typo in ("x@gmail.con", "x@hotmial.com", "x@yahooo.com", "x@gmail.in"):
            self.assertEqual(self.err(self.svc.register, typo, PW, "A").status, 400, typo)
        self.assertEqual(self.mailer.sent, [])              # nothing was sent for rejected addresses
        self.assertEqual(self.err(self.svc.register, "ok@example.com", "short", "A").status, 400)
        self.assertEqual(self.err(self.svc.register, "ok@example.com", PW, "  ").status, 400)

    def test_registered_email_cannot_be_registered_again_but_unverified_can_be_retried(self):
        self.signup("a@example.com")
        self.assertEqual(self.err(self.svc.register, "A@Example.com", PW, "X").status, 409)
        # an unverified attempt can be redone, and the newest password wins
        self.svc.register("b@example.com", "firstpassword1", "B")
        self.svc.register("b@example.com", "secondpassword2", "B2")
        self.svc.verify_email("b@example.com", self.mailer.last_code("b@example.com"))
        self.assertEqual(self.svc.login("b@example.com", "secondpassword2")["user"]["name"], "B2")
        self.assertEqual(self.err(self.svc.login, "b@example.com", "firstpassword1").status, 401)

    def test_code_is_locked_after_too_many_wrong_guesses(self):
        self.svc.register("a@example.com", PW, "A")
        good = self.mailer.last_code("a@example.com")
        bad = "000000" if good != "000000" else "111111"
        for _ in range(config.CODE_MAX_ATTEMPTS):
            self.assertEqual(self.err(self.svc.verify_email, "a@example.com", bad).status, 400)
        self.assertEqual(self.err(self.svc.verify_email, "a@example.com", good).status, 429)   # even the right code
        self.svc.resend_code("a@example.com")
        self.svc.verify_email("a@example.com", self.mailer.last_code("a@example.com"))          # a fresh code works

    def test_code_expires(self):
        self.svc.register("a@example.com", PW, "A")
        with self.svc.tx() as c:
            c.execute("UPDATE email_codes SET expires_at=?", (time.time() - 1,))
        self.assertEqual(self.err(self.svc.verify_email, "a@example.com", self.mailer.last_code("a@example.com")).status, 400)

    def test_sending_codes_is_rate_limited(self):
        config.CODE_COOLDOWN_SECONDS = 60
        self.svc.register("a@example.com", PW, "A")
        self.assertEqual(self.err(self.svc.resend_code, "a@example.com").status, 429)
        config.CODE_COOLDOWN_SECONDS, config.CODE_MAX_PER_HOUR = 0, 3
        self.svc.resend_code("a@example.com"); self.svc.resend_code("a@example.com")
        self.assertEqual(self.err(self.svc.resend_code, "a@example.com").status, 429)

    def test_resend_does_not_reveal_which_addresses_exist(self):
        self.signup("a@example.com")
        before = len(self.mailer.sent)
        for addr in ("a@example.com", "nobody@example.com", "not-an-email"):       # verified, unknown, invalid
            self.assertEqual(self.svc.resend_code(addr), {"ok": True})
        for addr in ("nobody@example.com", "not-an-email"):
            self.assertEqual(self.svc.forgot_password(addr), {"ok": True})
        self.assertEqual(len(self.mailer.sent), before)               # no email went out for any of them
        self.svc.register("p@example.com", PW, "P")
        n = len(self.mailer.sent)
        self.svc.resend_code("p@example.com")
        self.assertEqual(len(self.mailer.sent), n + 1)

    def test_old_unverified_signups_are_cleaned_up(self):
        self.svc.register("ghost@example.com", PW, "Ghost")
        with self.svc.tx() as c:
            c.execute("UPDATE users SET created_at='2000-01-01T00:00:00+00:00'")
        self.svc.register("new@example.com", PW, "New")
        with self.svc._lock:
            emails = [r["email"] for r in self.svc._conn.execute("SELECT email FROM users")]
        self.assertEqual(emails, ["new@example.com"])

    def test_login_errors_and_throttle(self):
        self.signup("a@example.com")
        self.assertEqual(self.err(self.svc.login, "a@example.com", "wrong-password").status, 401)
        self.assertEqual(self.err(self.svc.login, "nobody@example.com", PW).message, "Wrong email or password.")
        for _ in range(config.LOGIN_MAX_FAILURES):
            self.err(self.svc.login, "a@example.com", "wrong-password")
        self.assertEqual(self.err(self.svc.login, "a@example.com", PW).status, 429)

    def test_logout_and_expired_session_code(self):
        t = self.signup()["token"]
        self.svc.logout(t)
        e = self.err(self.svc.authenticate, t)
        self.assertEqual((e.status, e.code), (401, "session_expired"))
        self.assertEqual(self.err(self.svc.authenticate, None).code, "session_expired")

    # ---- Google
    def test_google_creates_and_reuses_an_account(self):
        r = self.svc.google_login("fake:sub1:gina@example.com:Gina:true")
        u = r["user"]
        self.assertEqual((u["name"], u["email"], u["email_verified"], u["has_password"], u["google_linked"]),
                         ("Gina", "gina@example.com", True, False, True))
        again = self.svc.google_login("fake:sub1:gina@example.com:Gina:true")
        self.assertEqual(again["user"]["id"], u["id"])
        self.assertEqual(self.svc.authenticate(again["token"])["id"], u["id"])
        self.assertEqual(self.mailer.sent, [])                     # Google already proved the address

    def test_google_rejects_bad_tokens_and_unverified_emails(self):
        self.assertEqual(self.err(self.svc.google_login, "garbage").status, 401)
        self.assertEqual(self.err(self.svc.google_login, "fake:s:x@example.com:X:false").status, 401)
        off = Service(":memory:", mailer=self.mailer, google_client_id="")
        self.assertEqual(self.err(off.google_login, "fake:s:x@example.com:X:true").status, 503)
        self.assertIsNone(off.public_config()["google_client_id"])
        off.close()

    def test_google_links_to_an_existing_account_with_the_same_email(self):
        uid = self.signup("a@example.com")["user"]["id"]
        r = self.svc.google_login("fake:subA:a@example.com:Asha G:true")
        self.assertEqual(r["user"]["id"], uid)
        self.assertTrue(r["user"]["has_password"] and r["user"]["google_linked"])
        self.assertEqual(self.svc.login("a@example.com", PW)["user"]["id"], uid)   # password still works
        e = self.err(self.svc.google_login, "fake:otherSub:a@example.com:Imposter:true")
        self.assertEqual(e.status, 409)                                            # different Google account, same email

    def test_google_signin_defeats_someone_who_squatted_the_address(self):
        self.svc.register("victim@example.com", "squatterpass1", "Squatter")      # never verified
        r = self.svc.google_login("fake:victimSub:victim@example.com:Victim:true")
        self.assertTrue(r["user"]["email_verified"])
        e = self.err(self.svc.login, "victim@example.com", "squatterpass1")
        self.assertEqual(e.status, 401)                                           # the squatter's password is gone

    def test_google_only_account_gets_a_helpful_message_on_password_login(self):
        self.svc.google_login("fake:sub1:gina@example.com:Gina:true")
        e = self.err(self.svc.login, "gina@example.com", PW)
        self.assertEqual(e.status, 401)
        self.assertIn("Google", e.message)

    # ---- forgot / reset password
    def test_forgot_and_reset_password(self):
        r = self.signup("a@example.com")
        second = self.svc.login("a@example.com", PW)                              # another device
        self.assertEqual(self.svc.forgot_password("nobody@example.com"), {"ok": True})
        self.assertEqual(self.mailer.count("nobody@example.com"), 0)
        self.svc.forgot_password("a@example.com")
        code = self.mailer.last_code("a@example.com")
        self.assertEqual(self.err(self.svc.reset_password, "a@example.com", "000000" if code != "000000" else "111111", "newpassword1").status, 400)
        self.assertEqual(self.err(self.svc.reset_password, "a@example.com", code, "short").status, 400)
        self.svc.reset_password("a@example.com", code, "newpassword1")            # the short try did not burn the code
        self.assertEqual(self.err(self.svc.reset_password, "a@example.com", code, "anotherpass1").status, 400)
        self.assertEqual(self.err(self.svc.login, "a@example.com", PW).status, 401)
        self.svc.login("a@example.com", "newpassword1")
        for t in (r["token"], second["token"]):
            self.assertEqual(self.err(self.svc.authenticate, t).status, 401)      # signed out everywhere

    def test_google_user_can_add_a_password_through_reset(self):
        self.svc.google_login("fake:sub1:gina@example.com:Gina:true")
        self.svc.forgot_password("gina@example.com")
        self.svc.reset_password("gina@example.com", self.mailer.last_code("gina@example.com"), "ginapassword1")
        u = self.svc.login("gina@example.com", "ginapassword1")["user"]
        self.assertTrue(u["has_password"] and u["google_linked"])

    def test_reset_also_verifies_the_address(self):
        self.svc.register("a@example.com", PW, "A")                                # still unverified
        self.svc.forgot_password("a@example.com")
        self.svc.reset_password("a@example.com", self.mailer.last_code("a@example.com"), "newpassword1")
        self.assertTrue(self.svc.login("a@example.com", "newpassword1")["user"]["email_verified"])

    # ---- profile, email, password
    def test_update_name(self):
        r = self.signup()
        u = self.svc.authenticate(r["token"])
        self.assertEqual(self.svc.update_name(u, "  New Name ")["user"]["name"], "New Name")
        self.assertEqual(self.err(self.svc.update_name, u, "").status, 400)
        self.assertEqual(self.err(self.svc.update_name, u, "x" * 61).status, 400)

    def test_change_email_needs_password_and_a_code_sent_to_the_new_address(self):
        self.signup("other@example.com")
        r = self.signup("a@example.com")
        u = self.svc.authenticate(r["token"])
        self.assertEqual(self.err(self.svc.request_email_change, u, "new@example.com", "wrong-pass").status, 403)
        self.assertEqual(self.err(self.svc.request_email_change, u, "other@example.com", PW).status, 409)
        self.assertEqual(self.err(self.svc.request_email_change, u, "a@example.com", PW).status, 400)
        self.assertEqual(self.err(self.svc.request_email_change, u, "new@gmial.com", PW).status, 400)
        self.assertEqual(self.mailer.count("new@example.com"), 0)
        self.svc.request_email_change(u, "new@example.com", PW)
        code = self.mailer.last_code("new@example.com")
        self.assertEqual(self.err(self.svc.confirm_email_change, u, "new@example.com", "000000" if code != "000000" else "111111").status, 400)
        stranger = self.svc.authenticate(self.signup("c@example.com")["token"])
        self.svc.request_email_change(u, "new@example.com", PW)                    # fresh code replaces the old one
        code = self.mailer.last_code("new@example.com")
        self.assertEqual(self.err(self.svc.confirm_email_change, stranger, "new@example.com", code).status, 400)
        self.svc.request_email_change(u, "new@example.com", PW)
        done = self.svc.confirm_email_change(u, "new@example.com", self.mailer.last_code("new@example.com"))
        self.assertEqual(done["user"]["email"], "new@example.com")
        self.svc.login("new@example.com", PW)
        self.assertEqual(self.err(self.svc.login, "a@example.com", PW).status, 401)

    def test_google_accounts_cannot_change_email(self):
        u = self.svc.authenticate(self.svc.google_login("fake:s:g@example.com:G:true")["token"])
        self.assertEqual(self.err(self.svc.request_email_change, u, "x@example.com", "whatever1").status, 400)

    def test_change_password(self):
        r = self.signup("a@example.com")
        other = self.svc.login("a@example.com", PW)
        u = self.svc.authenticate(r["token"])
        self.assertEqual(self.err(self.svc.change_password, u, r["token"], "wrong-old", "newpassword1").status, 403)
        self.assertEqual(self.err(self.svc.change_password, u, r["token"], PW, "short").status, 400)
        self.svc.change_password(u, r["token"], PW, "newpassword1")
        self.assertEqual(self.svc.authenticate(r["token"])["email"], "a@example.com")   # this device stays in
        self.assertEqual(self.err(self.svc.authenticate, other["token"]).status, 401)    # others are signed out
        g = self.svc.authenticate(self.svc.google_login("fake:s:g@example.com:G:true")["token"])
        self.assertEqual(self.err(self.svc.change_password, g, "x", "a", "newpassword1").status, 400)

    # ---- devices
    def test_devices_list_and_sign_out(self):
        first = self.signup("a@example.com")
        self.svc.logout(first["token"])
        a = self.svc.login("a@example.com", PW, "Mozilla/5.0 (Macintosh) Chrome/120")
        b = self.svc.login("a@example.com", PW, "Mozilla/5.0 (iPhone) Safari")
        u = self.svc.authenticate(a["token"])
        devices = self.svc.list_devices(u, a["token"])["devices"]
        self.assertEqual(len(devices), 2)
        self.assertEqual([d["current"] for d in devices].count(True), 1)
        mine = next(d for d in devices if d["current"])
        other = next(d for d in devices if not d["current"])
        self.assertIn("Chrome", mine["user_agent"])
        self.assertEqual(self.err(self.svc.revoke_device, u, a["token"], mine["id"]).status, 400)
        self.assertEqual(self.err(self.svc.revoke_device, u, a["token"], "0" * 16).status, 404)
        stranger = self.svc.authenticate(self.signup("z@example.com")["token"])
        self.assertEqual(self.err(self.svc.revoke_device, stranger, "x", other["id"]).status, 404)
        self.svc.revoke_device(u, a["token"], other["id"])
        self.assertEqual(self.err(self.svc.authenticate, b["token"]).status, 401)
        c = self.svc.login("a@example.com", PW)
        self.svc.revoke_other_devices(u, a["token"])
        self.assertEqual(self.err(self.svc.authenticate, c["token"]).status, 401)
        self.svc.authenticate(a["token"])

    # ---- delete account
    def test_delete_account(self):
        owner_tok = self.signup("owner@example.com", name="Owner")
        owner = self.svc.authenticate(owner_tok["token"])
        friend = self.svc.authenticate(self.signup("friend@example.com", name="Friend")["token"])
        s = self.svc.create_session(owner, "Pay check", 2)
        self.svc.join(owner, s["code"], "A" * 300)
        self.svc.join(friend, s["code"], "B" * 300)
        self.assertEqual(self.err(self.svc.delete_account, owner, owner_tok["token"], "wrong-pass").status, 403)
        e = self.err(self.svc.delete_account, owner, owner_tok["token"], PW)        # a run is in progress
        self.assertEqual(e.status, 409)
        self.assertIn("Pay check", e.message)
        g = self.svc.authenticate(self.svc.google_login("fake:s:g@example.com:G:true")["token"])
        self.assertEqual(self.err(self.svc.delete_account, g, "x", "anything").status, 400)   # no password yet
        # finish the session, then deleting works and the friend keeps the result
        ct = "C" * 344
        for u in (owner, friend):
            self.svc.submit_shares(u, s["id"], [{"to_idx": 1, "ciphertext": ct}, {"to_idx": 2, "ciphertext": ct}])
        self.svc.submit_partial(owner, s["id"], "5")
        self.svc.submit_partial(friend, s["id"], "7")
        self.svc.delete_account(owner, owner_tok["token"], PW)
        self.assertEqual(self.err(self.svc.authenticate, owner_tok["token"]).status, 401)
        self.assertEqual(self.err(self.svc.login, "owner@example.com", PW).status, 401)
        seen = self.svc.get_session(friend, s["id"])
        self.assertEqual(seen["result"]["sum"], "12")
        self.assertEqual([p["name"] for p in seen["participants"]], ["Deleted user", "Friend"])
        self.assertEqual(seen["creator_name"], "Deleted user")
        self.signup("owner@example.com", name="Owner again")                      # the address is free again

    def test_public_config(self):
        cfg = self.svc.public_config()
        self.assertEqual(cfg, {"google_client_id": "test-client", "email_delivery": "smtp"})

    # ---- databases from older versions
    def test_old_database_is_upgraded_and_old_accounts_keep_working(self):
        path = os.path.join(tempfile.mkdtemp(), "old.db")
        con = sqlite3.connect(path)
        con.executescript("""
            CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE tokens (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at REAL NOT NULL);
        """)
        con.execute("INSERT INTO users(email,name,pw_hash,created_at) VALUES (?,?,?,?)",
                    ("old@example.com", "Old", security.hash_password(PW), "2025-01-01T00:00:00+00:00"))
        con.commit(); con.close()
        svc = Service(path, mailer=self.mailer)
        r = svc.login("old@example.com", PW, "UA")
        self.assertTrue(r["user"]["email_verified"])         # existing accounts are trusted
        self.assertEqual(len(svc.list_devices(svc.authenticate(r["token"]), r["token"])["devices"]), 1)
        svc.close()


if __name__ == "__main__":
    unittest.main()
