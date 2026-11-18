"""Unit tests for the core service. Run:  python -m unittest discover -s backend/tests -t ."""
import base64
import os
import threading
import unittest

from backend.app import config
from backend.app.service import AppError, Service, fmt_fixed
from backend.tests.helpers import FakeMailer

P = config.MODULUS
FAKE_KEY = base64.b64encode(os.urandom(294)).decode()
FAKE_CT = base64.b64encode(os.urandom(256)).decode()


def shares_payload(n):
    return [{"to_idx": j, "ciphertext": FAKE_CT} for j in range(1, n + 1)]


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self._saved = (config.PBKDF2_ITERATIONS, config.CODE_COOLDOWN_SECONDS)
        config.PBKDF2_ITERATIONS, config.CODE_COOLDOWN_SECONDS = 1000, 0      # fast tests
        self.mailer = FakeMailer()
        self.svc = Service(":memory:", mailer=self.mailer)
        self._n = 0

    def tearDown(self):
        config.PBKDF2_ITERATIONS, config.CODE_COOLDOWN_SECONDS = self._saved
        self.svc.close()

    def user(self, name=None):
        """A registered AND e-mail-verified user (accounts cannot be used before verification)."""
        self._n += 1
        email = f"u{self._n}@example.com"
        self.svc.register(email, "password123", name or f"User{self._n}")
        return self.svc.verify_email(email, self.mailer.last_code(email))["user"]

    # ---- full protocol
    def run_session(self, n, values, decimals=0, metric="sum"):
        """Simulate the protocol with fake ciphertexts; partials are computed from
        plaintext shares that stand in for what the browsers would decrypt."""
        users = [self.user() for _ in range(n)]
        s = self.svc.create_session(users[0], "Test", n, metric, decimals)
        self.assertEqual(s["state"], "waiting")
        for i, u in enumerate(users):
            s = self.svc.join(u, s["code"], FAKE_KEY)
            self.assertEqual(s["me"]["idx"], i + 1)
        self.assertEqual(s["state"], "sharing")
        # each party "splits" its value
        matrix = []
        for i, u in enumerate(users):
            row = [(i * 7919 + j * 104729 + 13) % P for j in range(n - 1)]
            row.append((values[i] - sum(row)) % P)
            matrix.append(row)
            s = self.svc.submit_shares(u, s["id"], shares_payload(n))
        self.assertEqual(s["state"], "summing")
        for j, u in enumerate(users):
            got = self.svc.my_shares(u, s["id"])["shares"]
            self.assertEqual([x["from_idx"] for x in got], list(range(1, n + 1)))
            partial = sum(matrix[i][j] for i in range(n)) % P
            s = self.svc.submit_partial(u, s["id"], str(partial))
        self.assertEqual(s["state"], "done")
        return users, s

    def test_four_parties_example_from_presentation(self):
        users, s = self.run_session(4, [50, 70, 30, 90])
        self.assertEqual(s["result"]["sum"], "240")
        self.assertEqual(s["result"]["average"], "60.00")
        self.assertEqual(s["result"]["parties"], 4)

    def test_decimals(self):
        users, s = self.run_session(3, [123456, 44, 1000], decimals=2)   # 1234.56 + 0.44 + 10.00
        self.assertEqual(s["result"]["sum"], "1245.00")
        self.assertEqual(s["result"]["average"], "415.0000")

    def test_one_party(self):
        users, s = self.run_session(1, [7])
        self.assertEqual(s["result"]["sum"], "7")

    def test_two_parties(self):
        users, s = self.run_session(2, [10, 21])
        self.assertEqual(s["result"]["sum"], "31")
        self.assertEqual(s["result"]["average"], "15.50")

    def test_fifty_parties(self):
        users, s = self.run_session(50, list(range(1, 51)))
        self.assertEqual(s["result"]["sum"], "1275")

    def test_audit_never_contains_values(self):
        users, s = self.run_session(3, [111, 222, 333])
        events = [e["event"] for e in s["audit"]]
        self.assertEqual(events[0], "session_created")
        self.assertIn("all_joined", events)
        self.assertIn("all_shares_in", events)
        self.assertEqual(events[-1], "result_ready")
        text = str(s["audit"])
        for v in ("111", "222", "333"):
            self.assertNotIn(v, text.replace("2026", ""))

    # ---- permissions and state rules
    def test_state_rules(self):
        u1, u2, outsider = self.user(), self.user(), self.user()
        s = self.svc.create_session(u1, "T", 2)
        with self.assertRaises(AppError) as cm:
            self.svc.get_session(outsider, s["id"])
        self.assertEqual(cm.exception.status, 404)
        s = self.svc.join(u1, s["code"], FAKE_KEY)
        with self.assertRaises(AppError) as cm:     # cannot share before all joined
            self.svc.submit_shares(u1, s["id"], shares_payload(2))
        self.assertEqual(cm.exception.status, 409)
        with self.assertRaises(AppError):           # cannot join twice
            self.svc.join(u1, s["code"], FAKE_KEY)
        s = self.svc.join(u2, s["code"], FAKE_KEY)
        with self.assertRaises(AppError) as cm:     # session full
            self.svc.join(outsider, s["code"], FAKE_KEY)
        self.assertEqual(cm.exception.status, 409)
        with self.assertRaises(AppError):           # outsider cannot send shares
            self.svc.submit_shares(outsider, s["id"], shares_payload(2))
        with self.assertRaises(AppError):           # wrong share count
            self.svc.submit_shares(u1, s["id"], shares_payload(3))
        bad = shares_payload(2); bad[1]["to_idx"] = 1
        with self.assertRaises(AppError):           # duplicate recipient
            self.svc.submit_shares(u1, s["id"], bad)
        with self.assertRaises(AppError):           # bad ciphertext
            self.svc.submit_shares(u1, s["id"], [{"to_idx": 1, "ciphertext": "x"}, {"to_idx": 2, "ciphertext": "y"}])
        self.svc.submit_shares(u1, s["id"], shares_payload(2))
        with self.assertRaises(AppError):           # double submit
            self.svc.submit_shares(u1, s["id"], shares_payload(2))
        with self.assertRaises(AppError):           # shares hidden until everyone sent
            self.svc.my_shares(u1, s["id"])
        with self.assertRaises(AppError):           # partial too early
            self.svc.submit_partial(u1, s["id"], "5")
        self.svc.submit_shares(u2, s["id"], shares_payload(2))
        for bad_partial in ("abc", "-1", str(P), "", 5):
            with self.assertRaises(AppError):
                self.svc.submit_partial(u1, s["id"], bad_partial)
        self.svc.submit_partial(u1, s["id"], "5")
        with self.assertRaises(AppError):
            self.svc.submit_partial(u1, s["id"], "5")
        with self.assertRaises(AppError):           # outsider cannot read shares
            self.svc.my_shares(outsider, s["id"])

    def test_creator_not_participant_can_view_but_not_act(self):
        creator, u = self.user(), self.user()
        s = self.svc.create_session(creator, "T", 1)
        self.assertEqual(self.svc.get_session(creator, s["id"])["me"], None)
        self.svc.join(u, s["code"], FAKE_KEY)
        with self.assertRaises(AppError):
            self.svc.submit_shares(creator, s["id"], shares_payload(1))

    def test_validation(self):
        u = self.user()
        for args in [("", 3, "sum", 0), ("T", 0, "sum", 0), ("T", config.MAX_PARTIES + 1, "sum", 0),
                     ("T", 3, "max", 0), ("T", 3, "sum", 9), ("T", True, "sum", 0), ("T", "3", "sum", 0)]:
            with self.assertRaises(AppError):
                self.svc.create_session(u, *args)
        s = self.svc.create_session(u, "T", 3)
        for key in ("short", "!" * 300, 5, "A" * 5000):
            with self.assertRaises(AppError):
                self.svc.join(u, s["code"], key)
        with self.assertRaises(AppError) as cm:
            self.svc.preview_invite(u, "does-not-exist")
        self.assertEqual(cm.exception.status, 404)

    def test_preview_and_list(self):
        a, b = self.user("Alice"), self.user("Bob")
        s = self.svc.create_session(a, "Salaries", 3)
        pv = self.svc.preview_invite(b, s["code"])
        self.assertEqual((pv["title"], pv["joined"], pv["session_id"], pv["creator_name"]),
                         ("Salaries", 0, None, "Alice"))
        self.svc.join(b, s["code"], FAKE_KEY)
        self.assertIsNotNone(self.svc.preview_invite(b, s["code"])["session_id"])
        self.assertEqual(len(self.svc.list_sessions(a)["sessions"]), 1)
        self.assertEqual(len(self.svc.list_sessions(b)["sessions"]), 1)
        self.assertEqual(len(self.svc.list_sessions(self.user())["sessions"]), 0)

    def test_concurrent_joins_get_unique_slots(self):
        n = 12
        users = [self.user() for _ in range(n)]
        s = self.svc.create_session(users[0], "T", n)
        errors = []
        def go(u):
            try:
                self.svc.join(u, s["code"], FAKE_KEY)
            except Exception as e:      # pragma: no cover
                errors.append(e)
        ts = [threading.Thread(target=go, args=(u,)) for u in users]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(errors, [])
        got = self.svc.get_session(users[0], s["id"])
        self.assertEqual(sorted(p["idx"] for p in got["participants"]), list(range(1, n + 1)))

    # ---- manage sessions: delete, leave, archive, password
    def test_delete_session_creator_only(self):
        a, b, outsider = self.user(), self.user(), self.user()
        s = self.svc.create_session(a, "T", 2)
        self.svc.join(a, s["code"], FAKE_KEY)
        self.svc.join(b, s["code"], FAKE_KEY)
        with self.assertRaises(AppError) as cm:          # a participant who is not the creator
            self.svc.delete_session(b, s["id"])
        self.assertEqual(cm.exception.status, 403)
        with self.assertRaises(AppError) as cm:          # an outsider learns nothing
            self.svc.delete_session(outsider, s["id"])
        self.assertEqual(cm.exception.status, 404)
        self.svc.submit_shares(a, s["id"], shares_payload(2))
        self.svc.delete_session(a, s["id"])             # creator, even in the middle of a run
        for u in (a, b):
            with self.assertRaises(AppError) as cm:
                self.svc.get_session(u, s["id"])
            self.assertEqual(cm.exception.status, 404)
            self.assertEqual(self.svc.list_sessions(u)["sessions"], [])
        c = self.svc._conn                               # nothing left behind in any table
        for table in ("participants", "shares", "audit"):
            self.assertEqual(c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0, table)
        with self.assertRaises(AppError):                # the invite code is dead too
            self.svc.preview_invite(b, s["code"])

    def test_leave_renumbers_remaining_parties(self):
        u = [self.user() for _ in range(4)]
        s = self.svc.create_session(u[0], "T", 4)
        for x in u[:3]:
            self.svc.join(x, s["code"], FAKE_KEY)
        self.svc.leave_session(u[1], s["id"])                       # party 2 leaves
        got = self.svc.get_session(u[0], s["id"])
        self.assertEqual([(p["idx"], p["name"]) for p in got["participants"]],
                         [(1, "User1"), (2, "User3")])              # User3 moved up to 2
        self.assertEqual(got["joined"], 2)
        with self.assertRaises(AppError):                           # the one who left no longer sees it
            self.svc.get_session(u[1], s["id"])
        self.svc.join(u[1], s["code"], FAKE_KEY)                    # can come back, gets the next slot
        self.svc.join(u[3], s["code"], FAKE_KEY)
        got = self.svc.get_session(u[0], s["id"])
        self.assertEqual([p["idx"] for p in got["participants"]], [1, 2, 3, 4])
        self.assertEqual(got["state"], "sharing")
        self.assertIn("left", [e["event"] for e in got["audit"]])

    def test_cannot_leave_once_everyone_joined(self):
        u = [self.user() for _ in range(3)]
        s = self.svc.create_session(u[0], "T", 3)
        for x in u:
            self.svc.join(x, s["code"], FAKE_KEY)
        with self.assertRaises(AppError) as cm:
            self.svc.leave_session(u[1], s["id"])
        self.assertEqual(cm.exception.status, 409)

    def test_leave_rules(self):
        a, b = self.user(), self.user()
        s = self.svc.create_session(a, "T", 3)
        with self.assertRaises(AppError):                # not a participant
            self.svc.leave_session(b, s["id"])
        self.svc.join(b, s["code"], FAKE_KEY)
        view = self.svc.get_session(b, s["id"])
        self.assertTrue(view["can_leave"])
        self.assertFalse(view["can_delete"])
        self.assertTrue(self.svc.get_session(a, s["id"])["can_delete"])

    def test_archive_and_restore(self):
        users, s = self.run_session(3, [1, 2, 3])
        a, b = users[0], users[1]
        self.svc.set_hidden(a, s["id"], True)
        self.assertEqual(self.svc.list_sessions(a)["sessions"], [])
        self.assertEqual(len(self.svc.list_sessions(a, archived=True)["sessions"]), 1)
        self.assertEqual(len(self.svc.list_sessions(b)["sessions"]), 1)     # others unaffected
        self.assertTrue(self.svc.get_session(a, s["id"])["hidden"])
        self.assertFalse(self.svc.get_session(b, s["id"])["hidden"])
        self.svc.set_hidden(a, s["id"], False)
        self.assertEqual(len(self.svc.list_sessions(a)["sessions"]), 1)
        self.assertEqual(self.svc.list_sessions(a, archived=True)["sessions"], [])

    def test_archive_requires_finished_session_and_membership(self):
        a, outsider = self.user(), self.user()
        s = self.svc.create_session(a, "T", 2)
        with self.assertRaises(AppError) as cm:
            self.svc.set_hidden(a, s["id"], True)
        self.assertEqual(cm.exception.status, 409)
        with self.assertRaises(AppError) as cm:
            self.svc.set_hidden(outsider, s["id"], True)
        self.assertEqual(cm.exception.status, 404)

    def test_fmt_fixed(self):
        self.assertEqual(fmt_fixed(240, 4, 2), "60.00")
        self.assertEqual(fmt_fixed(1, 3, 2), "0.33")
        self.assertEqual(fmt_fixed(2, 3, 2), "0.67")
        self.assertEqual(fmt_fixed(5, 2, 0), "3")      # half rounds up
        self.assertEqual(fmt_fixed(0, 7, 3), "0.000")


if __name__ == "__main__":
    unittest.main()
