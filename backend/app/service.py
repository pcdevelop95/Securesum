#Database accounts, OTPs, sessions, and protocol rules (waiting, sharing,
#  summing, and done)
"""SecureSum core logic (framework independent).

The server never sees a raw value. It only stores:
  * public keys (one per party, created in the browser),
  * encrypted shares (RSA-OAEP ciphertexts it cannot read),
  * partial sums (sums of shares, which look random on their own).

Protocol (matches the presentation):
  1 Setup            creator picks n parties, sum or average, decimals
  2 Input sharing    every party splits its value into n shares, encrypts share j for party j
  3 Local sum        every party decrypts the n shares addressed to it and adds them mod p
  4 Share exchange   every party publishes only that partial sum
  5 Reconstruction   server adds the n partial sums mod p -> result
"""
import base64
import binascii
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config, security
from .mailer import Mailer

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
# Very common typos of big mail providers. Catching them saves people from waiting for a code that never comes.
TYPO_DOMAINS = {
    "gmial.com": "gmail.com", "gmai.com": "gmail.com", "gmail.con": "gmail.com", "gamil.com": "gmail.com",
    "gmail.co": "gmail.com", "gmal.com": "gmail.com", "gnail.com": "gmail.com", "gmail.cm": "gmail.com",
    "gmaill.com": "gmail.com", "gmail.om": "gmail.com", "gmail.comm": "gmail.com", "gmail.in": "gmail.com",
    "hotmial.com": "hotmail.com", "hotmail.con": "hotmail.com", "yahooo.com": "yahoo.com",
    "yaho.com": "yahoo.com", "yahoo.con": "yahoo.com", "outlok.com": "outlook.com", "outlook.con": "outlook.com",
}
B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
CODE_RE = re.compile(r"^[a-z0-9]{6,20}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    google_sub TEXT,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at REAL NOT NULL,
    created_at REAL,
    last_used REAL,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS email_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    user_id INTEGER,
    code_hash TEXT NOT NULL,
    expires_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    creator_id INTEGER NOT NULL REFERENCES users(id),
    n_parties INTEGER NOT NULL,
    metric TEXT NOT NULL,
    decimals INTEGER NOT NULL,
    modulus TEXT NOT NULL,
    result TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    idx INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    shares_submitted INTEGER NOT NULL DEFAULT 0,
    partial TEXT,
    joined_at TEXT NOT NULL,
    UNIQUE (session_id, user_id),
    UNIQUE (session_id, idx)
);
CREATE TABLE IF NOT EXISTS shares (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    from_idx INTEGER NOT NULL,
    to_idx INTEGER NOT NULL,
    ciphertext TEXT NOT NULL,
    PRIMARY KEY (session_id, from_idx, to_idx)
);
CREATE TABLE IF NOT EXISTS hidden (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, session_id)
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    event TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    at TEXT NOT NULL
);
"""


class AppError(Exception):
    def __init__(self, status: int, message: str, code: str = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code            # machine-readable reason, e.g. "email_not_verified"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fmt_fixed(num: int, den: int, places: int) -> str:
    """Exact decimal string for num/den rounded half-up to `places` digits."""
    scale = 10 ** places
    q = (num * scale * 2 + den) // (2 * den)
    whole, frac = divmod(q, scale)
    return str(whole) if places == 0 else f"{whole}.{frac:0{places}d}"


class Service:
    def __init__(self, db_path: str = None, mailer=None, google_client_id: str = None):
        db_path = db_path or config.DB_PATH
        self.mailer = mailer or Mailer()
        self.google_client_id = config.GOOGLE_CLIENT_ID if google_client_id is None else google_client_id
        self.google_verifier = None          # tests plug in a fake; None means "ask Google for real"
        if db_path != ":memory:":
            import os
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            db_path, check_same_thread=False, isolation_level=None, timeout=30
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        if db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._failures = {}   # email -> [timestamps] of failed logins
        self._code_times = {}  # email -> [timestamps] of codes sent

    # ------------------------------------------------------------------ db
    def _columns(self, table):
        return {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}

    def _migrate(self):
        """Upgrade databases created by older versions."""
        users = self._columns("users")
        if "email_verified" not in users:      # accounts that existed before verification are trusted
            self._conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1")
        if "google_sub" not in users:
            self._conn.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        if "deleted" not in users:
            self._conn.execute("ALTER TABLE users ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0")
        tokens = self._columns("tokens")
        for col, kind in (("created_at", "REAL"), ("last_used", "REAL"), ("user_agent", "TEXT")):
            if col not in tokens:
                self._conn.execute(f"ALTER TABLE tokens ADD COLUMN {col} {kind}")
        self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub ON users(google_sub)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS email_codes_lookup ON email_codes(email, purpose)")

    @contextmanager
    def tx(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def close(self):
        with self._lock:
            self._conn.close()

    # ---------------------------------------------------------------- auth
    def public_config(self):
        return {"google_client_id": self.google_client_id or None,
                "email_delivery": "smtp" if self.mailer.configured else "console"}

    @staticmethod
    def _user_dict(row):
        return {"id": row["id"], "name": row["name"], "email": row["email"],
                "email_verified": bool(row["email_verified"]), "has_password": bool(row["pw_hash"]),
                "google_linked": bool(row["google_sub"]), "created_at": row["created_at"]}

    @staticmethod
    def _clean_email(email, check_typo=True):
        email = (email or "").strip().lower()
        if len(email) > 120 or not EMAIL_RE.match(email) or ".." in email:
            raise AppError(400, "Enter a valid email address.")
        if check_typo:
            local, domain = email.rsplit("@", 1)
            fix = TYPO_DOMAINS.get(domain)
            if fix:
                raise AppError(400, f"Did you mean {local}@{fix}? Please check the spelling of your email.")
        return email

    @staticmethod
    def _clean_password(password):
        password = password or ""
        if len(password) < 8 or len(password) > 200:
            raise AppError(400, "Password must be 8 to 200 characters.")
        return password

    @staticmethod
    def _clean_name(name):
        name = (name or "").strip()
        if not 1 <= len(name) <= 60:
            raise AppError(400, "Name must be 1 to 60 characters.")
        return name

    def register(self, email, password, name):
        """Creates an UNVERIFIED account and e-mails a 6-digit code. No login until the code is entered."""
        email = self._clean_email(email)
        password = self._clean_password(password)
        name = self._clean_name(name)
        pw_hash = security.hash_password(password)       # slow, done outside the lock
        cutoff = datetime.fromtimestamp(time.time() - config.UNVERIFIED_ACCOUNT_TTL_SECONDS,
                                        timezone.utc).isoformat(timespec="seconds")
        with self.tx() as c:
            c.execute("DELETE FROM users WHERE email_verified=0 AND deleted=0 AND created_at < ?", (cutoff,))
            row = c.execute("SELECT id, email_verified FROM users WHERE email=? AND deleted=0", (email,)).fetchone()
            if row and row["email_verified"]:
                raise AppError(409, "This email is already registered. Log in, or use 'Forgot password'.")
            if row:       # someone started signing up with this address before: the newest attempt wins
                c.execute("UPDATE users SET name=?, pw_hash=? WHERE id=?", (name, pw_hash, row["id"]))
                uid = row["id"]
            else:
                uid = c.execute(
                    "INSERT INTO users(email, name, pw_hash, created_at, email_verified) VALUES (?,?,?,?,0)",
                    (email, name, pw_hash, now_iso())).lastrowid
        self._send_code(email, "verify", uid)
        return {"needs_verification": True, "email": email}

    def verify_email(self, email, code, user_agent=""):
        email = self._clean_email(email, check_typo=False)
        row = self._check_code(email, "verify", code)
        with self.tx() as c:
            u = c.execute("SELECT id FROM users WHERE id=? AND email=? AND deleted=0",
                          (row["user_id"], email)).fetchone()
            if not u:
                raise AppError(400, "That code is wrong or has expired.")
            c.execute("UPDATE users SET email_verified=1 WHERE id=?", (u["id"],))
        return self._login_result(u["id"], user_agent)

    def resend_code(self, email):
        """Always answers ok, so it cannot be used to find out which addresses have accounts."""
        try:
            email = self._clean_email(email, check_typo=False)
        except AppError:
            return {"ok": True}
        self._rate_check(email)
        with self._lock:
            u = self._conn.execute("SELECT id, email_verified FROM users WHERE email=? AND deleted=0",
                                   (email,)).fetchone()
        if u and not u["email_verified"]:
            self._send_code(email, "verify", u["id"], rate=False)
        return {"ok": True}

    def login(self, email, password, user_agent=""):
        email = (email or "").strip().lower()
        password = password or ""
        self._check_throttle(email)
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE email=? AND deleted=0", (email,)).fetchone()
        has_pw = bool(row and row["pw_hash"])
        ok = security.verify_password(password, row["pw_hash"] if has_pw else security.DUMMY_HASH) and has_pw
        if not ok:
            self._record_failure(email)
            if row and not has_pw and row["google_sub"]:
                raise AppError(401, "This account signs in with Google. Use the Google button, "
                                    "or choose 'Forgot password' to add a password.")
            raise AppError(401, "Wrong email or password.")
        if not row["email_verified"]:
            try:
                self._send_code(email, "verify", row["id"])
            except AppError:
                pass            # a code was sent a moment ago
            raise AppError(403, "Please verify your email first. We sent you a 6-digit code.",
                           code="email_not_verified")
        self._failures.pop(email, None)
        return self._login_result(row["id"], user_agent)

    def google_login(self, credential, user_agent=""):
        if not self.google_client_id:
            raise AppError(503, "Google sign-in is not set up on this server.")
        claims = (self.google_verifier or self._default_google_verifier)(credential)
        sub = str(claims.get("sub") or "")
        email = (claims.get("email") or "").strip().lower()
        if not sub or not email or claims.get("email_verified") not in (True, "true"):
            raise AppError(401, "Your Google email address is not verified.")
        name = ((claims.get("name") or email.split("@")[0]).strip() or "User")[:60]
        with self.tx() as c:
            u = c.execute("SELECT * FROM users WHERE google_sub=? AND deleted=0", (sub,)).fetchone()
            if not u:
                u = c.execute("SELECT * FROM users WHERE email=? AND deleted=0", (email,)).fetchone()
                if u:
                    if u["google_sub"] and u["google_sub"] != sub:
                        raise AppError(409, "This email is linked to a different Google account.")
                    # Google proves the owner of this address. If somebody else had started a password
                    # signup here and never verified it, their password is thrown away.
                    if not u["email_verified"]:
                        c.execute("UPDATE users SET pw_hash='' WHERE id=?", (u["id"],))
                    c.execute("UPDATE users SET google_sub=?, email_verified=1 WHERE id=?", (sub, u["id"]))
                    uid = u["id"]
                else:
                    uid = c.execute(
                        "INSERT INTO users(email, name, pw_hash, created_at, email_verified, google_sub) "
                        "VALUES (?,?,?,?,1,?)", (email, name, "", now_iso(), sub)).lastrowid
            else:
                uid = u["id"]
        return self._login_result(uid, user_agent)

    def _default_google_verifier(self, credential):
        try:
            from google.auth.transport import requests as g_requests
            from google.oauth2 import id_token
        except ImportError:
            raise AppError(503, "Google sign-in needs the 'google-auth' package: pip install google-auth requests")
        try:
            claims = id_token.verify_oauth2_token(credential, g_requests.Request(), self.google_client_id)
        except Exception:
            raise AppError(401, "Google sign-in failed. Please try again.")
        if claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
            raise AppError(401, "Google sign-in failed. Please try again.")
        return claims

    def forgot_password(self, email):
        """Always answers ok (no hint whether the address has an account)."""
        try:
            email = self._clean_email(email, check_typo=False)
        except AppError:
            return {"ok": True}
        self._rate_check(email)
        with self._lock:
            u = self._conn.execute("SELECT id FROM users WHERE email=? AND deleted=0", (email,)).fetchone()
        if u:
            self._send_code(email, "reset", u["id"], rate=False)
        return {"ok": True}

    def reset_password(self, email, code, new_password):
        email = self._clean_email(email, check_typo=False)
        new_password = self._clean_password(new_password)      # checked first, so a typo does not burn the code
        row = self._check_code(email, "reset", code)
        pw_hash = security.hash_password(new_password)
        with self.tx() as c:
            u = c.execute("SELECT id FROM users WHERE id=? AND email=? AND deleted=0",
                          (row["user_id"], email)).fetchone()
            if not u:
                raise AppError(400, "That code is wrong or has expired.")
            c.execute("UPDATE users SET pw_hash=?, email_verified=1 WHERE id=?", (pw_hash, u["id"]))
            c.execute("DELETE FROM tokens WHERE user_id=?", (u["id"],))      # sign out everywhere
        self._failures.pop(email, None)
        return {"ok": True}

    def logout(self, token):
        if token:
            with self.tx() as c:
                c.execute("DELETE FROM tokens WHERE token_hash=?", (security.token_digest(token),))
        return {"ok": True}

    def authenticate(self, token):
        if not token:
            raise AppError(401, "Please log in.", code="session_expired")
        with self._lock:
            row = self._conn.execute(
                "SELECT u.id, u.name, u.email, u.email_verified, u.pw_hash, u.google_sub, u.created_at, "
                "u.deleted, t.expires_at, t.last_used FROM tokens t JOIN users u ON u.id = t.user_id "
                "WHERE t.token_hash=?", (security.token_digest(token),)).fetchone()
        if not row or row["expires_at"] < time.time() or row["deleted"] or not row["email_verified"]:
            raise AppError(401, "Your login has expired. Please log in again.", code="session_expired")
        now = time.time()
        if now - (row["last_used"] or 0) > 300:         # remember when a device was last active
            with self.tx() as c:
                c.execute("UPDATE tokens SET last_used=? WHERE token_hash=?", (now, security.token_digest(token)))
        return self._user_dict(row)

    def _login_result(self, user_id, user_agent=""):
        token = self._issue_token(user_id, user_agent)
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return {"token": token, "user": self._user_dict(row)}

    def _issue_token(self, user_id, user_agent=""):
        token = security.new_token()
        now = time.time()
        with self.tx() as c:
            c.execute("DELETE FROM tokens WHERE expires_at < ?", (now,))
            c.execute(
                "INSERT INTO tokens(token_hash, user_id, expires_at, created_at, last_used, user_agent) "
                "VALUES (?,?,?,?,?,?)",
                (security.token_digest(token), user_id, now + config.TOKEN_TTL_SECONDS, now, now,
                 (user_agent or "")[:200]))
        return token

    def _check_throttle(self, email):
        cutoff = time.time() - config.LOGIN_WINDOW_SECONDS
        recent = [t for t in self._failures.get(email, []) if t > cutoff]
        self._failures[email] = recent
        if len(recent) >= config.LOGIN_MAX_FAILURES:
            raise AppError(429, "Too many failed attempts. Try again in a few minutes.")

    def _record_failure(self, email):
        self._failures.setdefault(email, []).append(time.time())

    # ---------------------------------------------------- e-mail codes
    @staticmethod
    def _code_hash(email, purpose, code):
        return hashlib.sha256(f"{email}|{purpose}|{code}".encode("utf-8")).hexdigest()

    def _rate_check(self, email):
        now = time.time()
        if len(self._code_times) > 5000:
            self._code_times = {k: v for k, v in self._code_times.items() if v and v[-1] > now - 3600}
        times = [t for t in self._code_times.get(email, []) if t > now - 3600]
        if times and now - times[-1] < config.CODE_COOLDOWN_SECONDS:
            raise AppError(429, "Please wait a minute before asking for another code.")
        if len(times) >= config.CODE_MAX_PER_HOUR:
            raise AppError(429, "Too many codes requested. Please try again in an hour.")
        times.append(now)
        self._code_times[email] = times

    def _send_code(self, email, purpose, user_id, rate=True):
        if rate:
            self._rate_check(email)
        code = f"{secrets.randbelow(10 ** 6):06d}"
        now = time.time()
        with self.tx() as c:
            c.execute("DELETE FROM email_codes WHERE email=? AND purpose=?", (email, purpose))
            c.execute(
                "INSERT INTO email_codes(email, purpose, user_id, code_hash, expires_at, attempts, created_at) "
                "VALUES (?,?,?,?,?,0,?)",
                (email, purpose, user_id, self._code_hash(email, purpose, code),
                 now + config.CODE_TTL_SECONDS, now))
        minutes = config.CODE_TTL_SECONDS // 60
        subject, intro = {
            "verify": ("Your SecureSum verification code", "Your SecureSum verification code is"),
            "reset": ("Your SecureSum password reset code", "Your SecureSum password reset code is"),
            "email_change": ("Confirm your new SecureSum email", "Your code to confirm this email address for SecureSum is"),
        }[purpose]
        self.mailer.send(email, subject,
                         f"{intro}: {code}\n\nIt expires in {minutes} minutes. "
                         "If you did not ask for this, you can safely ignore this email.")

    def _check_code(self, email, purpose, code):
        """Returns the code row if the code is right (and uses it up). Wrong guesses are counted."""
        code = (code or "").strip()
        with self.tx() as c:          # the counter must be saved even when we then raise, so decide first
            row = c.execute("SELECT * FROM email_codes WHERE email=? AND purpose=?", (email, purpose)).fetchone()
            if not row or row["expires_at"] < time.time():
                if row:
                    c.execute("DELETE FROM email_codes WHERE id=?", (row["id"],))
                outcome = "bad"
            elif row["attempts"] >= config.CODE_MAX_ATTEMPTS:
                c.execute("DELETE FROM email_codes WHERE id=?", (row["id"],))
                outcome = "locked"
            elif not (len(code) == 6 and code.isdigit()
                      and hmac.compare_digest(self._code_hash(email, purpose, code), row["code_hash"])):
                c.execute("UPDATE email_codes SET attempts=attempts+1 WHERE id=?", (row["id"],))
                outcome = "bad"
            else:
                c.execute("DELETE FROM email_codes WHERE id=?", (row["id"],))
                outcome = "ok"
        if outcome == "ok":
            return dict(row)
        if outcome == "locked":
            raise AppError(429, "Too many wrong attempts. Please request a new code.")
        raise AppError(400, "That code is wrong or has expired.")

    # ---------------------------------------------------------- account
    def update_name(self, user, name):
        name = self._clean_name(name)
        with self.tx() as c:
            c.execute("UPDATE users SET name=? WHERE id=?", (name, user["id"]))
            row = c.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        return {"user": self._user_dict(row)}

    def request_email_change(self, user, new_email, password):
        new_email = self._clean_email(new_email)
        with self._lock:
            u = self._conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if u["google_sub"]:
            raise AppError(400, "Your email comes from your Google account, so it cannot be changed here.")
        if not u["pw_hash"]:
            raise AppError(400, "Set a password first.")
        if new_email == u["email"]:
            raise AppError(400, "That is already your email address.")
        self._check_throttle(u["email"])
        if not security.verify_password(password or "", u["pw_hash"]):
            self._record_failure(u["email"])
            raise AppError(403, "Your password is wrong.")
        with self._lock:
            taken = self._conn.execute("SELECT 1 FROM users WHERE email=? AND email_verified=1 AND deleted=0",
                                       (new_email,)).fetchone()
        if taken:
            raise AppError(409, "That email address is already in use.")
        self._send_code(new_email, "email_change", user["id"])
        return {"ok": True, "new_email": new_email}

    def confirm_email_change(self, user, new_email, code):
        new_email = self._clean_email(new_email, check_typo=False)
        row = self._check_code(new_email, "email_change", code)
        if row["user_id"] != user["id"]:
            raise AppError(400, "That code is wrong or has expired.")
        with self.tx() as c:
            other = c.execute("SELECT id, email_verified FROM users WHERE email=? AND id<>?",
                              (new_email, user["id"])).fetchone()
            if other:
                if other["email_verified"]:
                    raise AppError(409, "That email address is already in use.")
                c.execute("DELETE FROM users WHERE id=?", (other["id"],))    # an abandoned, never-verified signup
            c.execute("UPDATE users SET email=? WHERE id=?", (new_email, user["id"]))
            fresh = c.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        return {"user": self._user_dict(fresh)}

    @staticmethod
    def _iso(ts):
        return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None

    def list_devices(self, user, current_token):
        cur = security.token_digest(current_token) if current_token else ""
        with self._lock:
            rows = self._conn.execute(
                "SELECT token_hash, created_at, last_used, user_agent FROM tokens "
                "WHERE user_id=? AND expires_at>? ORDER BY COALESCE(last_used, created_at, 0) DESC",
                (user["id"], time.time())).fetchall()
        return {"devices": [{
            "id": r["token_hash"][:16], "created_at": self._iso(r["created_at"]),
            "last_used": self._iso(r["last_used"] or r["created_at"]),
            "user_agent": r["user_agent"] or "", "current": r["token_hash"] == cur} for r in rows]}

    def revoke_device(self, user, current_token, device_id):
        cur = security.token_digest(current_token) if current_token else ""
        device_id = (device_id or "")[:16]
        with self.tx() as c:
            row = c.execute("SELECT token_hash FROM tokens WHERE user_id=? AND substr(token_hash,1,16)=?",
                            (user["id"], device_id)).fetchone()
            if not row:
                raise AppError(404, "Device not found.")
            if row["token_hash"] == cur:
                raise AppError(400, "Use Log out to sign out of this device.")
            c.execute("DELETE FROM tokens WHERE token_hash=?", (row["token_hash"],))
        return {"ok": True}

    def revoke_other_devices(self, user, current_token):
        cur = security.token_digest(current_token) if current_token else ""
        with self.tx() as c:
            c.execute("DELETE FROM tokens WHERE user_id=? AND token_hash<>?", (user["id"], cur))
        return {"ok": True}

    def delete_account(self, user, current_token, password):
        """Anonymises the account (sessions other people still need keep working). Blocked while the
        person is in a session that is not finished, so nobody else is left waiting for them."""
        with self._lock:
            u = self._conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not u["pw_hash"]:
            raise AppError(400, "Add a password first (Account > Password), then you can delete your account.")
        self._check_throttle(u["email"])
        if not security.verify_password(password or "", u["pw_hash"]):
            self._record_failure(u["email"])
            raise AppError(403, "Your password is wrong.")
        with self.tx() as c:
            rows = c.execute(
                "SELECT DISTINCT s.id FROM sessions s LEFT JOIN participants p ON p.session_id = s.id "
                "WHERE s.creator_id=? OR p.user_id=?", (user["id"], user["id"])).fetchall()
            unfinished = []
            for r in rows:
                s = self._session_row(c, r["id"])
                if self._state(s, self._counts(c, s["id"])) != "done":
                    unfinished.append(s["title"])
            if unfinished:
                shown = ", ".join(f'"{t}"' for t in unfinished[:5]) + (" and more" if len(unfinished) > 5 else "")
                raise AppError(409, f"Finish, leave or delete these sessions first: {shown}.")
            c.execute("UPDATE users SET email=?, name='Deleted user', pw_hash='', google_sub=NULL, "
                      "email_verified=0, deleted=1 WHERE id=?", (f"deleted-{user['id']}@deleted.invalid", user["id"]))
            c.execute("DELETE FROM tokens WHERE user_id=?", (user["id"],))
            c.execute("DELETE FROM hidden WHERE user_id=?", (user["id"],))
            c.execute("DELETE FROM email_codes WHERE user_id=?", (user["id"],))
        return {"ok": True}

    # ------------------------------------------------------------ sessions
    def create_session(self, user, title, n_parties, metric="sum", decimals=0):
        title = (title or "").strip()
        if not 1 <= len(title) <= 80:
            raise AppError(400, "Title must be 1 to 80 characters.")
        if not isinstance(n_parties, int) or isinstance(n_parties, bool) \
                or not 1 <= n_parties <= config.MAX_PARTIES:
            raise AppError(400, f"Number of parties must be 1 to {config.MAX_PARTIES}.")
        if metric not in ("sum", "average"):
            raise AppError(400, "Metric must be 'sum' or 'average'.")
        if not isinstance(decimals, int) or isinstance(decimals, bool) \
                or not 0 <= decimals <= 4:
            raise AppError(400, "Decimals must be 0 to 4.")
        with self.tx() as c:
            for _ in range(20):
                code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))
                if not c.execute("SELECT 1 FROM sessions WHERE code=?", (code,)).fetchone():
                    break
            cur = c.execute(
                "INSERT INTO sessions(code, title, creator_id, n_parties, metric, "
                "decimals, modulus, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (code, title, user["id"], n_parties, metric, decimals,
                 str(config.MODULUS), now_iso()),
            )
            sid = cur.lastrowid
            self._audit(c, sid, user["id"], "session_created", "")
        return self.get_session(user, sid)

    def list_sessions(self, user, archived=False):
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT s.id FROM sessions s "
                "LEFT JOIN participants p ON p.session_id = s.id "
                "WHERE (s.creator_id=? OR p.user_id=?) AND "
                "(CASE WHEN EXISTS(SELECT 1 FROM hidden h WHERE h.user_id=? AND h.session_id=s.id) "
                "THEN 1 ELSE 0 END)=? ORDER BY s.id DESC",
                (user["id"], user["id"], user["id"], 1 if archived else 0),
            ).fetchall()
            out = []
            for r in rows:
                s = self._session_row(self._conn, r["id"])
                counts = self._counts(self._conn, s["id"])
                me = self._conn.execute(
                    "SELECT idx FROM participants WHERE session_id=? AND user_id=?",
                    (s["id"], user["id"]),
                ).fetchone()
                creator = self._conn.execute(
                    "SELECT name FROM users WHERE id=?", (s["creator_id"],)
                ).fetchone()
                out.append({
                    "id": s["id"], "title": s["title"], "n_parties": s["n_parties"],
                    "metric": s["metric"], "joined": counts["joined"],
                    "state": self._state(s, counts), "created_at": s["created_at"],
                    "my_idx": me["idx"] if me else None,
                    "creator_name": creator["name"] if creator else "",
                    "is_creator": s["creator_id"] == user["id"],
                })
        return {"sessions": out}

    def preview_invite(self, user, code):
        code = self._clean_code(code)
        with self._lock:
            s = self._conn.execute("SELECT * FROM sessions WHERE code=?", (code,)).fetchone()
            if not s:
                raise AppError(404, "Invite code not found.")
            counts = self._counts(self._conn, s["id"])
            me = self._conn.execute(
                "SELECT idx FROM participants WHERE session_id=? AND user_id=?",
                (s["id"], user["id"]),
            ).fetchone()
            creator = self._conn.execute(
                "SELECT name FROM users WHERE id=?", (s["creator_id"],)
            ).fetchone()
        return {
            "title": s["title"], "n_parties": s["n_parties"], "metric": s["metric"],
            "decimals": s["decimals"], "joined": counts["joined"],
            "state": self._state(s, counts), "creator_name": creator["name"],
            "my_idx": me["idx"] if me else None,
            "session_id": s["id"] if (me or s["creator_id"] == user["id"]) else None,
        }

    def join(self, user, code, public_key):
        code = self._clean_code(code)
        self._check_public_key(public_key)
        with self.tx() as c:
            s = c.execute("SELECT * FROM sessions WHERE code=?", (code,)).fetchone()
            if not s:
                raise AppError(404, "Invite code not found.")
            if c.execute("SELECT 1 FROM participants WHERE session_id=? AND user_id=?",
                         (s["id"], user["id"])).fetchone():
                raise AppError(409, "You already joined this session.")
            counts = self._counts(c, s["id"])
            if counts["joined"] >= s["n_parties"]:
                raise AppError(409, "This session is already full.")
            idx = counts["joined"] + 1
            c.execute(
                "INSERT INTO participants(session_id, user_id, idx, public_key, joined_at) "
                "VALUES (?,?,?,?,?)",
                (s["id"], user["id"], idx, public_key, now_iso()),
            )
            self._audit(c, s["id"], user["id"], "joined", str(idx))
            if idx == s["n_parties"]:
                self._audit(c, s["id"], None, "all_joined", "")
            sid = s["id"]
        return self.get_session(user, sid)

    def get_session(self, user, sid):
        with self._lock:
            c = self._conn
            s = self._session_row(c, sid)
            me = c.execute("SELECT * FROM participants WHERE session_id=? AND user_id=?",
                           (sid, user["id"])).fetchone()
            if s["creator_id"] != user["id"] and not me:
                raise AppError(404, "Session not found.")
            counts = self._counts(c, sid)
            state = self._state(s, counts)
            people = c.execute(
                "SELECT p.idx, p.public_key, p.shares_submitted, p.partial, u.name "
                "FROM participants p JOIN users u ON u.id = p.user_id "
                "WHERE p.session_id=? ORDER BY p.idx", (sid,)).fetchall()
            creator = c.execute("SELECT name FROM users WHERE id=?",
                                (s["creator_id"],)).fetchone()
            hidden = bool(c.execute(
                "SELECT 1 FROM hidden WHERE user_id=? AND session_id=?",
                (user["id"], sid)).fetchone())
            events = c.execute(
                "SELECT a.event, a.detail, a.at, u.name FROM audit a "
                "LEFT JOIN users u ON u.id = a.user_id WHERE a.session_id=? "
                "ORDER BY a.id", (sid,)).fetchall()
        data = {
            "id": s["id"], "code": s["code"], "title": s["title"],
            "n_parties": s["n_parties"], "metric": s["metric"],
            "decimals": s["decimals"], "modulus": s["modulus"], "state": state,
            "joined": counts["joined"], "created_at": s["created_at"],
            "creator_name": creator["name"],
            "is_creator": s["creator_id"] == user["id"],
            "participants": [{
                "idx": r["idx"], "name": r["name"], "public_key": r["public_key"],
                "shares_sent": bool(r["shares_submitted"]),
                "partial_sent": r["partial"] is not None,
            } for r in people],
            "me": ({"idx": me["idx"], "shares_sent": bool(me["shares_submitted"]),
                    "partial_sent": me["partial"] is not None} if me else None),
            "can_delete": s["creator_id"] == user["id"],
            "can_leave": bool(me) and state == "waiting",
            "hidden": hidden,
            "audit": [{"event": e["event"], "detail": e["detail"], "at": e["at"],
                       "name": e["name"]} for e in events],
            "result": None,
        }
        if state == "done" and s["result"] is not None:
            total = int(s["result"])
            d = s["decimals"]
            data["result"] = {
                "sum": fmt_fixed(total, 10 ** d, d),
                "average": fmt_fixed(total, s["n_parties"] * 10 ** d, d + 2),
                "parties": s["n_parties"],
            }
        return data

    # ------------------------------------------------- manage sessions
    def delete_session(self, user, sid):
        """Only the creator can delete. It removes the session for every party."""
        with self.tx() as c:
            s = self._session_row(c, sid)
            is_member = c.execute("SELECT 1 FROM participants WHERE session_id=? AND user_id=?",
                                  (sid, user["id"])).fetchone()
            if s["creator_id"] != user["id"]:
                if not is_member:
                    raise AppError(404, "Session not found.")
                raise AppError(403, "Only the creator can delete this session. "
                                    "You can remove it from your own list once it is finished.")
            c.execute("DELETE FROM sessions WHERE id=?", (sid,))   # cascades to every table
        return {"ok": True}

    def leave_session(self, user, sid):
        """Leave before all parties have joined. Later parties move up one place."""
        with self.tx() as c:
            s, p = self._participant_ctx(c, user, sid)
            if self._state(s, self._counts(c, sid)) != "waiting":
                raise AppError(409, "You can only leave before all parties have joined.")
            c.execute("DELETE FROM participants WHERE id=?", (p["id"],))
            c.execute("UPDATE participants SET idx=-idx WHERE session_id=? AND idx>?",
                      (sid, p["idx"]))
            c.execute("UPDATE participants SET idx=-idx-1 WHERE session_id=? AND idx<0", (sid,))
            self._audit(c, sid, user["id"], "left", str(p["idx"]))
        return {"ok": True}

    def set_hidden(self, user, sid, hidden):
        """Archive (hide) a finished session from your own dashboard, or restore it."""
        with self.tx() as c:
            s = self._session_row(c, sid)
            is_member = c.execute("SELECT 1 FROM participants WHERE session_id=? AND user_id=?",
                                  (sid, user["id"])).fetchone()
            if s["creator_id"] != user["id"] and not is_member:
                raise AppError(404, "Session not found.")
            if hidden:
                if self._state(s, self._counts(c, sid)) != "done":
                    raise AppError(409, "You can remove a session from your list once it is finished.")
                c.execute("INSERT OR IGNORE INTO hidden(user_id, session_id) VALUES (?,?)",
                          (user["id"], sid))
            else:
                c.execute("DELETE FROM hidden WHERE user_id=? AND session_id=?",
                          (user["id"], sid))
        return {"ok": True}

    def change_password(self, user, current_token, old_password, new_password):
        new_password = self._clean_password(new_password)
        with self._lock:
            row = self._conn.execute("SELECT email, pw_hash FROM users WHERE id=?",
                                     (user["id"],)).fetchone()
        if not row["pw_hash"]:
            raise AppError(400, "This account has no password yet. Use 'Forgot password' to add one.")
        self._check_throttle(row["email"])
        if not security.verify_password(old_password or "", row["pw_hash"]):
            self._record_failure(row["email"])
            raise AppError(403, "Your current password is wrong.")
        new_hash = security.hash_password(new_password)
        keep = security.token_digest(current_token) if current_token else ""
        with self.tx() as c:
            c.execute("UPDATE users SET pw_hash=? WHERE id=?", (new_hash, user["id"]))
            # sign out every other device
            c.execute("DELETE FROM tokens WHERE user_id=? AND token_hash<>?", (user["id"], keep))
        self._failures.pop(row["email"], None)
        return {"ok": True}

    # --------------------------------------------------------- protocol
    def submit_shares(self, user, sid, shares):
        with self.tx() as c:
            s, p = self._participant_ctx(c, user, sid)
            counts = self._counts(c, sid)
            state = self._state(s, counts)
            if p["shares_submitted"]:
                raise AppError(409, "You already sent your shares.")
            if state == "waiting":
                raise AppError(409, "Wait until all parties have joined.")
            if state != "sharing":
                raise AppError(409, "This session is no longer accepting shares.")
            n = s["n_parties"]
            if not isinstance(shares, list) or len(shares) != n:
                raise AppError(400, f"Exactly {n} shares are required.")
            seen = set()
            for item in shares:
                to_idx = item.get("to_idx") if isinstance(item, dict) else None
                ct = item.get("ciphertext") if isinstance(item, dict) else None
                if not isinstance(to_idx, int) or isinstance(to_idx, bool) \
                        or not 1 <= to_idx <= n or to_idx in seen:
                    raise AppError(400, "Each share needs a unique valid recipient.")
                if not isinstance(ct, str) or not 100 <= len(ct) <= 2000 \
                        or not B64_RE.match(ct):
                    raise AppError(400, "A share has an invalid ciphertext.")
                seen.add(to_idx)
            for item in shares:
                c.execute(
                    "INSERT INTO shares(session_id, from_idx, to_idx, ciphertext) "
                    "VALUES (?,?,?,?)", (sid, p["idx"], item["to_idx"], item["ciphertext"]))
            c.execute("UPDATE participants SET shares_submitted=1 WHERE id=?", (p["id"],))
            self._audit(c, sid, user["id"], "shares_submitted", str(p["idx"]))
            if self._counts(c, sid)["submitted"] == n:
                self._audit(c, sid, None, "all_shares_in", "")
        return self.get_session(user, sid)

    def my_shares(self, user, sid):
        with self._lock:
            c = self._conn
            s = self._session_row(c, sid)
            p = c.execute("SELECT * FROM participants WHERE session_id=? AND user_id=?",
                          (sid, user["id"])).fetchone()
            if not p:
                raise AppError(404, "Session not found.")
            state = self._state(s, self._counts(c, sid))
            if state not in ("summing", "done"):
                raise AppError(409, "Shares are available after everyone has sent theirs.")
            rows = c.execute(
                "SELECT from_idx, ciphertext FROM shares WHERE session_id=? AND to_idx=? "
                "ORDER BY from_idx", (sid, p["idx"])).fetchall()
        return {"shares": [{"from_idx": r["from_idx"], "ciphertext": r["ciphertext"]}
                           for r in rows]}

    def submit_partial(self, user, sid, partial):
        with self.tx() as c:
            s, p = self._participant_ctx(c, user, sid)
            counts = self._counts(c, sid)
            state = self._state(s, counts)
            if p["partial"] is not None:
                raise AppError(409, "You already published your partial sum.")
            if state != "summing":
                raise AppError(409, "Partial sums are accepted after all shares are sent.")
            if not isinstance(partial, str) or not re.fullmatch(r"\d{1,20}", partial) \
                    or int(partial) >= int(s["modulus"]):
                raise AppError(400, "Invalid partial sum.")
            c.execute("UPDATE participants SET partial=? WHERE id=?", (partial, p["id"]))
            self._audit(c, sid, user["id"], "partial_submitted", str(p["idx"]))
            parts = c.execute(
                "SELECT partial FROM participants WHERE session_id=?", (sid,)).fetchall()
            if all(r["partial"] is not None for r in parts) and len(parts) == s["n_parties"]:
                total = sum(int(r["partial"]) for r in parts) % int(s["modulus"])
                c.execute("UPDATE sessions SET result=? WHERE id=?", (str(total), sid))
                self._audit(c, sid, None, "result_ready", "")
        return self.get_session(user, sid)

    # ---------------------------------------------------------- helpers
    def _session_row(self, c, sid):
        s = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not s:
            raise AppError(404, "Session not found.")
        return s

    def _participant_ctx(self, c, user, sid):
        s = self._session_row(c, sid)
        p = c.execute("SELECT * FROM participants WHERE session_id=? AND user_id=?",
                      (sid, user["id"])).fetchone()
        if not p:
            raise AppError(404, "Session not found.")
        return s, p

    def _counts(self, c, sid):
        r = c.execute(
            "SELECT COUNT(*) AS joined, "
            "COALESCE(SUM(shares_submitted),0) AS submitted, "
            "COALESCE(SUM(partial IS NOT NULL),0) AS partials "
            "FROM participants WHERE session_id=?", (sid,)).fetchone()
        return {"joined": r["joined"], "submitted": r["submitted"], "partials": r["partials"]}

    @staticmethod
    def _state(s, counts):
        n = s["n_parties"]
        if counts["joined"] < n:
            return "waiting"
        if counts["submitted"] < n:
            return "sharing"
        if counts["partials"] < n:
            return "summing"
        return "done"

    @staticmethod
    def _audit(c, sid, uid, event, detail):
        c.execute("INSERT INTO audit(session_id, user_id, event, detail, at) "
                  "VALUES (?,?,?,?,?)", (sid, uid, event, detail, now_iso()))

    @staticmethod
    def _clean_code(code):
        code = (code or "").strip().lower()
        if not CODE_RE.match(code):
            raise AppError(404, "Invite code not found.")
        return code

    @staticmethod
    def _check_public_key(key):
        if not isinstance(key, str) or not 200 <= len(key) <= 1400 or not B64_RE.match(key):
            raise AppError(400, "Invalid public key.")
        try:
            raw = base64.b64decode(key, validate=True)
        except (binascii.Error, ValueError):
            raise AppError(400, "Invalid public key.")
        if not 150 <= len(raw) <= 1000:
            raise AppError(400, "Invalid public key.")
