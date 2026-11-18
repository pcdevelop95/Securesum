"""Sends e-mail through SMTP. Without SMTP settings it prints the e-mail in the server terminal instead
(useful on your own computer; on a real server you must configure SMTP).

Environment: SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_SECURITY (starttls | ssl | none)
"""
import logging
import os
import smtplib
import sys
import threading
from email.message import EmailMessage

log = logging.getLogger("securesum.mail")


class Mailer:
    def __init__(self):
        self.host = os.environ.get("SMTP_HOST", "").strip()
        self.port = int(os.environ.get("SMTP_PORT", "587") or 587)
        self.user = os.environ.get("SMTP_USER", "").strip()
        self.password = os.environ.get("SMTP_PASSWORD", "")
        self.sender = os.environ.get("SMTP_FROM", "").strip() or self.user or "no-reply@localhost"
        self.security = os.environ.get("SMTP_SECURITY", "starttls").strip().lower()

    @property
    def configured(self):
        return bool(self.host)

    def send(self, to, subject, body):
        if not self.configured:
            bar = "=" * 64
            print(f"\n{bar}\n[SecureSum] E-mail sending is not configured, so this message was NOT sent.\n"
                  f"To: {to}\nSubject: {subject}\n\n{body}\n{bar}\n", file=sys.stderr, flush=True)
            return
        threading.Thread(target=self._send_smtp, args=(to, subject, body), daemon=True).start()

    def _send_smtp(self, to, subject, body):
        try:
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = self.sender, to, subject
            msg.set_content(body)
            if self.security == "ssl":
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=20)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=20)
            with server:
                if self.security == "starttls":
                    server.starttls()
                if self.user:
                    server.login(self.user, self.password)
                server.send_message(msg)
        except Exception:                      # never crash a request because mail failed
            log.exception("Could not send e-mail to %s", to)
