"""Test helpers: a mailer that records messages, and a fake Google token verifier."""
import re

from backend.app.service import AppError


class FakeMailer:
    configured = True

    def __init__(self):
        self.sent = []

    def send(self, to, subject, body):
        self.sent.append({"to": to, "subject": subject, "body": body})

    def last_code(self, to):
        for m in reversed(self.sent):
            if m["to"] == to:
                found = re.search(r"\b(\d{6})\b", m["body"])
                if found:
                    return found.group(1)
        return None

    def count(self, to):
        return sum(1 for m in self.sent if m["to"] == to)


def fake_google_verifier(credential):
    """Token format used in tests:  fake:<sub>:<email>:<name>:<true|false>"""
    parts = (credential or "").split(":")
    if len(parts) != 5 or parts[0] != "fake":
        raise AppError(401, "Google sign-in failed. Please try again.")
    return {"sub": parts[1], "email": parts[2], "name": parts[3], "email_verified": parts[4] == "true"}
