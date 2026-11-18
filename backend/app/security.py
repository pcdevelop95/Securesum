
"""Password hashing and token helpers (standard library only)."""
import hashlib
import hmac
import secrets

from . import config


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, config.PBKDF2_ITERATIONS
    )
    return f"pbkdf2${config.PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


# A fixed hash used to keep login timing similar for unknown emails.
DUMMY_HASH = hash_password("not-a-real-password")


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    """Tokens are stored hashed, so a leaked database cannot be used to log in."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
