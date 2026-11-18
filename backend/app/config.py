#System ki security aur configuration settings load karna, participants ki limit set
#  karna aur .env file se required values read karna
"""Central settings for SecureSum. Override with environment variables or a .env file."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]          # .../securesum


def _load_dotenv(path):
    """Tiny .env reader (KEY=value lines). Real environment variables win."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


_load_dotenv(BASE_DIR / ".env")
DB_PATH = os.environ.get("SECURESUM_DB", str(BASE_DIR / "data" / "securesum.db"))
FRONTEND_DIR = Path(os.environ.get("SECURESUM_FRONTEND", str(BASE_DIR / "frontend")))

# Public prime modulus for additive secret sharing: 2^61 - 1 (a Mersenne prime).
MODULUS = 2 ** 61 - 1
MAX_PARTIES = 50
# Largest value one party may submit, after scaling by 10^decimals.
# MAX_PARTIES * MAX_SCALED_VALUE must stay far below MODULUS so the sum never wraps.
MAX_SCALED_VALUE = 10 ** 15

TOKEN_TTL_SECONDS = 7 * 24 * 3600
PBKDF2_ITERATIONS = 240_000
LOGIN_MAX_FAILURES = 10          # per email
LOGIN_WINDOW_SECONDS = 600
MAX_BODY_BYTES = 200_000

# Google sign-in (leave empty to hide the Google button)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()

# E-mail verification codes
CODE_TTL_SECONDS = 15 * 60
CODE_COOLDOWN_SECONDS = 60       # minimum gap between two codes for the same address
CODE_MAX_PER_HOUR = 5
CODE_MAX_ATTEMPTS = 5            # wrong guesses allowed per code
UNVERIFIED_ACCOUNT_TTL_SECONDS = 2 * 24 * 3600
