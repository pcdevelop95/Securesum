# SecureSum

**Compute together. Reveal nothing.**
Companies calculate a **total or average** together while every individual number stays private.
Built on Secure Multi-Party Computation (additive secret sharing). Works for **any number of parties (1 to 50)**.

## Quick start (about 2 minutes)

You need **Python 3.10+**. Open a terminal in this folder:

```bash
python -m venv .venv
# Windows:   .venv\Scripts\activate        macOS / Linux:   source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open **http://localhost:8000**. That's it. Data is stored in `data/securesum.db` (SQLite).

**First run without email set up:** when you create an account, the 6-digit code is **printed in the terminal window** where you ran `python run.py` (look for the box with "E-mail sending is not configured"). Type that code in the browser. To send real emails, follow "Email setup" below.

> Important: the browser only allows cryptography on `http://localhost` or on **HTTPS**.
> To use SecureSum from other computers you must serve it over HTTPS (see "Going live").

### Docker instead
```bash
docker compose up --build
```
Then open http://localhost:8000. The database is kept in `./data`.

## What the app can do

- **Dashboard:** your sessions at a glance (total, in progress, completed) with tabs *In progress*, *Completed* and *Archived*, plus a box to join with an invite link or code.
- **New session:** any number of parties (1 to 50), total or average, number of decimals.
- **Session room:** live progress through the 5 protocol steps, parties table with key fingerprints, activity log, key backup.
- **Leave a session:** any party can leave before everyone has joined (later parties move up one place).
- **Delete a session:** the creator can delete it at any time. It disappears for every party.
- **After a session finishes:** download the result as CSV (summary, parties' names, activity log; never anyone's value, shares, keys or e-mails), **run again** with the same settings, or **remove it from your list** (Archived tab, restorable). Other parties keep their own copy.
- **Account:** change password (signs out your other devices).

## Sign-up, email codes and Google sign-in

**Nobody can use an account with an email address they do not own.** After sign-up, a 6-digit code is emailed to that address and the account stays locked until the code is entered. Obvious typos such as `gmial.com` or `gmail.con` are refused immediately. Codes expire after 15 minutes, allow 5 wrong tries, can be requested at most once a minute (5 per hour), and are stored only as hashes. Accounts that are never verified are deleted after 2 days. If somebody signs up with your address but never verifies it, signing in with Google (or resetting the password) on that address removes their password.

### Email setup (sends the codes to real inboxes)

Copy `.env.example` to `.env` and fill in the SMTP details. Example with a Gmail address:

1. In your Google account turn on 2-Step Verification, then create an **App password** at https://myaccount.google.com/apppasswords (16 letters).
2. Put this in `.env`:
   ```
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=yourname@gmail.com
   SMTP_PASSWORD=your-16-letter-app-password
   SMTP_FROM=SecureSum <yourname@gmail.com>
   ```
3. Restart `python run.py`. The warning box at start-up disappears, and codes arrive by email.

Gmail is fine for trying it out (limits apply). For a real company use a transactional email service (Brevo, SendGrid, Amazon SES, Resend...) and send from your own domain with SPF and DKIM set up, so the codes do not land in spam. They all give you SMTP details to paste into `.env`.

### Google sign-in setup ("Continue with Google")

1. Go to https://console.cloud.google.com, create a project.
2. **APIs & Services > OAuth consent screen**: choose *External*, fill in the app name and your support email, save.
3. **APIs & Services > Credentials > Create credentials > OAuth client ID** > *Web application*.
4. Under **Authorized JavaScript origins** add `http://localhost:8000` **and** `http://localhost` (Google needs both for local testing), plus your real `https://yourdomain.com` when you go live. You do not need redirect URIs.
5. Copy the **Client ID** (looks like `1234-abc.apps.googleusercontent.com`) into `.env` as `GOOGLE_CLIENT_ID=...` and restart. A "Continue with Google" button now appears on the login page.
6. While the consent screen is in *Testing* mode only the test users you add can sign in. Click *Publish app* when you are ready for everyone.

Google confirms the email address itself, so Google sign-in needs no code. If an account with the same email already exists it is linked automatically. Accounts created with Google have no password until the person adds one in Account settings.

## Account settings

Profile (name, verified email badge), change email (needs your password and a code sent to the new address), change or add a password, which sign-in methods are on, **devices where you are logged in** (log out one or all others), forgot password (code by email), and **delete account** (needs your password; blocked while you are in an unfinished session; finished sessions stay for the other parties with your name shown as "Deleted user").

## How to use it

1. Everyone creates an account and confirms their email with the 6-digit code (or uses "Continue with Google").
2. One person clicks **New session**: title, **number of parties**, total or average, decimals.
3. That person sends the **invite link** to the other parties. Everyone clicks **Join** (a secret key is created inside their browser).
4. When all parties have joined, each party types its private number and clicks **Split and send encrypted shares**.
5. Everything else is automatic. Each browser adds up the shares sent to it and publishes only that sum.
6. All parties see the same result. Nobody sees anyone else's number.

Tip: on the session page, **download your key backup**. The secret key lives only in your browser; without it (or the backup) you cannot finish a session.
Compare the **key fingerprints** shown in the Parties table with the other parties by phone or chat.

## How it matches the presentation

| Step in the PPT | What happens | Code |
|---|---|---|
| 1 Setup | Creator chooses n, sum/average, decimals; public prime p = 2^61 - 1; each party creates an RSA key pair in the browser | `service.create_session`, `frontend/js/protocol.js` `joinWithNewKey` |
| 2 Input sharing | Value split into n random shares (add up to the value mod p); share j encrypted for party j | `frontend/js/mpc.js` `splitSecret`, `protocol.js` `sendShares` |
| 3 Local computation | Each browser decrypts the n shares addressed to it and adds them mod p | `protocol.js` `sendPartial` |
| 4 Share exchange | Only the partial sum is published | `service.submit_partial` |
| 5 Reconstruction | Server adds the n partial sums mod p; average = sum / n | `service.submit_partial` |

Architecture: **Frontend** (HTML + JavaScript, WebCrypto) → **Backend API** (Python FastAPI) → **Database** (SQLite by default).
The server stores only public keys, encrypted shares and partial sums.

## Folder map

```
backend/app/config.py     settings (prime, limits)
backend/app/service.py    all logic: accounts, sessions, protocol state machine, database
backend/app/main.py       FastAPI routes + security headers + serves the frontend
backend/tests/            unit tests and API tests
frontend/index.html       the page
frontend/js/crypto.js     WebCrypto: key pairs, encrypt/decrypt, fingerprints
frontend/js/mpc.js        secret sharing math
frontend/js/protocol.js   the protocol steps used by the app and the tests
frontend/js/app.js        all screens
tests/                    end-to-end and UI smoke tests (need Node.js)
run.py  Dockerfile  docker-compose.yml  requirements.txt
```

## Going live (a real company using it)

1. **HTTPS is required.** Put SecureSum behind a reverse proxy. Simplest option, [Caddy](https://caddyserver.com):
   ```
   yourdomain.com {
       reverse_proxy localhost:8000
   }
   ```
   Then set `SECURESUM_HTTPS=1` (adds the HSTS header).
2. Run with `HOST=0.0.0.0` (Docker already does) or keep `127.0.0.1` behind the proxy.
3. **Back up the `data/` folder** regularly.
4. Set up **email (SMTP)** and, if you want it, **Google sign-in** (see above). Without SMTP nobody can verify an account except by reading the server's terminal.
5. Environment variables (or `.env`): `HOST`, `PORT`, `SECURESUM_DB` (database path), `SECURESUM_HTTPS=1`, `SECURESUM_DOCS=1` (API docs at `/api/docs`), `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_SECURITY`, `GOOGLE_CLIENT_ID`.

## Security model and honest limits

What is protected: the server, the database and a hacker who steals the database see only encrypted shares and partial sums. A party learns nothing about another party's number beyond what the final result implies.

Limits you should know (and say in your presentation):

- **Fewer than 3 parties:** with 2 parties the result itself reveals the other person's number; with 1 party there is nothing to hide. This is maths, not a bug. The app warns about it.
- **Collusion:** privacy holds unless **all the other n-1 parties** collude against one party.
- **Semi-honest model:** a party that wants to ruin the result could publish a wrong partial sum, and the protocol cannot detect it yet. Stronger versions need commitments or zero-knowledge proofs (roadmap).
- **Key swapping by the server:** a malicious server could give you a different public key for another party. Mitigations built in: your browser refuses to send if the server lists a wrong key for *you*, and fingerprints are shown so parties can compare them out of band.
- **Fake accounts:** one company can create several accounts to occupy several party slots. Share invite links only with parties you trust.
- **Lost key:** if a party loses its key (and has no backup), that session cannot finish.
- **Value range:** each number must be between 0 and 1,000,000,000,000 (scaled by decimals). The server cannot check numbers, so a party could enter an out-of-range value and distort the result.
- **Email codes prove access to a mailbox, not who a person is.** Anyone who can read the inbox can verify the account. Put your own checks (for example only sharing invite links with known colleagues) on top for sensitive use.
- Login rate limiting is per email, kept in memory. SQLite and a single process are fine for a team or a few hundred sessions; for large scale, move to PostgreSQL and add per-IP rate limiting at the proxy.

## Tests

```bash
python tests/run_all.py                                   # everything (needs Node.js 18+ for the browser-code tests)
python -m unittest discover -s backend/tests -t .         # Python tests only (API tests run if FastAPI is installed)
```
The end-to-end test runs the real browser code (WebCrypto + secret sharing) for 1, 2, 3, 4, 5 and 8 parties,
including concurrent joins, wrong keys, backups and access control.

## Roadmap

More statistics (min/max, histograms), CSV export of the activity log, PostgreSQL, proofs against cheating parties, e-mail invites.
# SecureSum
