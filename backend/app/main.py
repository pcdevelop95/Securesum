#All server routes (login, sessions, accounts) and security headers are securely 
# transmitted from the server to the frontend/browser.
"""SecureSum web API (FastAPI). All real logic lives in service.py."""
import mimetypes
import os
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config
from .service import AppError, Service

# Some Windows machines map .js to text/plain, which makes browsers refuse ES modules.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")

svc = Service(config.DB_PATH)

if not svc.mailer.configured:
    print("\n[SecureSum] E-mail is not configured (no SMTP_HOST), so verification codes will be PRINTED IN THIS WINDOW\n"
          "            instead of being emailed. To send real emails, see 'Email setup' in README.md.\n", flush=True)
if svc.google_client_id:
    try:
        import google.oauth2.id_token  # noqa: F401
    except ImportError:
        print("[SecureSum] GOOGLE_CLIENT_ID is set but the 'google-auth' package is missing.\n"
              "            Run: pip install google-auth requests\n", flush=True)

_docs = os.environ.get("SECURESUM_DOCS") == "1"
app = FastAPI(
    title="SecureSum",
    docs_url="/api/docs" if _docs else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if _docs else None,
)


def build_csp(google: bool) -> str:
    """Strict by default. Google's sign-in button needs a few extra Google addresses, added only when enabled."""
    script, style, connect, img, frame = "'self'", "'self'", "'self'", "'self' data:", ""
    if google:
        script += " https://accounts.google.com/gsi/client"
        style += " https://accounts.google.com/gsi/style"
        connect += " https://accounts.google.com/gsi/"
        img += " https://*.googleusercontent.com"
        frame = " frame-src https://accounts.google.com/gsi/;"
    return (f"default-src 'self'; script-src {script}; style-src {style}; img-src {img}; "
            f"connect-src {connect};{frame} base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


CSP = build_csp(bool(svc.google_client_id))


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > config.MAX_BODY_BYTES:
        return JSONResponse({"detail": "Request too large."}, status_code=413)
    response = await call_next(request)
    if not request.url.path.startswith("/api/docs"):      # the interactive docs page loads scripts from a CDN
        response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if os.environ.get("SECURESUM_HTTPS") == "1":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError):
    body = {"detail": exc.message}
    if exc.code:
        body["code"] = exc.code
    return JSONResponse(body, status_code=exc.status)


def _bearer(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def current_user(authorization: Optional[str] = Header(default=None)):
    return svc.authenticate(_bearer(authorization))


# ------------------------------------------------------------------ models
class RegisterIn(BaseModel):
    email: str
    password: str
    name: str


class VerifyIn(BaseModel):
    email: str
    code: str


class EmailIn(BaseModel):
    email: str


class GoogleIn(BaseModel):
    credential: str


class ResetIn(BaseModel):
    email: str
    code: str
    new_password: str


class NameIn(BaseModel):
    name: str


class EmailChangeIn(BaseModel):
    new_email: str
    password: str


class EmailConfirmIn(BaseModel):
    new_email: str
    code: str


class DeviceIn(BaseModel):
    id: str


class DeleteAccountIn(BaseModel):
    password: str


class LoginIn(BaseModel):
    email: str
    password: str


class PasswordIn(BaseModel):
    old_password: str
    new_password: str


class SessionIn(BaseModel):
    title: str
    n_parties: int
    metric: str = "sum"
    decimals: int = 0


class JoinIn(BaseModel):
    public_key: str


class ShareItem(BaseModel):
    to_idx: int
    ciphertext: str


class SharesIn(BaseModel):
    shares: List[ShareItem]


class PartialIn(BaseModel):
    partial: str


# ------------------------------------------------------------------ routes
@app.get("/api/health")
def health():
    return {"ok": True}


def _ua(request: Request) -> str:
    return request.headers.get("user-agent", "")


@app.get("/api/config")
def public_config():
    return svc.public_config()


@app.post("/api/auth/register")
def register(body: RegisterIn):
    return svc.register(body.email, body.password, body.name)


@app.post("/api/auth/verify")
def verify(body: VerifyIn, request: Request):
    return svc.verify_email(body.email, body.code, _ua(request))


@app.post("/api/auth/resend")
def resend(body: EmailIn):
    return svc.resend_code(body.email)


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request):
    return svc.login(body.email, body.password, _ua(request))


@app.post("/api/auth/google")
def google_login(body: GoogleIn, request: Request):
    return svc.google_login(body.credential, _ua(request))


@app.post("/api/auth/forgot")
def forgot(body: EmailIn):
    return svc.forgot_password(body.email)


@app.post("/api/auth/reset")
def reset(body: ResetIn):
    return svc.reset_password(body.email, body.code, body.new_password)


@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    return svc.logout(_bearer(authorization))


@app.post("/api/auth/password")
def change_password(body: PasswordIn, authorization: Optional[str] = Header(default=None),
                    user=Depends(current_user)):
    return svc.change_password(user, _bearer(authorization), body.old_password, body.new_password)


@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"user": user}


@app.post("/api/account/name")
def update_name(body: NameIn, user=Depends(current_user)):
    return svc.update_name(user, body.name)


@app.post("/api/account/email/request")
def email_change_request(body: EmailChangeIn, user=Depends(current_user)):
    return svc.request_email_change(user, body.new_email, body.password)


@app.post("/api/account/email/confirm")
def email_change_confirm(body: EmailConfirmIn, user=Depends(current_user)):
    return svc.confirm_email_change(user, body.new_email, body.code)


@app.get("/api/account/devices")
def devices(authorization: Optional[str] = Header(default=None), user=Depends(current_user)):
    return svc.list_devices(user, _bearer(authorization))


@app.post("/api/account/devices/revoke")
def revoke_device(body: DeviceIn, authorization: Optional[str] = Header(default=None), user=Depends(current_user)):
    return svc.revoke_device(user, _bearer(authorization), body.id)


@app.post("/api/account/devices/revoke-others")
def revoke_others(authorization: Optional[str] = Header(default=None), user=Depends(current_user)):
    return svc.revoke_other_devices(user, _bearer(authorization))


@app.post("/api/account/delete")
def delete_account(body: DeleteAccountIn, authorization: Optional[str] = Header(default=None),
                   user=Depends(current_user)):
    return svc.delete_account(user, _bearer(authorization), body.password)


@app.get("/api/sessions")
def list_sessions(archived: int = 0, user=Depends(current_user)):
    return svc.list_sessions(user, bool(archived))


@app.post("/api/sessions")
def create_session(body: SessionIn, user=Depends(current_user)):
    return svc.create_session(user, body.title, body.n_parties, body.metric, body.decimals)


@app.get("/api/sessions/{sid}")
def get_session(sid: int, user=Depends(current_user)):
    return svc.get_session(user, sid)


@app.delete("/api/sessions/{sid}")
def delete_session(sid: int, user=Depends(current_user)):
    return svc.delete_session(user, sid)


@app.post("/api/sessions/{sid}/leave")
def leave_session(sid: int, user=Depends(current_user)):
    return svc.leave_session(user, sid)


@app.post("/api/sessions/{sid}/hide")
def hide_session(sid: int, user=Depends(current_user)):
    return svc.set_hidden(user, sid, True)


@app.post("/api/sessions/{sid}/unhide")
def unhide_session(sid: int, user=Depends(current_user)):
    return svc.set_hidden(user, sid, False)


@app.get("/api/invite/{code}")
def preview_invite(code: str, user=Depends(current_user)):
    return svc.preview_invite(user, code)


@app.post("/api/invite/{code}/join")
def join(code: str, body: JoinIn, user=Depends(current_user)):
    return svc.join(user, code, body.public_key)


@app.post("/api/sessions/{sid}/shares")
def submit_shares(sid: int, body: SharesIn, user=Depends(current_user)):
    shares = [{"to_idx": s.to_idx, "ciphertext": s.ciphertext} for s in body.shares]
    return svc.submit_shares(user, sid, shares)


@app.get("/api/sessions/{sid}/my-shares")
def my_shares(sid: int, user=Depends(current_user)):
    return svc.my_shares(user, sid)


@app.post("/api/sessions/{sid}/partial")
def submit_partial(sid: int, body: PartialIn, user=Depends(current_user)):
    return svc.submit_partial(user, sid, body.partial)


# Frontend (must be mounted last so /api/* routes win).
if config.FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(config.FRONTEND_DIR), html=True), name="frontend")
