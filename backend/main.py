"""QuantLite API: secure development foundation for role-based monitoring."""
from __future__ import annotations

import hashlib
import hmac
import base64
import json
import os
import secrets
import smtplib
import sqlite3
import re
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, ConfigDict
from cryptography.fernet import Fernet, InvalidToken

ROOT = Path(__file__).resolve().parent


def load_local_env() -> None:
    env_file = ROOT.parent / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#") or "=" not in entry:
            continue
        key, value = entry.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_local_env()
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'data' / 'quantlite.db'}")
APP_ENV = os.getenv("APP_ENV", "development").lower()
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "12"))
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:8765")
SESSION_COOKIE = "quantlite_session"
CSRF_COOKIE = "quantlite_csrf"
_SCHEMA = (ROOT / "schema.sql").read_text(encoding="utf-8")


class HybridRow(dict):
    """Mapping row that also preserves SQLite-style numeric column access."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


def hybrid_row_factory(cursor):
    column_names = [column.name for column in cursor.description]
    return lambda values: HybridRow(zip(column_names, values))


class PostgresConnection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, statement, parameters=()):
        return self.connection.execute(re.sub(r"\?", "%s", statement), parameters)

    def executescript(self, script):
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self): self.connection.commit()
    def rollback(self): self.connection.rollback()
    def close(self): self.connection.close()


def _table_columns(conn, table: str) -> set[str]:
    if isinstance(conn, sqlite3.Connection):
        return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    rows = conn.execute("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=?", (table,)).fetchall()
    return {row["column_name"] for row in rows}


def _migrate_v2(conn) -> None:
    additions = {
        "users": [
            ("mfa_secret_enc", "TEXT"),
            ("mfa_enabled", "INTEGER NOT NULL DEFAULT 0"),
            ("recovery_codes_json", "TEXT NOT NULL DEFAULT '[]'"),
        ],
        "admin_profiles": [("owner_title", "TEXT NOT NULL DEFAULT 'Founder'")],
        "audit_logs": [("previous_hash", "TEXT"), ("entry_hash", "TEXT")],
    }
    for table, columns in additions.items():
        known = _table_columns(conn, table)
        for name, definition in columns:
            if name not in known:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
    conn.execute("CREATE TABLE IF NOT EXISTS audit_chain_head (id INTEGER PRIMARY KEY CHECK (id = 1), latest_hash TEXT NOT NULL DEFAULT '', latest_created_at TEXT)")
    conn.execute("INSERT INTO audit_chain_head(id,latest_hash,latest_created_at) VALUES(1,'',NULL) ON CONFLICT(id) DO NOTHING")
    previous = ""
    for row in conn.execute("SELECT id,actor_user_id,action,target_type,target_id,created_at,previous_hash,entry_hash FROM audit_logs ORDER BY created_at,id").fetchall():
        if row["entry_hash"]:
            previous = row["entry_hash"]
            continue
        record = {"id": row["id"], "actor_user_id": row["actor_user_id"], "action": row["action"], "target_type": row["target_type"], "target_id": row["target_id"], "created_at": row["created_at"], "previous_hash": previous}
        digest = audit_digest(record)
        conn.execute("UPDATE audit_logs SET previous_hash=?,entry_hash=? WHERE id=?", (previous, digest, row["id"]))
        previous = digest
    last = conn.execute("SELECT entry_hash,created_at FROM audit_logs ORDER BY created_at DESC,id DESC LIMIT 1").fetchone()
    if last:
        conn.execute("UPDATE audit_chain_head SET latest_hash=?,latest_created_at=? WHERE id=1", (last["entry_hash"] or "", last["created_at"]))
    if isinstance(conn, sqlite3.Connection):
        conn.execute("CREATE TRIGGER IF NOT EXISTS audit_logs_no_update BEFORE UPDATE ON audit_logs BEGIN SELECT RAISE(ABORT,'audit logs are append-only'); END")
        conn.execute("CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete BEFORE DELETE ON audit_logs BEGIN SELECT RAISE(ABORT,'audit logs are append-only'); END")
    else:
        conn.execute("CREATE OR REPLACE FUNCTION quantlite_reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit logs are append-only'; END; $$")
        conn.execute("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs")
        conn.execute("CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION quantlite_reject_audit_mutation()")
    conn.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(2,?) ON CONFLICT(version) DO NOTHING", (iso(),))
    conn.commit()

app = FastAPI(title="QuantLite API", version="0.1.0", docs_url="/api/docs" if APP_ENV != "production" else None, redoc_url=None)
origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:8765,http://127.0.0.1:8765,http://localhost:5500,http://127.0.0.1:5500").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"], allow_headers=["Content-Type", "X-CSRF-Token"])


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat()


def audit_digest(entry: dict) -> str:
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def mfa_fernet() -> Fernet:
    key = os.getenv("OWNER_MFA_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError("OWNER_MFA_ENCRYPTION_KEY must be configured for founder accounts.")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as error:
        raise RuntimeError("OWNER_MFA_ENCRYPTION_KEY is invalid; generate a Fernet key.") from error


def encrypt_mfa_secret(secret: str) -> str:
    return mfa_fernet().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_mfa_secret(encrypted: str) -> str:
    try:
        return mfa_fernet().decrypt(encrypted.encode("ascii")).decode("ascii")
    except InvalidToken as error:
        raise RuntimeError("Stored founder MFA secret cannot be decrypted with the configured key.") from error


def verify_totp(secret: str, code: str, timestamp: float | None = None) -> bool:
    if not code or not code.isdigit() or len(code) != 6:
        return False
    normalized = secret.upper()
    normalized += "=" * ((8 - len(normalized) % 8) % 8)
    try:
        key = base64.b32decode(normalized, casefold=True)
    except (ValueError, base64.binascii.Error):
        return False
    counter = int((timestamp if timestamp is not None else time.time()) // 30)
    for step in (-1, 0, 1):
        digest = hmac.new(key, struct.pack(">Q", counter + step), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1_000_000
        if hmac.compare_digest(f"{number:06d}", code):
            return True
    return False


def totp_code(secret: str, timestamp: float | None = None) -> str:
    normalized = secret.upper()
    normalized += "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized, casefold=True)
    counter = int((timestamp if timestamp is not None else time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1_000_000
    return f"{number:06d}"


def date_boundary(value: str | None, upper: bool = False) -> str | None:
    if not value:
        return None
    if len(value) == 10:
        return value + ("T23:59:59.999999+00:00" if upper else "T00:00:00+00:00")
    return value


def get_db():
    is_sqlite = DATABASE_URL.startswith("sqlite:///")
    if is_sqlite:
        db_path = Path(DATABASE_URL.removeprefix("sqlite:///"))
        if not db_path.is_absolute():
            db_path = ROOT / db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
    elif DATABASE_URL.startswith(("postgres://", "postgresql://")):
        try:
            import psycopg
        except ImportError as error:
            raise HTTPException(503, "PostgreSQL support is not installed. Install the backend requirements.") from error
        connection = psycopg.connect(DATABASE_URL, row_factory=hybrid_row_factory, connect_timeout=10)
        conn = PostgresConnection(connection)
    else:
        raise HTTPException(503, "DATABASE_URL must use sqlite:/// or postgresql://.")
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    if not conn.execute("SELECT 1 FROM schema_migrations WHERE version=1").fetchone():
        conn.executescript(_SCHEMA)
        conn.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(1,?) ON CONFLICT(version) DO NOTHING", (iso(),))
        conn.commit()
    if not conn.execute("SELECT 1 FROM schema_migrations WHERE version=2").fetchone():
        _migrate_v2(conn)
    return conn


def new_id(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def write_audit(db, actor: str | None, action: str, target_type: str, target_id: str | None = None) -> None:
    head_query = "SELECT latest_hash,latest_created_at FROM audit_chain_head WHERE id=1"
    if isinstance(db, PostgresConnection):
        head_query += " FOR UPDATE"
    head = db.execute(head_query).fetchone()
    created_at = now()
    if head and head["latest_created_at"]:
        prior = datetime.fromisoformat(head["latest_created_at"])
        if created_at <= prior:
            created_at = prior + timedelta(microseconds=1)
    entry = {
        "id": new_id("aud_"),
        "actor_user_id": actor,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "created_at": iso(created_at),
        "previous_hash": head["latest_hash"] if head else "",
    }
    digest = audit_digest(entry)
    db.execute("INSERT INTO audit_logs(id,actor_user_id,action,target_type,target_id,created_at,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)", (entry["id"], actor, action, target_type, target_id, entry["created_at"], entry["previous_hash"], digest))
    db.execute("UPDATE audit_chain_head SET latest_hash=?,latest_created_at=? WHERE id=1", (digest, entry["created_at"]))


def verify_audit_chain(db) -> dict:
    previous = ""
    checked = 0
    for row in db.execute("SELECT id,actor_user_id,action,target_type,target_id,created_at,previous_hash,entry_hash FROM audit_logs ORDER BY created_at,id").fetchall():
        record = {"id": row["id"], "actor_user_id": row["actor_user_id"], "action": row["action"], "target_type": row["target_type"], "target_id": row["target_id"], "created_at": row["created_at"], "previous_hash": previous}
        if row["previous_hash"] != previous or not hmac.compare_digest(row["entry_hash"] or "", audit_digest(record)):
            return {"valid": False, "checked_entries": checked, "failed_entry_id": row["id"]}
        previous = row["entry_hash"]
        checked += 1
    head = db.execute("SELECT latest_hash FROM audit_chain_head WHERE id=1").fetchone()
    if head and not hmac.compare_digest(head["latest_hash"], previous):
        return {"valid": False, "checked_entries": checked, "failed_entry_id": "audit_chain_head"}
    return {"valid": True, "checked_entries": checked, "latest_hash": previous}


def send_email(to: str, subject: str, body: str) -> bool:
    host = os.getenv("SMTP_HOST")
    if not host:
        return False
    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM", "QuantLite <no-reply@localhost>")
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as smtp:
        smtp.starttls()
        username, password = os.getenv("SMTP_USERNAME"), os.getenv("SMTP_PASSWORD")
        if username and password:
            smtp.login(username, password)
        smtp.send_message(msg)
    return True


def create_auth_token(db: sqlite3.Connection, user_id: str, purpose: str, minutes: int) -> str:
    value = secrets.token_urlsafe(32)
    db.execute("INSERT INTO auth_tokens(token_hash,user_id,purpose,expires_at,created_at) VALUES(?,?,?,?,?)", (token_hash(value), user_id, purpose, iso(now() + timedelta(minutes=minutes)), iso()))
    return value


def public_profile(db: sqlite3.Connection, user: sqlite3.Row) -> dict:
    base = {"id": user["id"], "email": user["email"], "role": user["role"], "email_verified": bool(user["email_verified"]), "account_status": user["account_status"], "created_at": user["created_at"]}
    if user["role"] == "CUSTOMER":
        profile = db.execute("SELECT * FROM customer_profiles WHERE user_id=?", (user["id"],)).fetchone()
        if profile:
            base["profile"] = dict(profile)
    else:
        profile = db.execute("SELECT * FROM admin_profiles WHERE user_id=?", (user["id"],)).fetchone()
        if profile:
            base["profile"] = dict(profile)
    return base


def current_user(
    db: sqlite3.Connection = Depends(get_db),
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> tuple[sqlite3.Connection, sqlite3.Row]:
    if not session_cookie:
        db.close()
        raise HTTPException(401, "Sign in to continue.")
    session = db.execute("SELECT user_id,expires_at FROM sessions WHERE token_hash=?", (token_hash(session_cookie),)).fetchone()
    if not session or datetime.fromisoformat(session["expires_at"]) <= now():
        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(session_cookie),))
        db.commit(); db.close()
        raise HTTPException(401, "Your session has expired. Please sign in again.")
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not user or user["account_status"] != "ACTIVE":
        db.close()
        raise HTTPException(401, "This account cannot access the workspace.")
    return db, user


def require_csrf(
    request: Request,
    db: sqlite3.Connection = Depends(get_db),
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
    csrf_header: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> None:
    if request.method in {"POST", "PATCH", "DELETE"}:
        if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
            db.close()
            raise HTTPException(403, "CSRF validation failed. Refresh the page and try again.")
        session = db.execute("SELECT csrf_hash FROM sessions WHERE token_hash=?", (token_hash(session_cookie or ""),)).fetchone()
        if not session or not hmac.compare_digest(session["csrf_hash"], token_hash(csrf_header)):
            db.close()
            raise HTTPException(403, "CSRF token is not bound to this active session.")


def customer_user(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(current_user), _: None = Depends(require_csrf)) -> tuple[sqlite3.Connection, sqlite3.Row]:
    db, user = ctx
    if user["role"] != "CUSTOMER":
        db.close()
        raise HTTPException(403, "Customer access is required.")
    return db, user


def admin_user(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(current_user), _: None = Depends(require_csrf)) -> tuple[sqlite3.Connection, sqlite3.Row]:
    db, user = ctx
    if user["role"] != "ADMIN":
        db.close()
        raise HTTPException(403, "Founder or co-founder access is required.")
    return db, user


class RegisterInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    phone: str = Field(min_length=6, max_length=32)
    organization: str | None = Field(default=None, max_length=160)
    organization_type: str = Field(min_length=2, max_length=80)
    country: str = Field(min_length=2, max_length=100)
    state: str = Field(min_length=2, max_length=100)
    district: str = Field(min_length=2, max_length=100)
    city: str = Field(min_length=2, max_length=100)
    region: str = Field(min_length=2, max_length=100)
    address: str = Field(min_length=3, max_length=500)
    password: str = Field(min_length=12, max_length=128)
    confirm_password: str = Field(min_length=12, max_length=128)


class LoginInput(BaseModel):
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    password: str = Field(min_length=1, max_length=128)
    portal: Literal["ADMIN", "CUSTOMER"]
    mfa_code: str | None = Field(default=None, pattern=r"^[0-9A-Za-z-]{6,32}$")


class TokenInput(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class EmailInput(BaseModel):
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)


class ResetInput(TokenInput):
    password: str = Field(min_length=12, max_length=128)
    confirm_password: str = Field(min_length=12, max_length=128)


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    phone: str | None = Field(default=None, min_length=6, max_length=32)
    organization: str | None = Field(default=None, max_length=160)
    organization_type: str | None = Field(default=None, min_length=2, max_length=80)
    country: str | None = Field(default=None, min_length=2, max_length=100)
    state: str | None = Field(default=None, min_length=2, max_length=100)
    district: str | None = Field(default=None, min_length=2, max_length=100)
    city: str | None = Field(default=None, min_length=2, max_length=100)
    region: str | None = Field(default=None, min_length=2, max_length=100)
    address: str | None = Field(default=None, min_length=3, max_length=500)


class AdminProfileUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    full_name: str = Field(min_length=2, max_length=120)


class TestCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    sample_reference: str | None = Field(default=None, max_length=120)
    sample_type: str = Field(min_length=2, max_length=80)
    collected_at: datetime | None = None
    country: str = Field(min_length=2, max_length=100)
    state: str = Field(min_length=2, max_length=100)
    district: str = Field(min_length=2, max_length=100)
    city: str = Field(min_length=2, max_length=100)
    region: str = Field(min_length=2, max_length=100)
    address: str | None = Field(default=None, max_length=500)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)


@app.get("/api/health")
def health() -> dict:
    db = get_db()
    db.execute("SELECT 1").fetchone()
    db.close()
    return {"status": "ok", "service": "quantlite-api", "inference": "not-configured", "storage": "sqlite-development" if DATABASE_URL.startswith("sqlite:///") else "postgresql" if DATABASE_URL.startswith(("postgres://", "postgresql://")) else "not-configured"}


@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterInput) -> dict:
    if payload.password != payload.confirm_password:
        raise HTTPException(422, "Passwords do not match.")
    bootstrap_owner = os.getenv("BOOTSTRAP_OWNER_EMAIL", "").strip().casefold()
    if bootstrap_owner and payload.email.casefold() == bootstrap_owner:
        raise HTTPException(409, "This email is reserved for the founder bootstrap process.")
    db = get_db()
    email = str(payload.email).lower()
    if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        db.close(); raise HTTPException(409, "An account with this email already exists.")
    user_id, customer_id = new_id("usr_"), "QL-" + secrets.token_hex(5).upper()
    try:
        db.execute("INSERT INTO users(id,email,password_hash,role,email_verified,created_at) VALUES(?,?,?,?,0,?)", (user_id, email, password_hash(payload.password), "CUSTOMER", iso()))
        db.execute("INSERT INTO customer_profiles(user_id,customer_id,full_name,phone,organization,organization_type,country,state,district,city,region,address,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (user_id, customer_id, payload.full_name, payload.phone, payload.organization, payload.organization_type, payload.country, payload.state, payload.district, payload.city, payload.region, payload.address, iso()))
        verification = create_auth_token(db, user_id, "VERIFY_EMAIL", 60 * 24)
        write_audit(db, user_id, "CUSTOMER_REGISTERED", "user", user_id)
        db.commit()
        link = f"{FRONTEND_BASE_URL}/#verify?token={verification}"
        try:
            mailed = send_email(email, "Verify your QuantLite account", f"Verify your email within 24 hours: {link}")
        except (OSError, smtplib.SMTPException):
            mailed = False
        result = {"message": "Account created. Verify your email before signing in.", "customer_id": customer_id, "email_delivery": "sent" if mailed else "not-configured"}
        if APP_ENV != "production" and not mailed:
            result["development_verification_token"] = verification
        return result
    except sqlite3.IntegrityError:
        db.rollback(); raise HTTPException(409, "An account with this email already exists.")
    finally:
        db.close()


@app.post("/api/auth/verify")
def verify_email(payload: TokenInput) -> dict:
    db = get_db()
    try:
        token = db.execute("SELECT * FROM auth_tokens WHERE token_hash=? AND purpose='VERIFY_EMAIL' AND consumed_at IS NULL", (token_hash(payload.token),)).fetchone()
        if not token or datetime.fromisoformat(token["expires_at"]) <= now():
            raise HTTPException(400, "Verification link is invalid or expired.")
        db.execute("UPDATE users SET email_verified=1 WHERE id=?", (token["user_id"],))
        db.execute("UPDATE auth_tokens SET consumed_at=? WHERE token_hash=?", (iso(), token["token_hash"]))
        write_audit(db, token["user_id"], "EMAIL_VERIFIED", "user", token["user_id"]); db.commit()
        return {"message": "Email verified. You can now sign in."}
    finally:
        db.close()


@app.post("/api/auth/login")
def login(payload: LoginInput, response: Response) -> dict:
    db = get_db()
    email = str(payload.email).lower()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not verify_password(payload.password, user["password_hash"]):
        db.close(); raise HTTPException(401, "Email or password is incorrect.")
    if user["role"] != payload.portal:
        db.close(); raise HTTPException(403, "This account is not authorized for that portal.")
    if not user["email_verified"]:
        db.close(); raise HTTPException(403, "Verify your email before signing in.")
    if user["account_status"] != "ACTIVE":
        db.close(); raise HTTPException(403, "This account is suspended. Contact QuantLite support.")
    if user["role"] == "ADMIN":
        if not user["mfa_enabled"] or not user["mfa_secret_enc"]:
            db.close(); raise HTTPException(403, "Founder MFA is not provisioned. Contact another verified founder for owner-controlled recovery.")
        if not payload.mfa_code:
            db.close(); raise HTTPException(422, "Founder sign-in requires an authenticator or recovery code.")
        try:
            secret = decrypt_mfa_secret(user["mfa_secret_enc"])
        except RuntimeError as error:
            db.close(); raise HTTPException(503, "Founder MFA is unavailable because its server encryption key is not configured.") from error
        code = payload.mfa_code.strip()
        recovery_codes = json.loads(user["recovery_codes_json"] or "[]")
        recovered_index = next((index for index, digest in enumerate(recovery_codes) if hmac.compare_digest(digest, token_hash(code))), None)
        is_totp = verify_totp(secret, code)
        if not is_totp and recovered_index is None:
            db.close(); raise HTTPException(401, "Authenticator or recovery code is invalid.")
        if recovered_index is not None and not is_totp:
            recovery_codes.pop(recovered_index)
            db.execute("UPDATE users SET recovery_codes_json=? WHERE id=?", (json.dumps(recovery_codes), user["id"]))
            db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
            write_audit(db, user["id"], "OWNER_RECOVERY_CODE_USED", "user", user["id"])
    session_value, csrf_value = secrets.token_urlsafe(40), secrets.token_urlsafe(24)
    expiry = now() + timedelta(hours=SESSION_HOURS)
    db.execute("INSERT INTO sessions(token_hash,csrf_hash,user_id,expires_at,created_at) VALUES(?,?,?,?,?)", (token_hash(session_value), token_hash(csrf_value), user["id"], iso(expiry), iso()))
    write_audit(db, user["id"], "LOGIN", "session"); db.commit()
    secure = APP_ENV == "production"
    response.set_cookie(SESSION_COOKIE, session_value, httponly=True, secure=secure, samesite="strict", max_age=SESSION_HOURS * 3600, path="/")
    response.set_cookie(CSRF_COOKIE, csrf_value, httponly=False, secure=secure, samesite="strict", max_age=SESSION_HOURS * 3600, path="/")
    result = {"user": public_profile(db, user), "csrf_token": csrf_value, "session_expires_at": iso(expiry)}
    db.close()
    return result


@app.post("/api/auth/logout")
def logout(response: Response, ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(current_user), _: None = Depends(require_csrf), session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None) -> dict:
    db, user = ctx
    db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(session_cookie or ""),))
    write_audit(db, user["id"], "LOGOUT", "session"); db.commit(); db.close()
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict", secure=APP_ENV == "production")
    response.delete_cookie(CSRF_COOKIE, path="/", samesite="strict", secure=APP_ENV == "production")
    return {"message": "Signed out."}


@app.get("/api/auth/me")
def whoami(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(current_user)) -> dict:
    db, user = ctx
    result = {"user": public_profile(db, user)}; db.close(); return result


@app.post("/api/auth/forgot-password")
def forgot_password(payload: EmailInput) -> dict:
    db = get_db(); user = db.execute("SELECT id,role FROM users WHERE email=?", (str(payload.email).lower(),)).fetchone()
    result = {"message": "If eligible, password reset instructions will be sent. Founder recovery requires founder-approved provisioning."}
    if user and user["role"] == "CUSTOMER":
        token = create_auth_token(db, user["id"], "RESET_PASSWORD", 30); db.commit()
        try:
            mailed = send_email(str(payload.email), "Reset your QuantLite password", f"Reset your password within 30 minutes: {FRONTEND_BASE_URL}/#reset-password?token={token}")
        except (OSError, smtplib.SMTPException):
            mailed = False
        if APP_ENV != "production" and not mailed: result["development_reset_token"] = token
    db.close(); return result


@app.post("/api/auth/reset-password")
def reset_password(payload: ResetInput) -> dict:
    if payload.password != payload.confirm_password: raise HTTPException(422, "Passwords do not match.")
    db = get_db()
    try:
        token = db.execute("SELECT * FROM auth_tokens WHERE token_hash=? AND purpose='RESET_PASSWORD' AND consumed_at IS NULL", (token_hash(payload.token),)).fetchone()
        if not token or datetime.fromisoformat(token["expires_at"]) <= now(): raise HTTPException(400, "Password reset link is invalid or expired.")
        user = db.execute("SELECT role FROM users WHERE id=?", (token["user_id"],)).fetchone()
        if not user or user["role"] != "CUSTOMER": raise HTTPException(403, "Founder accounts require recovery through an existing founder-approved provisioning process.")
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(payload.password), token["user_id"]))
        db.execute("DELETE FROM sessions WHERE user_id=?", (token["user_id"],))
        db.execute("UPDATE auth_tokens SET consumed_at=? WHERE token_hash=?", (iso(), token["token_hash"]))
        write_audit(db, token["user_id"], "PASSWORD_RESET", "user", token["user_id"]); db.commit()
        return {"message": "Password updated. Sign in with your new password."}
    finally: db.close()


@app.get("/api/customer/profile")
def get_customer_profile(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(customer_user)) -> dict:
    db, user = ctx; result = public_profile(db, user); db.close(); return result


@app.get("/api/admin/profile")
def get_admin_profile(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user)) -> dict:
    db, user = ctx; result = public_profile(db, user); db.close(); return result


@app.patch("/api/admin/profile")
def update_admin_profile(payload: AdminProfileUpdate, ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user)) -> dict:
    db, user = ctx
    db.execute("INSERT INTO admin_profiles(user_id,full_name,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET full_name=excluded.full_name,updated_at=excluded.updated_at", (user["id"], payload.full_name, iso()))
    write_audit(db, user["id"], "ADMIN_PROFILE_UPDATED", "user", user["id"]); db.commit()
    updated = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone(); result = public_profile(db, updated); db.close(); return result


@app.patch("/api/customer/profile")
def update_customer_profile(payload: ProfileUpdate, ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(customer_user)) -> dict:
    db, user = ctx; values = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not values: db.close(); raise HTTPException(422, "Provide at least one editable profile field.")
    values["updated_at"] = iso()
    assignments = ",".join(f"{field}=?" for field in values)
    db.execute(f"UPDATE customer_profiles SET {assignments} WHERE user_id=?", (*values.values(), user["id"]))
    write_audit(db, user["id"], "CUSTOMER_PROFILE_UPDATED", "user", user["id"]); db.commit()
    updated = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone(); result = public_profile(db, updated); db.close(); return result


@app.get("/api/customer/dashboard")
def customer_dashboard(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(customer_user)) -> dict:
    db, user = ctx
    counts = {row["status"].lower(): row["count"] for row in db.execute("SELECT status,COUNT(*) count FROM test_records WHERE customer_user_id=? GROUP BY status", (user["id"],))}
    total = sum(counts.values())
    recent = db.execute("SELECT id,sample_reference,sample_type,collected_at,country,state,district,city,region,status,created_at FROM test_records WHERE customer_user_id=? ORDER BY created_at DESC LIMIT 10", (user["id"],)).fetchall()
    reports = db.execute("SELECT id,test_id,status,created_at FROM reports WHERE customer_user_id=? ORDER BY created_at DESC LIMIT 5", (user["id"],)).fetchall()
    profile = db.execute("SELECT customer_id,full_name,organization,country,state,district,city,region FROM customer_profiles WHERE user_id=?", (user["id"],)).fetchone()
    result = {"profile": dict(profile) if profile else None, "counts": {"total": total, "pending": counts.get("pending", 0), "processing": counts.get("processing", 0), "completed": counts.get("completed", 0), "failed": counts.get("failed", 0)}, "recent_tests": [dict(row) for row in recent], "reports": [dict(row) for row in reports]}
    db.close(); return result


@app.get("/api/customer/tests")
def customer_tests(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(customer_user), limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict:
    db, user = ctx
    rows = db.execute("SELECT id,sample_reference,sample_type,collected_at,country,state,district,city,region,status,detection_json,model_info,report_id,created_at FROM test_records WHERE customer_user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?", (user["id"], limit, offset)).fetchall()
    total = db.execute("SELECT COUNT(*) FROM test_records WHERE customer_user_id=?", (user["id"],)).fetchone()[0]
    db.close(); return {"items": [dict(row) for row in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/api/customer/analytics")
def customer_analytics(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(customer_user)) -> dict:
    db, user = ctx
    statuses = db.execute("SELECT status,COUNT(*) count FROM test_records WHERE customer_user_id=? GROUP BY status", (user["id"],)).fetchall()
    by_month = db.execute("SELECT substr(created_at,1,7) month,COUNT(*) count FROM test_records WHERE customer_user_id=? GROUP BY month ORDER BY month", (user["id"],)).fetchall()
    sample_types = db.execute("SELECT sample_type,COUNT(*) count FROM test_records WHERE customer_user_id=? GROUP BY sample_type ORDER BY count DESC", (user["id"],)).fetchall()
    result = {"by_status": [dict(r) for r in statuses], "by_month": [dict(r) for r in by_month], "by_sample_type": [dict(r) for r in sample_types]}; db.close(); return result


@app.get("/api/customer/map")
def customer_map(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(customer_user), status: str | None = None, sample_type: str | None = None, start_date: str | None = None, end_date: str | None = None) -> dict:
    db, user = ctx
    where, values = ["customer_user_id=?", "latitude IS NOT NULL", "longitude IS NOT NULL"], [user["id"]]
    for column, value in (("status", status), ("sample_type", sample_type)):
        if value: where.append(f"{column}=?"); values.append(value)
    if start_date: where.append("created_at>=?"); values.append(date_boundary(start_date))
    if end_date: where.append("created_at<=?"); values.append(date_boundary(end_date, upper=True))
    rows = db.execute("SELECT id,sample_reference,latitude,longitude,status,created_at FROM test_records WHERE " + " AND ".join(where) + " ORDER BY created_at DESC", values).fetchall()
    db.close(); return {"items": [dict(r) for r in rows], "total": len(rows)}


@app.post("/api/customer/tests", status_code=201)
def create_customer_test(payload: TestCreate, ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(customer_user)) -> dict:
    db, user = ctx; record_id = new_id("test_")
    data = payload.model_dump(); collected = data["collected_at"].isoformat() if data["collected_at"] else None
    db.execute("INSERT INTO test_records(id,customer_user_id,sample_reference,sample_type,collected_at,country,state,district,city,region,address,latitude,longitude,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'PENDING',?)", (record_id, user["id"], data["sample_reference"], data["sample_type"], collected, data["country"], data["state"], data["district"], data["city"], data["region"], data["address"], data["latitude"], data["longitude"], iso()))
    write_audit(db, user["id"], "TEST_RECORD_CREATED", "test_record", record_id); db.commit()
    row = db.execute("SELECT * FROM test_records WHERE id=? AND customer_user_id=?", (record_id, user["id"])).fetchone(); db.close()
    return {"test": dict(row), "analysis": "not-configured"}


@app.get("/api/customer/tests/{test_id}")
def customer_test_detail(test_id: str, ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(customer_user)) -> dict:
    db, user = ctx
    row = db.execute("SELECT * FROM test_records WHERE id=? AND customer_user_id=?", (test_id, user["id"])).fetchone()
    db.close()
    if not row: raise HTTPException(404, "Test record was not found.")
    return {**dict(row), "detection_json": json.loads(row["detection_json"]) if row["detection_json"] else None}


@app.get("/api/customer/reports")
def customer_reports(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(customer_user)) -> dict:
    db, user = ctx; rows = db.execute("SELECT id,test_id,status,created_at FROM reports WHERE customer_user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall(); db.close()
    return {"items": [dict(row) for row in rows], "total": len(rows)}


def admin_test_query(db: sqlite3.Connection, filters: dict, limit: int, offset: int) -> tuple[list[dict], int]:
    where, values = [], []
    for key in ("state", "district", "city", "region", "status", "sample_type"):
        value = filters.get(key)
        if value: where.append(f"t.{key}=?"); values.append(value)
    if filters.get("customer_id"):
        where.append("p.customer_id=?"); values.append(filters["customer_id"])
    if filters.get("start_date"):
        where.append("t.created_at>=?"); values.append(date_boundary(filters["start_date"]))
    if filters.get("end_date"):
        where.append("t.created_at<=?"); values.append(date_boundary(filters["end_date"], upper=True))
    if filters.get("detection_result"):
        where.append("t.detection_json LIKE ?"); values.append(f"%{filters['detection_result']}%")
    clause = " WHERE " + " AND ".join(where) if where else ""
    base = " FROM test_records t JOIN customer_profiles p ON p.user_id=t.customer_user_id JOIN users u ON u.id=t.customer_user_id"
    rows = db.execute("SELECT t.*,p.customer_id,p.full_name customer_name,u.email" + base + clause + " ORDER BY t.created_at DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
    total = db.execute("SELECT COUNT(*)" + base + clause, values).fetchone()[0]
    return [dict(row) for row in rows], total


@app.get("/api/admin/dashboard")
def admin_dashboard(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user)) -> dict:
    db, user = ctx
    total_customers = db.execute("SELECT COUNT(*) FROM users WHERE role='CUSTOMER'").fetchone()[0]
    statuses = {row["status"].lower(): row["count"] for row in db.execute("SELECT status,COUNT(*) count FROM test_records GROUP BY status")}
    recent_customers = db.execute("SELECT u.id,u.email,u.created_at,p.customer_id,p.full_name,p.organization,p.state,p.city FROM users u JOIN customer_profiles p ON p.user_id=u.id WHERE u.role='CUSTOMER' ORDER BY u.created_at DESC LIMIT 8").fetchall()
    recent_tests, _ = admin_test_query(db, {}, 8, 0)
    regions = db.execute("SELECT state,district,city,region,COUNT(*) test_count FROM test_records GROUP BY state,district,city,region ORDER BY test_count DESC LIMIT 10").fetchall()
    audit = db.execute("SELECT action,target_type,target_id,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 12").fetchall()
    result = {"counts": {"customers": total_customers, "tests": sum(statuses.values()), "pending": statuses.get("pending", 0), "processing": statuses.get("processing", 0), "completed": statuses.get("completed", 0), "failed": statuses.get("failed", 0), "active_regions": db.execute("SELECT COUNT(DISTINCT state||'|'||district||'|'||city||'|'||region) FROM test_records").fetchone()[0]}, "recent_customers": [dict(r) for r in recent_customers], "recent_tests": recent_tests, "regional_counts": [dict(r) for r in regions], "activity": [dict(r) for r in audit]}
    db.close(); return result


@app.get("/api/admin/audit/verify")
def admin_audit_verify(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user)) -> dict:
    db, _ = ctx
    result = verify_audit_chain(db)
    db.close()
    return result


@app.get("/api/admin/customers")
def admin_customers(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user), q: str | None = None, state: str | None = None, district: str | None = None, city: str | None = None, region: str | None = None, status: str | None = None, start_date: str | None = None, end_date: str | None = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict:
    db, _ = ctx; where = ["u.role='CUSTOMER'"]; values = []
    if q:
        where.append("(p.full_name LIKE ? OR p.customer_id LIKE ? OR u.email LIKE ?)"); values.extend([f"%{q}%"] * 3)
    for col, val in (("p.state", state), ("p.district", district), ("p.city", city), ("p.region", region), ("u.account_status", status)):
        if val: where.append(f"{col}=?"); values.append(val)
    if start_date: where.append("u.created_at>=?"); values.append(date_boundary(start_date))
    if end_date: where.append("u.created_at<=?"); values.append(date_boundary(end_date, upper=True))
    clause = " WHERE " + " AND ".join(where)
    rows = db.execute("SELECT u.id,u.email,u.email_verified,u.account_status,u.created_at,p.*,(SELECT COUNT(*) FROM test_records t WHERE t.customer_user_id=u.id) test_count FROM users u JOIN customer_profiles p ON p.user_id=u.id" + clause + " ORDER BY u.created_at DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
    count = db.execute("SELECT COUNT(*) FROM users u JOIN customer_profiles p ON p.user_id=u.id" + clause, values).fetchone()[0]
    db.close(); return {"items": [dict(row) for row in rows], "total": count, "limit": limit, "offset": offset}


@app.get("/api/admin/customers/{customer_user_id}")
def admin_customer_detail(customer_user_id: str, ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user)) -> dict:
    db, _ = ctx
    user = db.execute("SELECT * FROM users WHERE id=? AND role='CUSTOMER'", (customer_user_id,)).fetchone()
    if not user: db.close(); raise HTTPException(404, "Customer account was not found.")
    tests = db.execute("SELECT * FROM test_records WHERE customer_user_id=? ORDER BY created_at DESC", (customer_user_id,)).fetchall()
    reports = db.execute("SELECT id,test_id,status,created_at FROM reports WHERE customer_user_id=? ORDER BY created_at DESC", (customer_user_id,)).fetchall()
    activity = db.execute("SELECT action,target_type,target_id,created_at FROM audit_logs WHERE actor_user_id=? OR (target_type='user' AND target_id=?) ORDER BY created_at DESC LIMIT 50", (customer_user_id, customer_user_id)).fetchall()
    result = {"customer": public_profile(db, user), "tests": [dict(row) for row in tests], "reports": [dict(row) for row in reports], "activity": [dict(row) for row in activity]}
    db.close(); return result


@app.patch("/api/admin/customers/{customer_user_id}/status")
def admin_set_customer_status(customer_user_id: str, status: Literal["ACTIVE", "SUSPENDED"], ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user)) -> dict:
    db, admin = ctx; target = db.execute("SELECT id FROM users WHERE id=? AND role='CUSTOMER'", (customer_user_id,)).fetchone()
    if not target: db.close(); raise HTTPException(404, "Customer account was not found.")
    db.execute("UPDATE users SET account_status=? WHERE id=?", (status, customer_user_id)); write_audit(db, admin["id"], "CUSTOMER_STATUS_CHANGED", "user", customer_user_id); db.commit(); db.close()
    return {"message": "Customer account status updated.", "account_status": status}


@app.get("/api/admin/tests")
def admin_tests(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user), customer_id: str | None = None, state: str | None = None, district: str | None = None, city: str | None = None, region: str | None = None, status: str | None = None, sample_type: str | None = None, detection_result: str | None = None, start_date: str | None = None, end_date: str | None = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict:
    db, _ = ctx; filters = locals(); items, total = admin_test_query(db, filters, limit, offset); db.close()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@app.get("/api/admin/test-records/{test_id}")
def admin_test_detail(test_id: str, ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user)) -> dict:
    db, _ = ctx
    row = db.execute("SELECT t.*,p.customer_id,p.full_name customer_name,u.email FROM test_records t JOIN customer_profiles p ON p.user_id=t.customer_user_id JOIN users u ON u.id=t.customer_user_id WHERE t.id=?", (test_id,)).fetchone()
    db.close()
    if not row: raise HTTPException(404, "Test record was not found.")
    result = dict(row)
    result["detection_json"] = json.loads(result["detection_json"]) if result["detection_json"] else None
    return result


@app.get("/api/admin/regions")
def admin_regions(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user), country: str | None = None, state: str | None = None, district: str | None = None, city: str | None = None, region: str | None = None, customer_id: str | None = None, start_date: str | None = None, end_date: str | None = None) -> dict:
    db, _ = ctx; where, values = [], []
    for key, value in (("t.country", country), ("t.state", state), ("t.district", district), ("t.city", city), ("t.region", region), ("p.customer_id", customer_id)):
        if value: where.append(f"{key}=?"); values.append(value)
    if start_date: where.append("t.created_at>=?"); values.append(date_boundary(start_date))
    if end_date: where.append("t.created_at<=?"); values.append(date_boundary(end_date, upper=True))
    clause = " WHERE " + " AND ".join(where) if where else ""
    rows = db.execute("SELECT t.state,t.district,t.city,t.region,COUNT(*) test_count FROM test_records t JOIN customer_profiles p ON p.user_id=t.customer_user_id" + clause + " GROUP BY t.state,t.district,t.city,t.region ORDER BY test_count DESC", values).fetchall()
    db.close(); return {"items": [dict(row) for row in rows], "total": sum(row["test_count"] for row in rows)}


@app.get("/api/admin/map")
def admin_map(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user), status: str | None = None, sample_type: str | None = None, start_date: str | None = None, end_date: str | None = None) -> dict:
    db, _ = ctx
    where, values = ["t.latitude IS NOT NULL", "t.longitude IS NOT NULL"], []
    for column, value in (("t.status", status), ("t.sample_type", sample_type)):
        if value: where.append(f"{column}=?"); values.append(value)
    if start_date: where.append("t.created_at>=?"); values.append(date_boundary(start_date))
    if end_date: where.append("t.created_at<=?"); values.append(date_boundary(end_date, upper=True))
    rows = db.execute("SELECT t.id,t.customer_user_id,p.customer_id,p.full_name,t.sample_reference,t.latitude,t.longitude,t.status,t.created_at FROM test_records t JOIN customer_profiles p ON p.user_id=t.customer_user_id WHERE " + " AND ".join(where) + " ORDER BY t.created_at DESC", values).fetchall()
    db.close(); return {"items": [dict(row) for row in rows], "total": len(rows)}


@app.get("/api/admin/tests/export.csv")
def admin_export(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user), customer_id: str | None = None, state: str | None = None, district: str | None = None, city: str | None = None, region: str | None = None, status: str | None = None, sample_type: str | None = None, detection_result: str | None = None, start_date: str | None = None, end_date: str | None = None) -> StreamingResponse:
    import csv, io
    db, _ = ctx; filters = locals(); items, _ = admin_test_query(db, filters, 100_000, 0); db.close()
    output = io.StringIO(newline=""); columns = ["id", "customer_id", "customer_name", "email", "sample_reference", "sample_type", "collected_at", "country", "state", "district", "city", "region", "latitude", "longitude", "status", "detection_json", "model_info", "created_at"]
    writer = csv.DictWriter(output, fieldnames=columns); writer.writeheader()
    for item in items:
        safe = {key: item.get(key) for key in columns}
        for key, value in safe.items():
            if isinstance(value, str) and value.startswith(("=", "+", "-", "@")): safe[key] = "'" + value
        writer.writerow(safe)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=quantlite-test-records.csv"})


@app.get("/api/admin/analytics")
def admin_analytics(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user), start_date: str | None = None, end_date: str | None = None) -> dict:
    db, _ = ctx; clauses, values = [], []
    if start_date: clauses.append("created_at>=?"); values.append(date_boundary(start_date))
    if end_date: clauses.append("created_at<=?"); values.append(date_boundary(end_date, upper=True))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    status = db.execute("SELECT status,COUNT(*) count FROM test_records" + where + " GROUP BY status", values).fetchall()
    by_state = db.execute("SELECT state,COUNT(*) count FROM test_records" + where + " GROUP BY state ORDER BY count DESC", values).fetchall()
    by_type = db.execute("SELECT sample_type,COUNT(*) count FROM test_records" + where + " GROUP BY sample_type ORDER BY count DESC", values).fetchall()
    by_month = db.execute("SELECT substr(created_at,1,7) month,COUNT(*) count FROM test_records" + where + " GROUP BY month ORDER BY month", values).fetchall()
    by_customer = db.execute("SELECT p.customer_id,p.full_name,COUNT(t.id) count FROM customer_profiles p JOIN test_records t ON t.customer_user_id=p.user_id" + (" WHERE " + " AND ".join("t." + x for x in clauses) if clauses else "") + " GROUP BY p.user_id ORDER BY count DESC", values).fetchall()
    result = {"by_status": [dict(r) for r in status], "by_state": [dict(r) for r in by_state], "by_sample_type": [dict(r) for r in by_type], "by_month": [dict(r) for r in by_month], "by_customer": [dict(r) for r in by_customer]}; db.close(); return result


@app.get("/api/admin/reports")
def admin_reports(ctx: tuple[sqlite3.Connection, sqlite3.Row] = Depends(admin_user), customer_id: str | None = None, status: str | None = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict:
    db, _ = ctx; where, values = [], []
    if customer_id: where.append("p.customer_id=?"); values.append(customer_id)
    if status: where.append("r.status=?"); values.append(status)
    clause = " WHERE " + " AND ".join(where) if where else ""
    rows = db.execute("SELECT r.id,r.test_id,r.status,r.created_at,p.customer_id,p.full_name customer_name FROM reports r JOIN customer_profiles p ON p.user_id=r.customer_user_id" + clause + " ORDER BY r.created_at DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
    total = db.execute("SELECT COUNT(*) FROM reports r JOIN customer_profiles p ON p.user_id=r.customer_user_id" + clause, values).fetchone()[0]
    db.close(); return {"items": [dict(row) for row in rows], "total": total, "limit": limit, "offset": offset}
