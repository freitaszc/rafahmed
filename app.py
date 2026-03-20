import os
import io
import re
import json
import base64
import secrets
from io import BytesIO
from functools import wraps
from contextvars import ContextVar
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Any, Optional, cast

from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from cryptography.fernet import Fernet

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, jsonify,
    get_flashed_messages, abort, send_file, make_response, current_app
)

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from flask_migrate import Migrate
from sqlalchemy import text, inspect, desc, and_, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError, OperationalError

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow

from whatsapp import send_quote_whatsapp, send_pix_receipt_admin
from mercado_pago import generate_payment_link
from email_utils import send_email_quote

from records import (
    get_suppliers_by_user, add_supplier_db, update_supplier_db, delete_supplier_db,
    update_product, get_product_by_id, get_products, save_products,
    is_package_available, update_package_usage, get_package_info,
    add_doctor, get_patient_by_id, get_patients_by_doctor, update_patient,
    delete_patient_record, add_patient, add_consult, get_consults_by_patient,
    add_quiz_result, get_quiz_results_by_doctor, delete_product_record
)

from models import (
    db, User, Company, Supplier, Quote, QuoteResponse, Doctor, Consult, Patient,
    QuizResult, PdfFile, DoctorAvailability, QuestionnaireResult, DoctorDateAvailability,
    SecureFile, Product, UserPackage
)

# ------------------------------------------------------------------------------
# App & DB
# ------------------------------------------------------------------------------
load_dotenv()
app = Flask(__name__)

# Fernet
FILE_ENC_KEY = os.getenv("FILE_ENC_KEY")
if not FILE_ENC_KEY:
    raise RuntimeError("Missing FILE_ENC_KEY env var. Generate one: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'")
FERNET = Fernet(FILE_ENC_KEY)

# DB/config dirs
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
os.makedirs(BASE_DIR, exist_ok=True)
db_path = os.path.join(BASE_DIR, 'web.db')
DATABASE_URL = (os.getenv('DATABASE_URL') or f'sqlite:///{db_path}').strip()

# static dir + uploads (gerais)
STATIC_DIR = os.path.join(app.root_path, 'static')
os.makedirs(STATIC_DIR, exist_ok=True)
UPLOAD_FOLDER = os.path.join(STATIC_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 1800,
}
# Use stable secret key if provided; otherwise generate one (sessions/tokens persist across restarts if set)
app.secret_key = os.getenv("APP_SECRET_KEY") or secrets.token_hex(32)

db.init_app(app)
migrate = Migrate(app, db)

def ensure_tables():
    with app.app_context():
        insp = inspect(db.engine)
        existing = set(insp.get_table_names())
        required = {
            "users",
            "companies",
            "suppliers",
            "quotes",
            "quote_responses",
            "doctors",
            "patients",
            "consults",
            "quiz_results",
            "products",
            "user_packages",
            "doctor_availability",
            "questionnaire_results",
            "doctor_date_availability",
            "secure_files",
            "pdf_files",
        }
        if required - existing:
            app.logger.warning(
                "Missing tables detected. Creating any that are missing."
            )
            db.create_all()

ensure_tables()

# ------------------------------------------------------------------------------
# Files secure tokens
# ------------------------------------------------------------------------------
# replace _pdf_serializer/generate_pdf_token/verify_pdf_token with generic versions
def _file_serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt="file-token-v1")  # type: ignore

def generate_file_token(file_id: int) -> str:
    return _file_serializer().dumps({"fid": int(file_id)})

def verify_file_token(token: str, max_age_seconds: int = 3600) -> Optional[int]:
    try:
        data = _file_serializer().loads(token, max_age=max_age_seconds)
        return int(data.get("fid"))
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        return None

@app.get("/files/<int:file_id>")
def file_download_auth(file_id):
    user = get_logged_user()
    if not user:
        abort(403)
    raw, sf = read_secure_file_bytes(file_id)
    if not is_admin(user) and sf.owner_user_id != user.id:
        abort(403)
    resp = make_response(raw)
    resp.headers["Content-Type"] = sf.mime_type
    resp.headers["Content-Disposition"] = f'inline; filename="{sf.filename}"'
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return resp

@app.get("/files/signed/<token>")
def file_download_signed(token):
    file_id = verify_file_token(token, max_age_seconds=3600)
    if not file_id:
        abort(403)
    raw, sf = read_secure_file_bytes(file_id)
    resp = make_response(raw)
    resp.headers["Content-Type"] = sf.mime_type
    resp.headers["Content-Disposition"] = f'inline; filename="{sf.filename}"'
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return resp


# ------------------------------------------------------------------------------
# Subscription / PIX
# ------------------------------------------------------------------------------
PIX_CNPJ = os.getenv("PIX_CNPJ", "49.942.520/0001-02")
PIX_KEY  = os.getenv("PIX_KEY", "49.942.520/0001-02")
PIX_NAME = os.getenv("PIX_NAME", "RafahMed")
PIX_CITY = os.getenv("PIX_CITY", "Ipatinga")
PIX_DESC = os.getenv("PIX_DESC", "Assinatura RafahMed")
PLAN_PRICES = {"plus": 99.00, "premium": 179.00}
ADMIN_WHATSAPP = os.getenv("ADMIN_WHATSAPP", "31985570920")
AUTO_WHATSAPP_ENABLED = os.getenv("AUTO_WHATSAPP_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}
QUOTES_SECTION_ENABLED = os.getenv("QUOTES_SECTION_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}

PLAN_LEVELS = {'standard': 1, 'plus': 2, 'premium': 3}
FEATURES = {
    'quotes_auto': 3,
    'training': 3,
    'selfevaluations': 3
}

def _emv(tag, value):
    v = str(value)
    return f"{tag}{len(v):02d}{v}"

def _crc16(data: bytes) -> str:
    poly = 0x1021
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
    return f"{crc:04X}"

def build_pix_payload(key: str, name: str, city: str, amount: float, txid: str, description: str = "") -> str:
    p = _emv("00", "01") + _emv("01", "11")
    mai = _emv("00", "br.gov.bcb.pix") + _emv("01", key)
    if description:
        if len(description) > 99:
            description = description[:99]
        mai += _emv("02", description)
    p += _emv("26", mai)
    p += _emv("52", "0000") + _emv("53", "986") + _emv("54", f"{amount:.2f}")
    name = (name or "")[:25]
    city = (city or "SAO PAULO")[:15]
    p += _emv("58", "BR") + _emv("59", name) + _emv("60", city)
    txid = (txid or "RAF")[:25]
    p += _emv("62", _emv("05", txid))
    to_crc = (p + "6304").encode("ascii")
    crc = _crc16(to_crc)
    return p + "63" + "04" + crc

def make_qr_base64(payload: str) -> str | None:
    try:
        import qrcode  # type: ignore
        from PIL import Image  # noqa: F401
        img = qrcode.make(payload)
        buf = io.BytesIO()
        img.save(buf, "PNG")
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception as e:
        print("[pix] qr generation skipped:", e)
        return None

def ensure_subscription_columns():
    with app.app_context():
        insp = inspect(db.engine)
        try:
            cols = {c["name"] for c in insp.get_columns("users")}
        except Exception as e:
            print("[migrate] Could not read 'users' columns:", e)
            return

        stmts = []
        if "plan" not in cols:
            stmts.append("ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'standard'")
        if "plan_status" not in cols:
            stmts.append("ALTER TABLE users ADD COLUMN plan_status TEXT DEFAULT 'inactive'")
        if "plan_expires_at" not in cols:
            stmts.append("ALTER TABLE users ADD COLUMN plan_expires_at DATETIME")
        if "trial_until" not in cols:
            stmts.append("ALTER TABLE users ADD COLUMN trial_until DATETIME")

        with db.engine.begin() as conn:
            for s in stmts:
                print("[migrate]", s)
                conn.execute(text(s))
            conn.execute(text(
                "UPDATE users "
                "SET plan = COALESCE(plan,'standard'), "
                "    plan_status = COALESCE(plan_status,'inactive')"
            ))

ensure_subscription_columns()

def ensure_user_columns():
    with app.app_context():
        try:
            insp = inspect(db.engine)
        except SQLAlchemyError as e:
            app.logger.error("[migrate] Could not inspect database: %s", e)
            return

        if not insp.has_table("users"):
            return

        cols = {c["name"]: c for c in insp.get_columns("users")}
        dialect = db.engine.dialect.name
        stmts = []

        if "name" not in cols:
            stmts.append("ALTER TABLE users ADD COLUMN name VARCHAR(120)")
        if "birthdate" not in cols:
            stmts.append("ALTER TABLE users ADD COLUMN birthdate DATE")
        if "profile_image" not in cols:
            stmts.append("ALTER TABLE users ADD COLUMN profile_image VARCHAR(200)")
        if "company_id" not in cols:
            stmts.append("ALTER TABLE users ADD COLUMN company_id INTEGER")
        if "auth_user_id" not in cols:
            if dialect == "postgresql":
                stmts.append("ALTER TABLE users ADD COLUMN auth_user_id UUID")
            else:
                stmts.append("ALTER TABLE users ADD COLUMN auth_user_id VARCHAR(36)")
        if "role" not in cols:
            stmts.append("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user'")

        pw_col = cols.get("password_hash")
        pw_len = getattr(pw_col["type"], "length", None) if pw_col else None
        if pw_len and pw_len < 255:
            if dialect == "postgresql":
                stmts.append("ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(255)")
            elif dialect in {"mysql", "mariadb"}:
                stmts.append("ALTER TABLE users MODIFY COLUMN password_hash VARCHAR(255) NOT NULL")

        try:
            with db.engine.begin() as conn:
                for s in stmts:
                    app.logger.warning("[migrate] %s", s)
                    conn.execute(text(s))
                conn.execute(text(
                    "UPDATE users "
                    "SET role = CASE "
                    "  WHEN role IS NULL OR TRIM(role) = '' THEN CASE WHEN LOWER(username) = 'admin' THEN 'admin' ELSE 'user' END "
                    "  ELSE role "
                    "END"
                ))
                if dialect == "postgresql":
                    conn.execute(text(
                        "DO $$ BEGIN "
                        "IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'ix_users_auth_user_id') THEN "
                        "  CREATE UNIQUE INDEX ix_users_auth_user_id ON users (auth_user_id) WHERE auth_user_id IS NOT NULL; "
                        "END IF; "
                        "END $$;"
                    ))
                    conn.execute(text(
                        "DO $$ BEGIN "
                        "IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check') THEN "
                        "  ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin','user')); "
                        "END IF; "
                        "END $$;"
                    ))
        except SQLAlchemyError as e:
            app.logger.error("[migrate] Failed to update users table: %s", e)

ensure_user_columns()

def ensure_medical_ownership_columns():
    with app.app_context():
        try:
            insp = inspect(db.engine)
        except SQLAlchemyError as e:
            app.logger.error("[migrate] Could not inspect database (medical ownership): %s", e)
            return

        stmts = []

        if insp.has_table("doctors"):
            doctor_cols = {c["name"] for c in insp.get_columns("doctors")}
            doctor_idxs = {ix.get("name") for ix in insp.get_indexes("doctors")}
            if "user_id" not in doctor_cols:
                stmts.append("ALTER TABLE doctors ADD COLUMN user_id INTEGER")
            if "ix_doctors_user_id" not in doctor_idxs:
                stmts.append("CREATE INDEX ix_doctors_user_id ON doctors (user_id)")

        if insp.has_table("patients"):
            patient_cols = {c["name"] for c in insp.get_columns("patients")}
            patient_idxs = {ix.get("name") for ix in insp.get_indexes("patients")}
            if "owner_user_id" not in patient_cols:
                stmts.append("ALTER TABLE patients ADD COLUMN owner_user_id INTEGER")
            if "ix_patients_owner_user_id" not in patient_idxs:
                stmts.append("CREATE INDEX ix_patients_owner_user_id ON patients (owner_user_id)")

        if insp.has_table("consults"):
            consult_cols = {c["name"] for c in insp.get_columns("consults")}
            consult_idxs = {ix.get("name") for ix in insp.get_indexes("consults")}
            if "owner_user_id" not in consult_cols:
                stmts.append("ALTER TABLE consults ADD COLUMN owner_user_id INTEGER")
            if "ix_consults_owner_user_id" not in consult_idxs:
                stmts.append("CREATE INDEX ix_consults_owner_user_id ON consults (owner_user_id)")

        try:
            with db.engine.begin() as conn:
                for s in stmts:
                    app.logger.warning("[migrate] %s", s)
                    conn.execute(text(s))

                # Backfill doctor profile owner from legacy ID matching.
                conn.execute(text(
                    "UPDATE doctors "
                    "SET user_id = id "
                    "WHERE user_id IS NULL "
                    "  AND EXISTS (SELECT 1 FROM users u WHERE u.id = doctors.id)"
                ))

                # Backfill patient owner from doctor profile owner.
                conn.execute(text(
                    "UPDATE patients "
                    "SET owner_user_id = (SELECT d.user_id FROM doctors d WHERE d.id = patients.doctor_id) "
                    "WHERE owner_user_id IS NULL "
                    "  AND doctor_id IS NOT NULL "
                    "  AND EXISTS (SELECT 1 FROM doctors d2 WHERE d2.id = patients.doctor_id AND d2.user_id IS NOT NULL)"
                ))
                # Legacy fallback where patient.doctor_id was actually users.id.
                conn.execute(text(
                    "UPDATE patients "
                    "SET owner_user_id = doctor_id "
                    "WHERE owner_user_id IS NULL "
                    "  AND doctor_id IS NOT NULL "
                    "  AND EXISTS (SELECT 1 FROM users u WHERE u.id = patients.doctor_id)"
                ))

                # Backfill consult owner from linked patient.
                conn.execute(text(
                    "UPDATE consults "
                    "SET owner_user_id = (SELECT p.owner_user_id FROM patients p WHERE p.id = consults.patient_id) "
                    "WHERE owner_user_id IS NULL "
                    "  AND EXISTS (SELECT 1 FROM patients p2 WHERE p2.id = consults.patient_id AND p2.owner_user_id IS NOT NULL)"
                ))
                # Legacy fallback where consult.doctor_id was actually users.id.
                conn.execute(text(
                    "UPDATE consults "
                    "SET owner_user_id = doctor_id "
                    "WHERE owner_user_id IS NULL "
                    "  AND doctor_id IS NOT NULL "
                    "  AND EXISTS (SELECT 1 FROM users u WHERE u.id = consults.doctor_id)"
                ))
        except SQLAlchemyError as e:
            app.logger.error("[migrate] Failed to ensure medical ownership columns: %s", e)

ensure_medical_ownership_columns()

def ensure_consult_patient_nullable():
    with app.app_context():
        try:
            insp = inspect(db.engine)
            if not insp.has_table("consults"):
                return
            cols = {c["name"]: c for c in insp.get_columns("consults")}
            patient_col = cols.get("patient_id")
            if not patient_col or patient_col.get("nullable", True):
                return

            dialect = db.engine.dialect.name
            stmt = None
            if dialect == "postgresql":
                stmt = "ALTER TABLE consults ALTER COLUMN patient_id DROP NOT NULL"
            elif dialect in {"mysql", "mariadb"}:
                stmt = "ALTER TABLE consults MODIFY COLUMN patient_id INTEGER NULL"
            elif dialect == "sqlite":
                app.logger.warning("[migrate] consults.patient_id is NOT NULL (SQLite requires manual migration).")
                return

            if stmt:
                with db.engine.begin() as conn:
                    app.logger.warning("[migrate] %s", stmt)
                    conn.execute(text(stmt))
        except SQLAlchemyError as e:
            app.logger.error("[migrate] Failed to update consults.patient_id nullability: %s", e)

ensure_consult_patient_nullable()

# ------------------------------------------------------------------------------
# RLS helpers (Supabase/Postgres)
# ------------------------------------------------------------------------------
_request_rls_user_id: ContextVar[Optional[int]] = ContextVar("request_rls_user_id", default=None)
_request_rls_auth_uid: ContextVar[Optional[str]] = ContextVar("request_rls_auth_uid", default=None)

def ensure_rls_helper_functions():
    with app.app_context():
        if db.engine.dialect.name != "postgresql":
            return
        stmts = [
            """
            CREATE OR REPLACE FUNCTION public.app_user_id()
            RETURNS integer
            LANGUAGE sql
            STABLE
            SECURITY DEFINER
            SET search_path = public
            AS $$
              SELECT COALESCE(
                (SELECT u.id FROM public.users u WHERE u.auth_user_id = auth.uid() LIMIT 1),
                NULLIF(current_setting('app.current_user_id', true), '')::integer
              );
            $$;
            """,
            """
            CREATE OR REPLACE FUNCTION public.app_company_id()
            RETURNS integer
            LANGUAGE sql
            STABLE
            SECURITY DEFINER
            SET search_path = public
            AS $$
              SELECT u.company_id
              FROM public.users u
              WHERE u.id = public.app_user_id()
              LIMIT 1;
            $$;
            """,
            """
            CREATE OR REPLACE FUNCTION public.is_admin()
            RETURNS boolean
            LANGUAGE sql
            STABLE
            SECURITY DEFINER
            SET search_path = public
            AS $$
              SELECT EXISTS (
                SELECT 1
                FROM public.users u
                WHERE u.id = public.app_user_id()
                  AND (LOWER(COALESCE(u.role, 'user')) = 'admin' OR LOWER(COALESCE(u.username, '')) = 'admin')
              );
            $$;
            """
        ]
        try:
            with db.engine.begin() as conn:
                for stmt in stmts:
                    conn.execute(text(stmt))
        except SQLAlchemyError as e:
            app.logger.warning("[migrate] Failed to ensure RLS helper functions: %s", e)

def apply_rls_context(*, user_id: Optional[int], auth_uid: Optional[str] = None) -> None:
    uid = int(user_id) if user_id is not None else None
    sub = (auth_uid or "").strip() or None
    _request_rls_user_id.set(uid)
    _request_rls_auth_uid.set(sub)

    if db.engine.dialect.name != "postgresql":
        return

    try:
        db.session.execute(
            text("SELECT set_config('app.current_user_id', :uid, false)"),
            {"uid": str(uid) if uid is not None else ""}
        )
        db.session.execute(
            text("SELECT set_config('request.jwt.claim.sub', :sub, false)"),
            {"sub": sub or ""}
        )
        db.session.execute(
            text("SELECT set_config('request.jwt.claim.role', :role, false)"),
            {"role": "authenticated" if uid is not None else "anon"}
        )
    except SQLAlchemyError as e:
        app.logger.warning("Falha ao aplicar contexto de RLS no Postgres: %s", e)

ensure_rls_helper_functions()

# ------------------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------------------
def get_logged_user():
    uid = session.get('user_id')
    if not uid:
        return None
    try:
        return db.session.get(User, uid)
    except OperationalError as e:
        app.logger.warning("Falha de conexão ao carregar usuário da sessão; tentando reconectar: %s", e)
        try:
            db.session.rollback()
        except Exception:
            pass
        try:
            db.session.remove()
        except Exception:
            pass
        try:
            return db.session.get(User, uid)
        except Exception as e2:
            app.logger.error("Erro persistente ao carregar usuário da sessão: %s", e2)
            return None

@app.before_request
def attach_request_rls_context():
    uid = parse_int(session.get("user_id"))
    auth_uid = session.get("auth_user_id")
    apply_rls_context(user_id=uid, auth_uid=auth_uid if isinstance(auth_uid, str) else None)

@app.teardown_request
def clear_request_rls_context(_exc):
    _request_rls_user_id.set(None)
    _request_rls_auth_uid.set(None)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_logged_user()
        if not user:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Agora não precisamos mais validar plano, sempre libera
def has_feature(user, feature):
    return True

def feature_required(feature):
    def inner(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_logged_user()
            if not user:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapper
    return inner

def quotes_section_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not QUOTES_SECTION_ENABLED:
            abort(404)
        return f(*args, **kwargs)
    return wrapper

def is_admin(user: Optional[User]) -> bool:
    if not user:
        return False
    role = (getattr(user, "role", "") or "").strip().lower()
    username = (getattr(user, "username", "") or "").strip().lower()
    return role == "admin" or username == "admin"

def profile_image_url(user: Optional[User]) -> str:
    default_path = url_for("static", filename="images/user-icon.png")
    if not user:
        return default_path
    raw = (user.profile_image or "").strip()
    if not raw:
        return default_path
    if raw.startswith("/files/"):
        return raw
    if raw.startswith("files/"):
        return f"/{raw}"
    if raw.startswith(("http://", "https://", "/")):
        return raw
    return url_for("static", filename=raw)

@app.context_processor
def inject_sidebar_auth_context():
    """
    Garante contexto de autenticação para o sidebar em qualquer template,
    mesmo quando a rota não passa `username` explicitamente.
    """
    user = get_logged_user()
    username = (user.username if user else None)
    return {
        "username": username,
        "is_admin_sidebar": is_admin(user),
    }

def can_manage_patient(user: Optional[User], patient: Optional[Patient]) -> bool:
    if not user or not patient:
        return False
    if is_admin(user):
        return True
    if patient.owner_user_id is not None:
        return patient.owner_user_id == user.id
    if patient.doctor and patient.doctor.user_id is not None:
        return patient.doctor.user_id == user.id
    # Legacy fallback (old rows used patient.doctor_id as users.id)
    return patient.doctor_id == user.id

def can_manage_doctor_profile(user: Optional[User], doctor: Optional[Doctor]) -> bool:
    if not user or not doctor:
        return False
    return is_admin(user) or (doctor.user_id == user.id)

def get_user_public_doctor_profile(
    *,
    user: User,
    create_if_missing: bool = False,
    fallback_name: Optional[str] = None
) -> Optional[Doctor]:
    profile = Doctor.query.filter_by(user_id=user.id).order_by(Doctor.id.asc()).first()
    if profile or not create_if_missing:
        return profile

    base_name = (fallback_name or user.name or user.username or f"Profissional {user.id}").strip()
    profile = Doctor(name=base_name[:120], phone=None, user_id=user.id)
    db.session.add(profile)
    db.session.commit()
    return profile

# Expor helpers no Jinja (mantendo compatibilidade nos templates)
app.jinja_env.globals.update(
    has_feature=has_feature,
    pdf_token=generate_file_token,
    make_pdf_token=generate_file_token,
    profile_image_url=profile_image_url,
)

def parse_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        if isinstance(value, str):
            s = value.strip()
            if s == "":
                return None
            return int(s)
        return int(value)
    except (TypeError, ValueError):
        return None

def render_html_pdf_bytes(html: str, base_url: str) -> bytes:
    """
    Importa o WeasyPrint sob demanda para não quebrar o startup do app
    quando dependências nativas não estiverem instaladas no host.
    """
    timeout_env = parse_int(os.getenv("PDF_RENDER_TIMEOUT_SECONDS"))
    timeout_seconds = timeout_env if timeout_env and timeout_env > 0 else 20

    class _PdfRenderTimeout(Exception):
        pass

    timer_enabled = False
    old_handler = None
    sig = None

    # Evita que uma importação/renderização travada mate o worker por timeout do Gunicorn.
    try:
        import signal as sig  # type: ignore
        if hasattr(sig, "SIGALRM") and hasattr(sig, "setitimer"):
            try:
                def _raise_timeout(_signum, _frame):
                    raise _PdfRenderTimeout(f"Geração de PDF excedeu {timeout_seconds}s.")
                old_handler = sig.signal(sig.SIGALRM, _raise_timeout)
                sig.setitimer(sig.ITIMER_REAL, float(timeout_seconds))
                timer_enabled = True
            except ValueError:
                timer_enabled = False
    except Exception:
        timer_enabled = False

    try:
        try:
            import weasyprint  # type: ignore
        except _PdfRenderTimeout as e:
            raise RuntimeError(str(e)) from e
        except Exception as e:
            raise RuntimeError("WeasyPrint não disponível no ambiente.") from e

        try:
            return weasyprint.HTML(string=html, base_url=base_url).write_pdf()
        except _PdfRenderTimeout as e:
            raise RuntimeError(str(e)) from e
        except Exception as e:
            raise RuntimeError("Falha ao gerar PDF com WeasyPrint.") from e
    finally:
        if timer_enabled and sig is not None:
            try:
                sig.setitimer(sig.ITIMER_REAL, 0.0)
                if old_handler is not None:
                    sig.signal(sig.SIGALRM, old_handler)
            except Exception:
                pass

# ------------------------------------------------------------------------------
# Public pages & auth
# ------------------------------------------------------------------------------
@app.route('/schedule_consultation')
def schedule_consultation():
    doctors = Doctor.query.filter(Doctor.user_id.isnot(None)).order_by(Doctor.name).all()
    return render_template('schedule_consultation.html', doctors=doctors)

@app.route('/')
def hero():
    return render_template('hero.html')

@app.route('/plano-de-empresas')
def companies_plan():
    return render_template('companies_plan.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms')
def terms():
    return render_template("terms.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        coming_from_register_post = session.pop('register_flash', None)
        if not coming_from_register_post:
            session.pop('register_form', None)
        form = session.get('register_form', {})
        return render_template('register.html', form=form)

    username     = (request.form.get('username', '')).strip()
    email        = (request.form.get('email', '')).strip().lower()
    password     = request.form.get('password', '')
    confirm      = request.form.get('confirm_password', '')
    company_code = (request.form.get('company_code', '')).strip().upper()
    account_type = (request.form.get('account_type', '')).strip().lower()

    def stash_form():
        session['register_form'] = {
            "username": username,
            "email": email,
            "company_code": company_code,
            "account_type": account_type,
        }

    if account_type not in {"pessoal", "empresa"}:
        stash_form()
        session['register_flash'] = True
        flash('Selecione o tipo de cadastro.', 'warning')
        return redirect(url_for('register'))

    if not username:
        stash_form()
        session['register_flash'] = True
        flash('Nome de usuário é obrigatório.', 'warning')
        return redirect(url_for('register'))
    if len(username) > 80:
        stash_form()
        session['register_flash'] = True
        flash('Nome de usuário muito longo.', 'warning')
        return redirect(url_for('register'))

    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        stash_form()
        session['register_flash'] = True
        flash('E-mail inválido.', 'warning')
        return redirect(url_for('register'))
    if len(email) > 120:
        stash_form()
        session['register_flash'] = True
        flash('E-mail muito longo.', 'warning')
        return redirect(url_for('register'))

    exists_email = User.query.filter_by(email=email).first()
    exists_user  = User.query.filter_by(username=username).first()
    if exists_email or exists_user:
        stash_form()
        session['register_flash'] = True
        flash('E-mail ou usuário já cadastrado.', 'warning')
        return redirect(url_for('register'))

    if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        stash_form()
        session['register_flash'] = True
        flash('A senha deve ter 8+ caracteres, letras, números e um símbolo.', 'warning')
        return redirect(url_for('register'))
    if password != confirm:
        stash_form()
        session['register_flash'] = True
        flash('As senhas não coincidem.', 'warning')
        return redirect(url_for('register'))

    company = None
    if account_type == "empresa":
        if not company_code:
            stash_form()
            session['register_flash'] = True
            flash('Código da empresa é obrigatório.', 'warning')
            return redirect(url_for('register'))
        if len(company_code) > 50:
            stash_form()
            session['register_flash'] = True
            flash('Código da empresa muito longo.', 'warning')
            return redirect(url_for('register'))
        company = Company.query.filter_by(access_code=company_code).first()
        if not company:
            stash_form()
            session['register_flash'] = True
            flash('Código da empresa inválido.', 'danger')
            return redirect(url_for('register'))

    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        company_id=company.id if company else None,
        role="user"
    )
    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        stash_form()
        session['register_flash'] = True
        flash('E-mail ou usuário já cadastrado.', 'warning')
        return redirect(url_for('register'))
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error("Erro ao criar usuário: %s", e)
        stash_form()
        session['register_flash'] = True
        flash('Erro interno ao criar cadastro. Tente novamente.', 'danger')
        return redirect(url_for('register'))

    session.pop('register_form', None)
    flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        login_input = request.form.get('login', '').strip()
        pwd         = request.form.get('password', '')

        if login_input.lower() == 'admin':
            user = User.query.filter_by(username='admin').first()
        else:
            user = User.query.filter_by(email=login_input.lower()).first()

        if not user or not check_password_hash(user.password_hash, pwd):
            error = 'Usuário ou senha inválidos.'
        else:
            session['user_id']  = user.id
            session['username'] = user.username
            session['auth_user_id'] = getattr(user, "auth_user_id", None)
            session['role'] = getattr(user, "role", "user")
            apply_rls_context(
                user_id=user.id,
                auth_uid=getattr(user, "auth_user_id", None)
            )
            return redirect(url_for('index'))

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('auth_user_id', None)
    session.pop('role', None)
    apply_rls_context(user_id=None, auth_uid=None)
    return redirect(url_for('login'))

@app.route('/account')
def account():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('account.html', user=user)

@app.route('/update_personal_info', methods=['POST'])
def update_personal_info():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    fname = request.form.get("name", "").strip()
    sname = request.form.get("secondname", "").strip()
    bd    = (request.form.get("birthdate", "") or "").strip()
    email = request.form.get("email", "").strip()
    user.name = f"{fname} {sname}".strip()
    if bd:
        parsed_birthdate = None
        for fmt in ("%d/%m/%Y", "%Y-%m-%d"):
            try:
                parsed_birthdate = datetime.strptime(bd, fmt).date()
                break
            except ValueError:
                continue
        if parsed_birthdate:
            user.birthdate = parsed_birthdate
    user.email = email
    img = request.files.get("profile_image")
    if img and img.filename:
        from werkzeug.utils import secure_filename
        raw = img.read()
        sf = save_secure_file(
            owner_user_id=user.id,
            kind="profile_image",
            filename=secure_filename(img.filename),
            mime_type=img.mimetype,
            raw_bytes=raw,
        )
        # store only the ID or a signed URL
        user.profile_image = f"/files/{sf.id}"  # or store sf.id in a new user.profile_image_id column
    db.session.commit()
    return redirect(url_for("account"))

@app.route('/update_password', methods=['POST'])
def update_password():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    cur = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    conf= request.form.get("confirm_password", "")
    if not check_password_hash(user.password_hash, cur):
        flash("Senha atual incorreta.", "danger")
        return redirect(url_for("account"))
    if new != conf:
        flash("As senhas não coincidem.", "danger")
        return redirect(url_for("account"))
    user.password_hash = generate_password_hash(new)
    db.session.commit()
    flash("Senha atualizada.", "success")
    return redirect(url_for("account"))

@app.route('/remove_profile_image', methods=['POST'])
def remove_profile_image():
    user = get_logged_user() or abort(403)
    user.profile_image = 'images/user-icon.png'
    db.session.commit()
    return redirect(url_for("account"))

# ------------------------------------------------------------------------------
# Upload / Dashboard
# ------------------------------------------------------------------------------
@app.route('/RafahMed-lab')
def RafahMed_lab():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    pkg = get_package_info(user.id)
    if pkg['total'] - pkg['used'] <= 0:
        return redirect(url_for('purchase'))

    return render_template('upload.html')

@app.route('/index')
def index():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    used = getattr(user, 'packets_used', 0) or 0
    remaining = getattr(user, 'packets_remaining', 50) or 50

    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=6)

    quizzes = QuizResult.query.filter_by(doctor_id=user.id).all()

    date_counts = { (week_ago + timedelta(days=i)).strftime('%d/%m'): 0 for i in range(7) }
    dep_stats = defaultdict(lambda: {'sum_score': 0, 'num': 0})

    score_map = {'BAIXO': 1, 'NORMAL/LEVE': 2, 'MODERADO': 3, 'ALTO': 4}
    inv_map = {v: k for k, v in score_map.items()}

    for q in quizzes:
        q_date = q.date if isinstance(q.date, datetime) else datetime.strptime(q.date, '%Y-%m-%d')
        q_date = q_date.date()
        if week_ago <= q_date <= today:
            key = q_date.strftime('%d/%m')
            date_counts[key] += 1
            dep_stats[key]['sum_score'] += score_map.get(q.depressao, 0)
            dep_stats[key]['num'] += 1

    quiz_chart_data = []
    cum_count = 0
    for i in range(7):
        dia = week_ago + timedelta(days=i)
        key = dia.strftime('%d/%m')
        cnt = date_counts[key]
        cum_count += cnt
        mavg = round(cum_count / (i + 1), 2)
        stats = dep_stats[key]
        if stats['num']:
            avg_score = stats['sum_score'] / stats['num']
            dep_class = inv_map.get(round(avg_score))
        else:
            avg_score = 0.0
            dep_class = None
        quiz_chart_data.append({
            'date': key, 'count': cnt, 'media': mavg,
            'dep_avg': round(avg_score, 2), 'dep_class': dep_class
        })

    return render_template(
        'index.html',
        quiz_chart_data=quiz_chart_data,
        used=used,
        remaining=remaining,
        username=user.username,
        user=user
    )

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    flash('Módulo Ponza Lab removido.', 'info')
    return redirect(url_for('index'))


# ------------------------------------------------------------------------------
# Pagamentos (Pacotes de Análises)
# ------------------------------------------------------------------------------
@app.route('/purchase', methods=['GET', 'POST'])
def purchase():
    user = get_logged_user()
    if request.method == 'POST':
        pacote = request.form.get('package', '')
        valor  = {'50': 120, '150': 300, '500': 950}.get(pacote)
        if not valor:
            flash('Selecione um pacote válido.', 'warning')
            return redirect(url_for('purchase'))

        # Usa função existente para gerar link de pagamento (Mercado Pago, etc.)
        link = generate_payment_link(pacote, valor)
        return redirect(link or url_for('pagamento_falha'))

    return render_template('purchase.html')

@app.route('/pagamento_falha')
def pagamento_falha():
    flash('Não foi possível gerar o link de pagamento. Tente novamente.', 'danger')
    return redirect(url_for('purchase'))

# ------------------------------------------------------------------------------
# Agenda / disponibilidade
# ------------------------------------------------------------------------------
@app.route('/agenda')
@login_required
def agenda():
    user = get_logged_user()
    return render_template('agenda.html', user=user, username=(user.username if user else None))

@app.route('/doctors')
@login_required
def doctors():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    q = Doctor.query
    if not is_admin(user):
        q = q.filter_by(user_id=user.id)
    doctors = q.order_by(Doctor.name).all()
    return render_template('doctors.html', doctors=doctors, user=user)

@app.route('/add_doctor', methods=['POST'])
@login_required
def add_doctor_route():
    user = get_logged_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    name  = (data.get('name') or request.form.get('name') or '').strip()
    phone = (data.get('phone') or request.form.get('phone') or '').strip()

    if not name:
        return jsonify({"ok": False, "error": "Nome obrigatório"}), 400

    if Doctor.query.filter_by(name=name, user_id=user.id).first():
        return jsonify({"ok": False, "error": "Já existe um prescritor com esse nome"}), 400

    doctor = Doctor(name=name, phone=phone or None, user_id=user.id)
    db.session.add(doctor)
    db.session.commit()

    return jsonify({"ok": True, "doctor": {"id": doctor.id, "name": doctor.name}})

@app.route('/update_doctor/<int:doctor_id>', methods=['POST'])
@login_required
def update_doctor(doctor_id):
    user = get_logged_user()
    doctor = Doctor.query.get_or_404(doctor_id)
    if not can_manage_doctor_profile(user, doctor):
        flash("Acesso negado.", "danger")
        return redirect(url_for("doctors"))
    doctor.name      = (request.form.get('name') or doctor.name).strip()
    doctor.phone     = (request.form.get('phone') or doctor.phone or '').strip() or None
    db.session.commit()
    flash("Prescritor atualizado!", "success")
    return redirect(url_for("doctors"))

@app.route('/delete_doctor/<int:doctor_id>', methods=['POST'])
@login_required
def delete_doctor(doctor_id):
    user = get_logged_user()
    wants_json = request.accept_mimetypes.best == "application/json"
    if not user:
        if wants_json:
            return jsonify({"ok": False, "error": "unauthorized"}), 403
        return redirect(url_for('login'))

    doc = db.session.get(Doctor, doctor_id)
    if not doc:
        if wants_json:
            return jsonify({"ok": False, "error": "Médico não encontrado."}), 404
        flash("Médico não encontrado.", "warning")
        return redirect(url_for("doctors"))

    if not can_manage_doctor_profile(user, doc):
        if wants_json:
            return jsonify({"ok": False, "error": "Acesso negado."}), 403
        flash("Acesso negado.", "danger")
        return redirect(url_for("doctors"))

    try:
        DoctorDateAvailability.query.filter_by(doctor_id=doctor_id).delete(synchronize_session=False)
        DoctorAvailability.query.filter_by(doctor_id=doctor_id).delete(synchronize_session=False)

        replacement_id = None
        if doc.user_id:
            replacement = (
                Doctor.query
                .filter(Doctor.user_id == doc.user_id, Doctor.id != doctor_id)
                .order_by(Doctor.id.asc())
                .first()
            )
            # Não recria mais perfil automaticamente ao excluir:
            # se não houver outro, removemos vínculos conforme regras abaixo.
            replacement_id = replacement.id if replacement else None

        if replacement_id:
            Patient.query.filter_by(doctor_id=doctor_id).update({"doctor_id": replacement_id}, synchronize_session=False)
            Consult.query.filter_by(doctor_id=doctor_id).update({"doctor_id": replacement_id}, synchronize_session=False)
        else:
            Patient.query.filter_by(doctor_id=doctor_id).update({"doctor_id": None}, synchronize_session=False)
            Consult.query.filter_by(doctor_id=doctor_id).delete(synchronize_session=False)

        db.session.delete(doc)
        db.session.commit()
        if wants_json:
            return jsonify({"ok": True})
        flash("Prescritor excluído com todas as dependências removidas.", "info")
        return redirect(url_for("doctors"))

    except Exception as e:
        db.session.rollback()
        if wants_json:
            return jsonify({"ok": False, "error": str(e)}), 500
        flash("Erro ao excluir médico.", "danger")
        return redirect(url_for("doctors"))

@app.route('/availability', methods=['GET', 'POST'])
@login_required
def availability():
    # ONly admin
    user = get_logged_user()
    if not user or not is_admin(user):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    raw_doctor_id = request.args.get('doctor_id')  # Optional[str]

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        if raw_doctor_id is None:
            raw_doctor_id = data.get('doctor_id')

        doctor_id = parse_int(raw_doctor_id)
        if doctor_id is None:
            return jsonify({"ok": False, "error": "doctor_id inválido"}), 400

        blocks = data.get('blocks') or []
        if not isinstance(blocks, list):
            return jsonify({"ok": False, "error": "`blocks` deve ser uma lista"}), 400

        new_rows = []
        for i, b in enumerate(blocks):
            if not isinstance(b, dict):
                return jsonify({"ok": False, "error": f"blocks[{i}] deve ser um objeto"}), 400

            weekday = parse_int(b.get('weekday'))
            if weekday is None or weekday < 0 or weekday > 6:
                return jsonify({"ok": False, "error": f"blocks[{i}].weekday inválido (0..6)"}), 400

            start_raw = str(b.get('start', ''))
            end_raw   = str(b.get('end', ''))
            try:
                start_t = datetime.strptime(start_raw, '%H:%M').time()
                end_t   = datetime.strptime(end_raw,   '%H:%M').time()
            except ValueError:
                return jsonify({"ok": False, "error": f"blocks[{i}] horários inválidos (use HH:MM)"}), 400

            slot = parse_int(b.get('slot'))
            if slot is None or slot <= 0:
                slot = 30

            if end_t <= start_t:
                return jsonify({"ok": False, "error": f"blocks[{i}] end deve ser maior que start"}), 400

            new_rows.append(
                DoctorAvailability(
                    doctor_id=doctor_id,
                    weekday=weekday,
                    start_time=start_t,
                    end_time=end_t,
                    slot_minutes=slot
                )
            )

        DoctorAvailability.query.filter_by(doctor_id=doctor_id).delete(synchronize_session=False)
        db.session.add_all(new_rows)
        db.session.commit()
        return jsonify({"ok": True})

    # GET: listar disponibilidade de um médico
    doctor_id = parse_int(raw_doctor_id)
    if doctor_id is None:
        return jsonify([])

    rows = DoctorAvailability.query.filter_by(doctor_id=doctor_id).all()
    return jsonify([
        {
            "weekday": r.weekday,
            "start": r.start_time.strftime('%H:%M'),
            "end":   r.end_time.strftime('%H:%M'),
            "slot":  r.slot_minutes
        } for r in rows
    ])

DID_COL  = cast(Any, Consult.doctor_id)
DATE_COL = cast(Any, Consult.date)
TIME_COL = cast(Any, Consult.time)
DA_DID_COL  = cast(Any, DoctorDateAvailability.doctor_id)

@app.route('/availability_dates', methods=['GET', 'POST'])
@login_required
def availability_dates():
    # apenas admin
    user = get_logged_user()
    if not user or not is_admin(user):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    raw_doctor_id = request.args.get('doctor_id') or (request.get_json(silent=True) or {}).get('doctor_id')
    doctor_id = parse_int(raw_doctor_id)
    if doctor_id is None:
        return jsonify({"ok": False, "error": "doctor_id inválido"}), 400

    if request.method == 'GET':
        rows = DoctorDateAvailability.query.filter_by(doctor_id=doctor_id).order_by(
            DoctorDateAvailability.day.asc(), DoctorDateAvailability.start_time.asc()
        ).all()
        return jsonify([
            {
                "id": r.id,
                "day": r.day.strftime('%d/%m/%Y'),
                "start": r.start_time.strftime('%H:%M'),
                "end": r.end_time.strftime('%H:%M'),
                "slot": r.slot_minutes
            } for r in rows
        ])

    data = request.get_json(silent=True) or {}
    blocks = data.get('blocks') or []
    if not isinstance(blocks, list):
        return jsonify({"ok": False, "error": "`blocks` deve ser lista"}), 400

    print("[availability_dates] received blocks:", data)

    # capturar blocos antigos p/ descobrir quais foram removidos
    old_rows = DoctorDateAvailability.query.filter_by(doctor_id=doctor_id).all()
    old_set = {
        (r.day, r.start_time.strftime('%H:%M'), r.end_time.strftime('%H:%M'))
        for r in old_rows
    }

    new_rows = []
    new_set = set()
    for i, b in enumerate(blocks):
        try:
            day_pt = str(b.get('day', '')).strip()          # dd/mm/aaaa
            start_raw = str(b.get('start', '')).strip()     # HH:MM
            end_raw = str(b.get('end', '')).strip()         # HH:MM
            slot = parse_int(b.get('slot')) or 30

            day = datetime.strptime(day_pt, '%d/%m/%Y').date()
            start_t = datetime.strptime(start_raw, '%H:%M').time()
            end_t = datetime.strptime(end_raw, '%H:%M').time()
            if end_t <= start_t:
                return jsonify({"ok": False, "error": f"blocks[{i}] end deve ser > start"}), 400

            new_rows.append(DoctorDateAvailability(
                doctor_id=doctor_id,
                day=day,
                start_time=start_t,
                end_time=end_t,
                slot_minutes=slot
            ))
            new_set.add((day, start_raw, end_raw))
        except Exception as e:
            return jsonify({"ok": False, "error": f"blocks[{i}] inválido ({e})"}), 400

    # sobrescrever
    DoctorDateAvailability.query.filter_by(doctor_id=doctor_id).delete(synchronize_session=False)

    for nr in new_rows:
        db.session.add(nr)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": f"Erro ao salvar disponibilidade: {e}"}), 500

    # identify removed blocks and delete consults within it
    removed = old_set - new_set
    for day, start_s, end_s in removed:
        s_t = datetime.strptime(start_s, '%H:%M').time()
        e_t = datetime.strptime(end_s, '%H:%M').time()
        Consult.query.filter(
            and_(
                DID_COL == doctor_id,
                DATE_COL == day,
                TIME_COL.isnot(None),
                TIME_COL >= s_t,
                TIME_COL <  e_t,
            )
        ).delete(synchronize_session=False)
    db.session.commit()

    return jsonify({"ok": True})

@app.route('/api/available_days')
def api_available_days():
    doctor_id = request.args.get('doctor_id', type=int)
    days_ahead = request.args.get('days', default=45, type=int)
    if not doctor_id:
        return jsonify([])

    today = datetime.utcnow().date()
    end_day = today + timedelta(days=days_ahead)

    day_rows = DoctorDateAvailability.query.filter(
        DA_DID_COL == doctor_id,
        DoctorDateAvailability.day >= today,
        DoctorDateAvailability.day <= end_day
    ).all()

    by_day = {}
    for r in day_rows:
        by_day.setdefault(r.day, []).append(r)

    result = []
    for day, blocks in sorted(by_day.items()):
        taken = {
            c.time.strftime('%H:%M')
            for c in Consult.query.filter_by(doctor_id=doctor_id, date=day)
                                  .filter(Consult.time.is_not(None)).all() #type:ignore
        }

        free_count = 0
        for b in blocks:
            cur = datetime.combine(day, b.start_time)
            end = datetime.combine(day, b.end_time)
            step = timedelta(minutes=b.slot_minutes or 30)
            while cur <= end - step + timedelta(seconds=1):
                hm = cur.strftime('%H:%M')
                if hm not in taken:
                    free_count += 1
                cur += step

        if free_count > 0:
            result.append(day.strftime('%d/%m/%Y'))

    return jsonify(result)


@app.route('/api/available_slots')
def api_available_slots():
    doctor_id = request.args.get('doctor_id', type=int)
    date_str  = request.args.get('date', type=str)  # dd/mm/yyyy
    if not doctor_id or not date_str:
        return jsonify([])

    try:
        day = datetime.strptime(date_str, '%d/%m/%Y').date()
    except ValueError:
        return jsonify([])

    blocks = DoctorDateAvailability.query.filter_by(doctor_id=doctor_id, day=day).all()
    if not blocks:
        # if nothing is scheduled for this date -> nothing available
        return jsonify([])

    taken = {
        c.time.strftime('%H:%M')
        for c in Consult.query.filter_by(doctor_id=doctor_id, date=day)
                              .filter(TIME_COL.isnot(None)).all()
    }

    free = []
    for b in blocks:
        cur = datetime.combine(day, b.start_time)
        end = datetime.combine(day, b.end_time)
        step = timedelta(minutes=b.slot_minutes or 30)
        while cur <= end - step + timedelta(seconds=1):
            hm = cur.strftime('%H:%M')
            if hm not in taken:
                free.append(hm)
            cur += step

    return jsonify(sorted(free))

@app.route('/admin/availability')
@login_required
def admin_availability_page():
    user = get_logged_user()
    if not user or not is_admin(user):
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))
    docs = Doctor.query.order_by(Doctor.name).all()
    return render_template('admin_availability.html', doctors=docs, user=user)

# ------------------------------------------------------------------------------
# Companies / PDFs (admin)
# ------------------------------------------------------------------------------
ALLOWED_EXTENSIONS = {'pdf'}
PDF_UPLOAD_DIR = os.path.join(app.root_path, 'uploads', 'pdfs')  # admin repo
os.makedirs(PDF_UPLOAD_DIR, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------------------
# Admin — empresas (criar & listar)
# ---------------------------
@app.route('/admin/companies', methods=['GET', 'POST'])
@login_required
def admin_companies():
    user = get_logged_user()
    if not user or not is_admin(user):
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        code = (request.form.get('code') or '').strip()
        if not name:
            flash('Nome da empresa é obrigatório.', 'danger')
            return redirect(url_for('admin_companies'))
        comp = Company(name=name, access_code=code)
        db.session.add(comp)
        db.session.commit()
        flash('Empresa criada com sucesso!', 'success')
        return redirect(url_for('admin_companies'))

    companies = Company.query.order_by(Company.name).all()
    users = User.query.order_by(User.id).all()

    return render_template(
        'admin_companies.html',
        companies=companies,
        users=users
    )

def save_secure_file(*, owner_user_id, kind, filename, mime_type, raw_bytes):
    token = FERNET.encrypt(raw_bytes)
    obj = SecureFile(
        owner_user_id=owner_user_id,
        kind=kind,
        filename=filename or "file.bin",
        mime_type=mime_type or "application/octet-stream",
        size_bytes=len(raw_bytes),
        data=token,
    )
    db.session.add(obj)
    db.session.commit()
    return obj

def read_secure_file_bytes(file_id: int) -> tuple[bytes, SecureFile]:
    sf = SecureFile.query.get_or_404(file_id)
    raw = FERNET.decrypt(sf.data)
    return raw, sf

# ---------------------------
# Admin — deletar empresa
# ---------------------------
@app.route('/admin/companies/<int:company_id>/delete', methods=['POST'])
@login_required
def delete_company(company_id):
    user = get_logged_user()
    if not user or not is_admin(user):
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))

    comp = db.session.get(Company, company_id)
    if not comp:
        flash('Empresa não encontrada.', 'warning')
        return redirect(url_for('admin_companies'))

    db.session.delete(comp)
    db.session.commit()
    flash('Empresa removida.', 'success')
    return redirect(url_for('admin_companies'))

# ---------------------------
# Admin — repositório de PDFs (página separada)
# ---------------------------
@app.route('/admin/pdfs', methods=['GET'])
@login_required
def admin_pdfs():
    user = get_logged_user()
    if not user or not is_admin(user):
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))

    pdfs = PdfFile.query.order_by(desc(getattr(PdfFile, 'uploaded_at'))).all()
    return render_template('admin_pdfs.html', pdfs=pdfs, upload_url=url_for('upload_pdf'))

# ---------------------------
# Admin — upload de PDF (salva em PDF_UPLOAD_DIR)
# ---------------------------
@app.route('/admin/pdfs/upload', methods=['POST'])
@login_required
def upload_pdf():
    user = get_logged_user()
    if not user or not is_admin(user):
        flash('Acesso negado.', 'danger')
        return redirect(url_for('admin_pdfs'))

    f = request.files.get('file')
    if f is None or not getattr(f, 'filename', None):
        flash('Selecione um arquivo.', 'danger')
        return redirect(url_for('admin_pdfs'))

    from werkzeug.utils import secure_filename
    raw = f.read()

    original_name: str = f.filename or "upload.pdf"
    safe_name: str = secure_filename(original_name)
    mime: str = (getattr(f, 'mimetype', None) or "application/pdf")

    sf = save_secure_file(
        owner_user_id=user.id,
        kind="admin_pdf",
        filename=safe_name,
        mime_type=mime,
        raw_bytes=raw
    )

    pdf = PdfFile(
        filename=sf.filename,
        original_name=original_name,
        size_bytes=sf.size_bytes,
        secure_file_id=sf.id,  # link to bytes
    )
    db.session.add(pdf)
    db.session.commit()

    flash('Arquivo enviado com sucesso!', 'success')
    return redirect(url_for('admin_pdfs'))

@app.get('/pdfs/view/<int:file_id>')
def view_pdf(file_id):
    user = get_logged_user()
    if not user or not is_admin(user):
        abort(403)
    pdf = PdfFile.query.get_or_404(file_id)
    if not pdf.secure_file_id:
        abort(404)
    return redirect(url_for('file_download_auth', file_id=pdf.secure_file_id))

@app.get('/pdfs/download/<int:file_id>')
def download_pdf_admin(file_id):
    user = get_logged_user()
    if not user or not is_admin(user):
        abort(403)
    pdf = PdfFile.query.get_or_404(file_id)
    if not pdf.secure_file_id:
        abort(404)
    raw, sf = read_secure_file_bytes(pdf.secure_file_id)
    resp = make_response(raw)
    resp.headers["Content-Type"] = sf.mime_type
    resp.headers["Content-Disposition"] = f'attachment; filename="{pdf.original_name or sf.filename}"'
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return resp

@app.get('/pdfs/s/<token>')
def view_pdf_signed(token):
    file_id = verify_file_token(token, max_age_seconds=3600)
    if not file_id:
        abort(403)
    return redirect(url_for('file_download_auth', file_id=file_id))

@app.get('/pdfs/d/<token>')
def download_pdf_signed(token):
    file_id = verify_file_token(token, max_age_seconds=3600)
    if not file_id:
        abort(403)
    raw, sf = read_secure_file_bytes(file_id)
    resp = make_response(raw)
    resp.headers["Content-Type"] = sf.mime_type
    resp.headers["Content-Disposition"] = f'attachment; filename="{sf.filename}"'
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return resp

@app.route('/admin/pdfs/<int:pdf_id>/delete', methods=['POST'])
@login_required
def delete_pdf(pdf_id):
    user = get_logged_user()
    if not user or not is_admin(user):
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))

    if 'PdfFile' not in globals():
        flash('Modelo PdfFile não encontrado.', 'danger')
        return redirect(url_for('admin_pdfs'))

    pdf = db.session.get(PdfFile, pdf_id)
    if not pdf:
        flash('Arquivo não encontrado.', 'warning')
        return redirect(url_for('admin_pdfs'))

    try:
        if getattr(pdf, 'path', None) and os.path.exists(pdf.path):
            os.remove(pdf.path)
    except Exception:
        pass

    db.session.delete(pdf)
    db.session.commit()
    flash('Arquivo removido.', 'success')
    return redirect(url_for('admin_pdfs'))

# ------------------------------------------------------------------------------
# Patients / consults
# ------------------------------------------------------------------------------
@app.route('/users')
def list_users():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    if not is_admin(user):
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))
    users = User.query.order_by(User.id).all()
    return render_template('users.html', users=users)

@app.route('/save_consult/<int:patient_id>', methods=['POST'])
@login_required
def save_consult(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    patient = get_patient_by_id(patient_id)
    if not can_manage_patient(user, patient):
        abort(403)
    notes = request.form.get('notes', '').strip()
    if not notes:
        flash('Notas obrigatórias.', 'warning')
        return redirect(url_for('patient_result', patient_id=patient_id))
    profile = get_user_public_doctor_profile(user=user, create_if_missing=True)
    consult_doctor_id = patient.doctor_id or (profile.id if profile else None)
    if not consult_doctor_id:
        flash('Não foi possível identificar um perfil público para a consulta.', 'danger')
        return redirect(url_for('patient_result', patient_id=patient_id))
    add_consult(
        patient_id=patient_id,
        doctor_id=consult_doctor_id,
        notes=notes,
        owner_user_id=patient.owner_user_id or user.id
    )
    flash('Consulta salva.', 'success')
    return redirect(url_for('patient_result', patient_id=patient_id))

@app.route('/product/<int:product_id>')
@login_required
def product_result(product_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    product = get_product_by_id(product_id, user.id)
    return render_template('product_result.html', product=product)

@app.route('/download_pdf/<int:patient_id>')
def download_pdf(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient_by_id(patient_id)
    if not can_manage_patient(user, patient):
        abort(403)

    consults = get_consults_by_patient(patient_id)
    if consults:
        latest_notes = consults[-1].notes or ""
        parts = latest_notes.split("Prescrição:\n", 1)
        diagnostic_text   = parts[0].strip()
        prescription_text = (parts[1].strip() if len(parts) > 1 else (patient.prescription or "")).strip()
    else:
        diagnostic_text   = "Nenhuma consulta registrada."
        prescription_text = (patient.prescription or "").strip()

    patient_info = (
        f"Paciente: {patient.name}\n"
        f"Idade: {patient.age or ''}\n"
        f"CPF: {(patient.cpf or '')}\n"
        f"Sexo: {patient.gender or ''}\n"
        f"Telefone: {patient.phone or ''}"
    )

    html = render_template(
        "result_pdf.html",
        diagnostic_text=diagnostic_text,
        prescription_text=prescription_text,
        doctor_name=getattr(patient.doctor, "name", ""),
        patient_info=patient_info,
        logo_path=os.path.join(app.root_path, 'static', 'images', 'logo.png')
    )
    static_base = os.path.join(app.root_path, 'static')
    try:
        pdf_bytes: bytes = render_html_pdf_bytes(html, static_base)
    except RuntimeError as e:
        app.logger.error("Falha ao gerar PDF com WeasyPrint: %s", e)
        abort(503, description="Serviço de PDF indisponível.")

    cpf_or_id = (patient.cpf or f"id_{patient.id}").replace('.', '').replace('-', '')
    safe_name = re.sub(r'[^A-Za-z0-9_-]+', '_', f"{patient.name}_{cpf_or_id}")[:80] or f"paciente_{patient.id}"
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"prescription_{safe_name}.pdf"
    )

@app.route('/catalog')
@login_required
def catalog():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    search = request.args.get('search', '').strip().lower()
    status = request.args.get('status', '').strip()

    patients = get_patients_by_doctor(user.id)

    if search:
        patients = [p for p in patients if search in p.name.lower()]

    if status:
        patients = [p for p in patients if p.status == status]

    return render_template('catalog.html', patients=patients)

@app.route('/edit_patient/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def edit_patient(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient_by_id(patient_id)
    if not patient:
        abort(404)
    if not can_manage_patient(user, patient):
        abort(403)

    if request.method == 'POST':
        name         = request.form['name'].strip()
        age          = int(request.form['age'])
        cpf          = request.form['cpf'].strip()
        gender       = request.form['gender'].strip()
        phone        = request.form['phone'].strip()
        prescription = request.form.get('prescription', '').strip()
        status       = request.form.get('status', patient.status).strip()

        update_patient(
            patient_id=patient_id,
            name=name, age=age, cpf=cpf, gender=gender, phone=phone,
            doctor_id=patient.doctor_id, owner_user_id=patient.owner_user_id,
            prescription=prescription, status=status
        )
        return redirect(url_for('catalog'))

    return render_template('edit_patient.html', patient=patient)

@app.route('/patient_result/<int:patient_id>')
def patient_result(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient_by_id(patient_id)
    if not can_manage_patient(user, patient):
        abort(403)

    consults = get_consults_by_patient(patient_id)
    if consults:
        latest = consults[-1].notes
        parts = latest.split("Prescrição:\n", 1)  # type: ignore
        diagnostic_text  = parts[0].strip()
        prescription_text = parts[1].strip() if len(parts) > 1 else patient.prescription or ""
    else:
        diagnostic_text  = "Nenhuma consulta registrada."
        prescription_text = patient.prescription or ""

    return render_template(
        'result.html',
        patient=patient,
        diagnostic_text=diagnostic_text,
        prescription_text=prescription_text,
        doctor_name=getattr(patient.doctor, "name", "")
    )

@app.route('/patient_info/<int:patient_id>')
@login_required
def patient_info(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    patient = get_patient_by_id(patient_id)
    if not can_manage_patient(user, patient):
        abort(403)

    return render_template('patient_info.html', patient=patient)

@app.route('/api/edit_patient/<int:patient_id>', methods=['POST'])
@login_required
def edit_patient_api(patient_id):
    user = get_logged_user()
    if not user:
        return jsonify(success=False, error="Não autenticado"), 403

    patient = get_patient_by_id(patient_id)
    if not can_manage_patient(user, patient):
        return jsonify(success=False, error="Paciente não encontrado"), 404

    data = request.get_json() or {}
    update_patient(
        patient_id   = patient_id,
        name         = data.get('name', patient.name),
        age          = int(data.get('age', patient.age) or 0),
        cpf          = data.get('cpf', patient.cpf),
        gender       = data.get('gender', patient.gender),
        phone        = data.get('phone', patient.phone),
        doctor_id    = patient.doctor_id,
        owner_user_id = patient.owner_user_id if is_admin(user) else user.id,
        prescription = data.get('prescription', patient.prescription),
        status       = patient.status
    )
    return jsonify(success=True)

@app.route('/delete_patient/<int:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient_by_id(patient_id)
    if not can_manage_patient(user, patient):
        abort(403)

    try:
        delete_patient_record(patient_id)
        flash('Paciente removido com sucesso.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error("Erro ao remover paciente %s: %s", patient_id, e)
        flash('Não foi possível remover o paciente.', 'danger')
    return redirect(url_for('catalog'))

@app.route('/toggle_patient_status/<int:patient_id>/<new_status>', methods=['POST'])
@login_required
def toggle_patient_status(patient_id, new_status):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient_by_id(patient_id)
    if not patient:
        abort(404)
    if not can_manage_patient(user, patient):
        abort(403)

    update_patient(
        patient_id=patient_id,
        name=patient.name, age=patient.age, cpf=patient.cpf, gender=patient.gender,
        phone=patient.phone, doctor_id=patient.doctor_id,
        owner_user_id=patient.owner_user_id,
        prescription=patient.prescription, status=new_status
    )
    return redirect(url_for('catalog'))

@app.route('/api/add_patient', methods=['POST'])
def api_add_patient():
    user = get_logged_user()
    if not user:
        return jsonify(success=False, error='Unauthorized'), 403

    data = request.get_json() or {}
    name         = data.get("name", "").strip()
    age_raw      = data.get("age", "")
    cpf          = data.get("cpf", "").strip()
    gender       = data.get("gender", "").strip()
    phone        = data.get("phone", "").strip()
    prescription = data.get("prescription", "").strip()

    if not (name and age_raw):
        return jsonify(success=False, error='Preencha todos os campos obrigatórios'), 400

    try:
        age = int(age_raw)
    except ValueError:
        return jsonify(success=False, error='Idade inválida'), 400

    owner_profile = get_user_public_doctor_profile(user=user, create_if_missing=True)
    if not owner_profile:
        return jsonify(success=False, error='Perfil público não pôde ser criado'), 500

    patient = add_patient(
        name=name, age=age, cpf=cpf or None, gender=gender or None,
        phone=phone or None,
        doctor_id=owner_profile.id,
        owner_user_id=user.id,
        prescription=prescription
    )

    return jsonify(success=True, patient_id=patient.id), 201

# ------------------------------------------------------------------------------
# Products
# ------------------------------------------------------------------------------
@app.route('/products')
@login_required
def products():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    category_filter    = request.args.get('category', '')
    via_filter         = request.args.get('application_route', '')
    status_filter      = request.args.get('status', '')
    stock_filter       = request.args.get('stock_filter', 'all')  # all | in_stock | min_stock
    search             = (request.args.get('search', '') or '').lower()

    q = Product.query.filter_by(doctor_id=user.id)

    if category_filter:
        q = q.filter(Product.category == category_filter)
    if via_filter:
        q = q.filter(Product.application_route == via_filter)
    if status_filter:
        q = q.filter(Product.status == status_filter)
    if search:
        q = q.filter(Product.name.ilike(f'%{search}%'))

    products_list = q.order_by(Product.created_at.desc()).all()

    if stock_filter == 'in_stock':
        products_list = [p for p in products_list if (p.quantity or 0) > 0]
    elif stock_filter == 'min_stock':
        products_list = [p for p in products_list if (p.quantity or 0) <= (p.min_stock or 0)]

    categories         = sorted({p.category for p in products_list if p.category})
    application_routes = sorted({p.application_route for p in products_list if p.application_route})

    return render_template('products.html',
                           products=products_list,
                           categories=categories,
                           application_routes=application_routes)


@app.route('/add_product', methods=['POST'])
def add_product_route():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    name = request.form.get('name', '').strip()
    if not name:
        flash('Nome do produto é obrigatório.', 'warning')
        return redirect(url_for('products'))

    try:
        quantity       = int(request.form.get('quantity', 0))
        purchase_price = float(request.form.get('purchase_price', 0))
        sale_price     = float(request.form.get('sale_price', 0))
    except ValueError:
        flash('Quantidade ou preços inválidos.', 'warning')
        return redirect(url_for('products'))

    produtos = get_products()
    next_id = max((p['id'] for p in produtos), default=0) + 1
    new_product = {
        "id": next_id,
        "name": name,
        "purchase_price": purchase_price,
        "sale_price": sale_price,
        "quantity": quantity,
        "status": "Ativo",
        "doctor_id": user.id
    }
    produtos.append(new_product)
    save_products(produtos)

    flash("Produto adicionado com sucesso.", "success")
    return redirect(url_for('products'))

@app.route('/api/edit_product/<int:product_id>', methods=['POST'])
@login_required
def edit_product_api(product_id):
    user = get_logged_user()
    if not user:
        return jsonify(success=False, error="Não autenticado"), 403

    p = Product.query.filter_by(id=product_id, doctor_id=user.id).first()
    if not p:
        return jsonify(success=False, error="Produto não encontrado"), 404

    data = request.get_json(silent=True) or {}

    try:
        name = (data.get('name') or p.name).strip()
        code = (data.get('code') or p.code or '').strip() or None
        quantity = int(data.get('quantity', p.quantity))
        purchase_price = float(data.get('purchase_price', p.purchase_price))
        sale_price = float(data.get('sale_price', p.sale_price))
    except (TypeError, ValueError):
        return jsonify(success=False, error="Dados inválidos"), 400

    status = (data.get('status') or p.status or "Ativo").strip() or "Ativo"
    if status not in {"Ativo", "Inativo"}:
        return jsonify(success=False, error="Status inválido"), 400

    p.name = name
    p.code = code
    p.quantity = quantity
    p.purchase_price = purchase_price
    p.sale_price = sale_price
    p.status = status
    db.session.commit()
    return jsonify(success=True)

@app.route('/toggle_product_status/<int:product_id>/<new_status>', methods=['POST'])
def toggle_product_status(product_id, new_status):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    produtos = get_products()
    for p in produtos:
        if p['id'] == product_id and p.get('doctor_id') == user.id:
            p['status'] = new_status
            break
    save_products(produtos)

    return redirect(url_for('products'))

@app.route('/stock_view/<int:product_id>')
def stock_view(product_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    product = next(
        (p for p in get_products() if p['id'] == product_id and p.get('doctor_id') == user.id),
        None
    )
    if not product:
        abort(404)
    return render_template('stock_view.html', product=product)

@app.route('/stock_edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def stock_edit(product_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    product = get_product_by_id(product_id, user.id)
    if not product:
        abort(404, description="Produto não encontrado ou sem permissão")

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        code = request.form.get('code', '').strip()
        try:
            quantity = int(request.form.get('quantity', 0))
            purchase_price = float(request.form.get('purchase_price', 0))
            sale_price = float(request.form.get('sale_price', 0))
        except ValueError:
            flash('Valores inválidos.', 'warning')
            return redirect(url_for('stock_edit', product_id=product_id))

        update_product(
            product_id=product_id, doctor_id=user.id, name=name, code=code,
            purchase_price=purchase_price, sale_price=sale_price, quantity=quantity
        )
        flash('Produto atualizado com sucesso.', 'success')
        return redirect(url_for('products'))

    return render_template('stock_edit.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    ok = delete_product_record(product_id, user.id)
    flash('Produto removido.' if ok else 'Produto não encontrado ou sem permissão.', 'info' if ok else 'danger')
    return redirect(url_for('products'))

# ------------------------------------------------------------------------------
# Suppliers
# ------------------------------------------------------------------------------
@app.route('/suppliers')
@login_required
def suppliers():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    suppliers = get_suppliers_by_user(user.id)
    return render_template('suppliers.html', suppliers=suppliers)

@app.route('/add_supplier', methods=['POST'])
@login_required
def add_supplier():
    user = get_logged_user()
    if not user:
        flash('Usuário não autenticado.', 'danger')
        return redirect(url_for('login'))
    name = request.form.get('name', '').strip()
    phone = request.form.get('phone', '').strip()
    email = request.form.get('email', '').strip()
    if not (name and phone and email):
        flash('Preencha todos os campos.', 'warning')
        return redirect(url_for('suppliers'))
    add_supplier_db(name, phone, email, user.id)
    flash('Fornecedor cadastrado!', 'success')
    return redirect(url_for('suppliers'))

@app.route('/update_supplier/<int:supplier_id>', methods=['POST'])
@login_required
def update_supplier(supplier_id):
    user = get_logged_user()
    name = request.form.get('name', '').strip()
    phone = request.form.get('phone', '').strip()
    email = request.form.get('email', '').strip()
    if not user:
        flash('Usuário não autenticado.', 'danger')
        return redirect(url_for('login'))
    supplier = update_supplier_db(supplier_id, name, phone, email, user.id)
    if supplier:
        flash('Fornecedor atualizado!', 'success')
    else:
        flash('Fornecedor não encontrado ou sem permissão!', 'danger')
    return redirect(url_for('suppliers'))

@app.route('/delete_supplier/<int:supplier_id>', methods=['POST'])
@login_required
def delete_supplier(supplier_id):
    user = get_logged_user()
    if not user:
        flash('Usuário não autenticado.', 'danger')
        return redirect(url_for('login'))
    ok = delete_supplier_db(supplier_id, user.id)
    if ok:
        flash('Fornecedor removido.', 'info')
    else:
        flash('Fornecedor não encontrado ou sem permissão.', 'danger')
    return redirect(url_for('suppliers'))

# ------------------------------------------------------------------------------
# Quotes
# ------------------------------------------------------------------------------
@app.route('/create_quote', methods=['GET', 'POST'])
@login_required
@quotes_section_required
@feature_required('quotes_auto')
def create_quote():
    user = get_logged_user()
    if not user:
        flash('Usuário não autenticado.', 'danger')
        return redirect(url_for('login'))

    suppliers = get_suppliers_by_user(user.id)
    if request.method == 'POST':
        title = request.form['title']
        items_raw = request.form['items']
        supplier_ids = request.form.getlist('supplier_ids')
        suppliers_str = ",".join(supplier_ids)

        # ⭐ grava o criador
        quote = Quote(title=title, items=items_raw, suppliers=suppliers_str, user_id=user.id)
        db.session.add(quote)
        db.session.commit()

        items_list = [i.strip() for i in items_raw.split('\n') if i.strip()]
        items_text = "\n".join([f"• {item}" for item in items_list])

        for s in suppliers:
            if str(s.id) not in supplier_ids:
                continue
            response_url = url_for('respond_quote', quote_id=quote.id, supplier_id=s.id, _external=True)
            if s.phone and AUTO_WHATSAPP_ENABLED:
                try:
                    send_quote_whatsapp(
                        supplier_name=s.name,
                        phone=s.phone,
                        quote_title=title,
                        quote_items=items_list,
                        response_url=response_url
                    )
                except Exception as e:
                    print(f"[Erro WhatsApp - {s.name}] {e}")
            if s.email:
                try:
                    email_subject = f"Cotação RafahMed: {title}"
                    email_body = f"""
Olá {s.name},

Você recebeu uma nova cotação da plataforma RafahMed.

Título: {title}
Itens:
{items_text}

Responda acessando o link abaixo:
{response_url}

Atenciosamente,
Equipe RafahMed
"""
                    send_email_quote(s.email, email_subject, email_body)
                except Exception as e:
                    print(f"Erro ao enviar e-mail para {s.email}: {e}")

        flash('Cotação criada com sucesso!', 'success')
        return redirect(url_for('quote_index'))

    return render_template('create_quote.html', suppliers=suppliers)

@app.route('/quote_index')
@login_required
@quotes_section_required
@feature_required('quotes_auto')
def quote_index():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    quotes = Quote.query.filter_by(user_id=user.id).order_by(Quote.created_at.desc()).all()
    suppliers_all = {str(s.id): s.name for s in get_suppliers_by_user(user.id)}

    for quote in quotes:
        if quote.suppliers:
            quote.supplier_list = [suppliers_all.get(sid, f"ID {sid}") for sid in quote.suppliers.split(',') if sid]
        else:
            quote.supplier_list = []
        quote.responses = QuoteResponse.query.filter_by(quote_id=quote.id).all()

    return render_template('quote_index.html', quotes=quotes, user=user)

@app.route('/quote/<int:quote_id>/supplier/<int:supplier_id>', methods=['GET', 'POST'])
@quotes_section_required
def respond_quote(quote_id, supplier_id):
    quote = Quote.query.get_or_404(quote_id)
    apply_rls_context(user_id=quote.user_id)
    supplier_ids = quote.suppliers.split(",") if quote.suppliers else []
    if str(supplier_id) not in supplier_ids:
        return "Cotação inválida ou fornecedor não autorizado.", 403

    items = [i.strip() for i in quote.items.split('\n') if i.strip()]

    if request.method == 'POST':
        prices = []
        for idx in range(len(items)):
            price = request.form.get(f'price_{idx}')
            deadline = request.form.get(f'deadline_{idx}')
            prices.append({"price": price, "deadline": deadline})

        response = QuoteResponse(
            quote_id=quote.id,
            supplier_id=supplier_id,
            answers=json.dumps(prices)
        )
        db.session.add(response)
        db.session.commit()

        return render_template(
            'quote_response.html',
            quote=quote,
            items=list(enumerate(items)),
            success=True
        )

    return render_template(
        'quote_response.html',
        quote=quote,
        items=list(enumerate(items)),
        success=False
    )

@app.route('/quote_results/<int:quote_id>')
@login_required
@quotes_section_required
@feature_required('quotes_auto')
def quote_results(quote_id):
    user = cast(User, get_logged_user())
    if user is None:  # extra safety; helps type checkers
        return redirect(url_for('login'))

    quote = Quote.query.get_or_404(quote_id)

    # block access if quote has no owner or owner != current user
    if not quote.user_id or quote.user_id != user.id:
        abort(403)

    responses = QuoteResponse.query.filter_by(quote_id=quote_id).all()

    supplier_ids = [int(x) for x in (quote.suppliers or '').split(',') if x]
    supplier_objs = Supplier.query.filter(Supplier.id.in_(supplier_ids)).all()
    supplier_map = {s.id: s.name for s in supplier_objs}
    supplier_names = [supplier_map.get(sid, f'Fornecedor {sid}') for sid in supplier_ids]
    quote_suppliers = supplier_ids

    quote_items = list(enumerate([item.strip() for item in (quote.items or '').split('\n') if item.strip()]))

    quote_responses = {}
    for r in responses:
        try:
            answers = json.loads(r.answers)
        except Exception:
            answers = []
        quote_responses[r.supplier_id] = {'answers': answers}

    best_per_item = {}
    for idx, _ in quote_items:
        min_price = float('inf')
        best_supplier = None
        for sid in quote_suppliers:
            resp = quote_responses.get(sid)
            if resp and idx < len(resp['answers']):
                try:
                    price = float(resp['answers'][idx]['price'])
                    if price < min_price:
                        min_price = price
                        best_supplier = sid
                except Exception:
                    continue
        best_per_item[idx] = best_supplier

    return render_template(
        'quote_results.html',
        quote=quote,
        supplier_names=supplier_names,
        quote_items=quote_items,
        quote_suppliers=quote_suppliers,
        quote_responses=quote_responses,
        best_per_item=best_per_item,
        user=user
    )

@app.route('/delete_quote/<int:quote_id>', methods=['POST'])
@login_required
@quotes_section_required
def delete_quote(quote_id):
    user = cast(User, get_logged_user())
    if user is None:
        return redirect(url_for('login'))

    quote = Quote.query.get_or_404(quote_id)

    if not quote.user_id or quote.user_id != user.id:
        abort(403)

    db.session.delete(quote)
    db.session.commit()
    flash('Cotação excluída com sucesso!', 'success')
    return redirect(url_for('quote_index'))

# ------------------------------------------------------------------------------
# API & Consult routes quick
# ------------------------------------------------------------------------------
@app.get('/api/doctors')
@login_required
def api_doctors():
    user = get_logged_user()
    if not user:
        return jsonify([]), 403
    q = Doctor.query
    if not is_admin(user):
        q = q.filter_by(user_id=user.id)
    docs = q.order_by(Doctor.name).all()
    return jsonify([{"id": d.id, "name": d.name} for d in docs])

@app.get('/api/patients')
@login_required
def api_patients():
    user = get_logged_user()
    if not user:
        return jsonify([]), 403

    requested_doctor_id = request.args.get('doctor_id', type=int)
    q = Patient.query

    if is_admin(user):
        if requested_doctor_id:
            q = q.filter_by(doctor_id=requested_doctor_id)
    else:
        doctor_profile_ids = [d.id for d in Doctor.query.filter_by(user_id=user.id).all()]
        allowed_conditions = [
            Patient.owner_user_id == user.id,
            and_(Patient.owner_user_id.is_(None), Patient.doctor_id == user.id),  # legado
        ]
        if doctor_profile_ids:
            allowed_conditions.append(
                and_(Patient.owner_user_id.is_(None), Patient.doctor_id.in_(doctor_profile_ids))
            )
        q = q.filter(or_(*allowed_conditions))

        if requested_doctor_id:
            doctor_obj = db.session.get(Doctor, requested_doctor_id)
            is_legacy_allowed = requested_doctor_id == user.id
            if not is_legacy_allowed and (not doctor_obj or doctor_obj.user_id != user.id):
                return jsonify([])
            q = q.filter_by(doctor_id=requested_doctor_id)

    patients = q.order_by(Patient.name.asc()).all()
    return jsonify([
        {"id": p.id, "name": p.name, "doctor_id": p.doctor_id}
        for p in patients
    ])

@app.route('/api/add_consult', methods=['POST'])
def api_add_consult():
    user = get_logged_user()
    if not user:
        return jsonify(success=False, error='UNAUTHORIZED'), 403

    data = request.get_json() or {}
    pid = parse_int(data.get('patient_id'))
    if pid is None:
        return jsonify(success=False, error='patient_id inválido'), 400

    patient = get_patient_by_id(pid)
    if not patient:
        return jsonify(success=False, error='Paciente não encontrado'), 404
    if not can_manage_patient(user, patient):
        return jsonify(success=False, error='Acesso negado'), 403

    notes = data.get('notes', '').strip() or None
    req_doctor_id = parse_int(data.get('doctor_id'))
    consult_doctor_id = req_doctor_id or patient.doctor_id

    if req_doctor_id is not None:
        doctor_obj = db.session.get(Doctor, req_doctor_id)
        if not doctor_obj:
            return jsonify(success=False, error='Médico não encontrado'), 404
        if not can_manage_doctor_profile(user, doctor_obj):
            return jsonify(success=False, error='Acesso negado ao médico'), 403

    if consult_doctor_id is None:
        prof = get_user_public_doctor_profile(user=user, create_if_missing=True)
        consult_doctor_id = prof.id if prof else None

    if consult_doctor_id is None:
        return jsonify(success=False, error='Perfil público de médico não encontrado'), 400

    consult = add_consult(
        patient_id=pid,
        doctor_id=consult_doctor_id,
        notes=notes,
        owner_user_id=patient.owner_user_id or user.id
    )

    try:
        create_user_event(
            summary=f"Consulta paciente #{pid}",
            start_datetime=datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            end_datetime=(datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%S'),
            description=notes or ""
        )
    except Exception as e:
        print("Erro ao criar evento no Google Calendar:", e)

    return jsonify(success=True, consult_id=consult.id), 201

@app.route('/submit_patient_consultation', methods=['POST'])
def submit_patient_consultation():
    """
    Agendamento público (página Agendar Consulta) — valida contra DoctorDateAvailability
    e grava a consulta. Cria o paciente automaticamente.
    """
    name     = (request.form.get('name')  or '').strip()
    cpf      = (request.form.get('cpf')   or '').strip()
    phone    = (request.form.get('phone') or '').strip()
    doctor_id = request.form.get('doctor_id', type=int)
    date_br   = (request.form.get('date') or '').strip()   # dd/mm/aaaa
    time_hm   = (request.form.get('time') or '').strip()   # HH:MM

    if not (name and doctor_id and date_br and time_hm):
        return "Campos obrigatórios ausentes.", 400

    # Converter data e hora
    try:
        day = datetime.strptime(date_br, "%d/%m/%Y").date()
    except ValueError:
        return "Data inválida. Use dd/mm/aaaa.", 400

    try:
        t = datetime.strptime(time_hm, '%H:%M').time()
    except ValueError:
        return "Horário inválido. Use HH:MM.", 400

    doctor = db.session.get(Doctor, doctor_id)
    if not doctor:
        return "Médico não encontrado.", 404
    owner_user_id = doctor.user_id
    if owner_user_id is None:
        return "Perfil de médico indisponível para agendamento.", 409
    apply_rls_context(user_id=owner_user_id)

    # 1) Buscar blocos explícitos para a DATA escolhida
    blocks = DoctorDateAvailability.query.filter_by(doctor_id=doctor_id, day=day).all()
    if not blocks:
        return "Médico sem disponibilidade nessa data.", 409

    # 2) Calcular todos os slots disponíveis do(s) bloco(s) do dia
    free = set()
    for b in blocks:
        cur  = datetime.combine(day, b.start_time)
        end  = datetime.combine(day, b.end_time)
        step = timedelta(minutes=b.slot_minutes or 30)
        # inclui o último slot que termina exatamente em end
        while cur <= end - step + timedelta(seconds=1):
            free.add(cur.strftime('%H:%M'))
            cur += step

    if time_hm not in free:
        return "Horário fora da disponibilidade.", 409

    # 3) Checar se já está ocupado
    taken = {
        c.time.strftime('%H:%M')
        for c in Consult.query.filter_by(doctor_id=doctor_id, date=day)
                              .filter(TIME_COL.isnot(None)).all()
    }
    if time_hm in taken:
        return "Horário já reservado.", 409

    # 4) Criar paciente e consulta
    patient = add_patient(
        name=name, age=None, cpf=cpf or None, gender=None, phone=phone or None,
        doctor_id=doctor_id, owner_user_id=owner_user_id, prescription=None
    )

    c = Consult(
        patient_id=patient.id,
        doctor_id=doctor_id,
        owner_user_id=owner_user_id,
        date=day,
        time=t,
        notes=f"Consulta — {name}"
    )
    db.session.add(c)
    db.session.commit()

    # 5) Agendar no Google Calendar do admin (duração = slot do bloco correspondente; fallback 60 min)
    slot_minutes = 60
    for b in blocks:
        if b.start_time <= t < b.end_time:
            slot_minutes = b.slot_minutes or 60
            break

    start_iso = datetime.combine(day, t).strftime("%Y-%m-%dT%H:%M:%S")
    end_iso   = (datetime.combine(day, t) + timedelta(minutes=slot_minutes)).strftime("%Y-%m-%dT%H:%M:%S")

    summary = f"Consulta — {name} (Dr(a). {doctor.name})"
    description = f"CPF: {cpf}\nTelefone: {phone}\nData: {date_br}\nHorário: {time_hm}"

    try:
        create_admin_event(summary=summary, start_datetime=start_iso, end_datetime=end_iso, description=description)
    except Exception as e:
        current_app.logger.error(f"[Calendar] Erro ao agendar no calendário do admin: {e}")
        return redirect(url_for('hero'))

    return redirect(url_for('hero'))

@app.route('/delete_consult/<int:consult_id>', methods=['POST'])
@login_required
def delete_consult(consult_id):
    user = get_logged_user()
    if not user:
        return jsonify({"ok": False, "error": "Não autenticado"}), 403

    consult = db.session.get(Consult, consult_id)
    if not consult:
        return jsonify({"ok": False, "error": "Consulta não encontrada"}), 404
    is_owner = (
        consult.owner_user_id == user.id or
        (consult.owner_user_id is None and consult.doctor_id == user.id)  # legado
    )
    if not is_admin(user) and not is_owner:
        return jsonify({"ok": False, "error": "Acesso negado"}), 403

    db.session.delete(consult)
    db.session.commit()
    return jsonify({"ok": True})

@app.route('/authorize_calendar')
def authorize_calendar():
    flow = Flow.from_client_secrets_file(
        os.getenv('GOOGLE_CLIENT_SECRET_JSON'),
        scopes=['https://www.googleapis.com/auth/calendar'],
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['state'] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    if not state:
        return "Sessão expirada ou inválida", 400

    flow = Flow.from_client_secrets_file(
        os.getenv('GOOGLE_CLIENT_SECRET_JSON'),
        scopes=["https://www.googleapis.com/auth/calendar"],
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials  # type: ignore

    session["credentials"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": getattr(creds, "token_uri", None),
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }

    u = get_logged_user()
    if is_admin(u):
        admin_creds_path = os.path.join(BASE_DIR, 'admin_google_creds.json')
        with open(admin_creds_path, 'w') as f:
            f.write(creds.to_json())

    return redirect(url_for("agenda"))

@app.after_request
def no_cache_for_availability(resp):
    if request.path.startswith(('/api/available_slots',
                                '/api/available_days',
                                '/availability')):
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
    return resp

def create_user_event(summary: str, start_datetime: str, end_datetime: str, description: str) -> None:
    info = session.get("credentials")
    if not info:
        raise Exception("Usuário não autenticado no Google")
    creds   = Credentials.from_authorized_user_info(info)  # type: ignore[attr-defined]
    service = build("calendar", "v3", credentials=creds)
    event = {
        "summary":     summary,
        "description": description,
        "start": {"dateTime": start_datetime, "timeZone": "America/Sao_Paulo"},
        "end":   {"dateTime": end_datetime,   "timeZone": "America/Sao_Paulo"},
    }
    service.events().insert(calendarId='primary', body=event).execute()

@app.route('/api/events')
@login_required
def api_events():
    user = get_logged_user()
    if not user:
        return jsonify([]), 403

    requested_doctor_id = request.args.get('doctor_id', type=int)

    q = Consult.query
    show_global_title = True
    if is_admin(user):
        if requested_doctor_id:
            q = q.filter_by(doctor_id=requested_doctor_id)
            show_global_title = False
    else:
        q = q.filter(
            or_(
                Consult.owner_user_id == user.id,
                and_(Consult.owner_user_id.is_(None), Consult.doctor_id == user.id),  # legado
            )
        )
        if requested_doctor_id:
            doctor_obj = db.session.get(Doctor, requested_doctor_id)
            if not doctor_obj or doctor_obj.user_id != user.id:
                return jsonify([])
            q = q.filter_by(doctor_id=requested_doctor_id)
        show_global_title = False

    rows = q.all()
    doctor_ids = {c.doctor_id for c in rows if c.doctor_id}
    doctors = {
        d.id: d.name
        for d in Doctor.query.filter(Doctor.id.in_(doctor_ids)).all()
    } if doctor_ids else {}

    events = []
    for c in rows:
        doctor_name = doctors.get(c.doctor_id)
        base_title = c.notes or "Consulta"
        title = base_title if not show_global_title else (f"{doctor_name} — {base_title}" if doctor_name else base_title)
        event = {
            "id": c.id,
            "title": title,
            "extendedProps": {
                "doctorId": c.doctor_id,
                "doctorName": doctor_name,
            },
        }
        if c.time:
            event["start"] = datetime.combine(c.date, c.time).isoformat()
        else:
            event["start"] = c.date.isoformat()
            event["allDay"] = True
        events.append(event)
    return jsonify(events)

def create_admin_event(summary: str, start_datetime: str, end_datetime: str, description: str) -> None:
    """
    Usa as credenciais persistidas do admin (instance/admin_google_creds.json)
    para criar um evento no calendário principal dele.
    """
    admin_creds_path = os.path.join(BASE_DIR, 'admin_google_creds.json')
    if not os.path.exists(admin_creds_path):
        raise Exception("Admin ainda não autorizou o Google Calendar. Entre como admin e acesse /authorize_calendar.")

    from google.oauth2.credentials import Credentials as OAuthCreds
    with open(admin_creds_path, 'r') as f:
        admin_json = f.read()
    creds = OAuthCreds.from_authorized_user_info(json.loads(admin_json))

    service = build("calendar", "v3", credentials=creds)
    event = {
        "summary":     summary,
        "description": description,
        "start": {"dateTime": start_datetime, "timeZone": "America/Sao_Paulo"},
        "end":   {"dateTime": end_datetime,   "timeZone": "America/Sao_Paulo"},
    }
    service.events().insert(calendarId='primary', body=event).execute()

@app.route('/submit_consultation', methods=['POST'])
@login_required
def submit_consultation():
    """
    Agendamento interno (ex.: agenda/admin) — valida contra DoctorDateAvailability
    e grava a consulta. Vínculo com paciente é opcional.
    Horário é obrigatório e deve vir dos slots disponíveis.
    """
    user = get_logged_user()
    if not user:
        return "Unauthorized", 403

    patient_id = request.form.get('patient_id', type=int)
    doctor_id  = request.form.get('doctor_id', type=int)
    date_str   = (request.form.get('date') or '').strip()   # dd/mm/aaaa
    time_str   = (request.form.get('time') or '').strip()   # HH:MM
    notes      = (request.form.get('title') or '').strip()

    if not doctor_id or not date_str or not time_str:
        return "Missing fields", 400

    doctor = db.session.get(Doctor, doctor_id)
    if not doctor:
        return "Doctor not found", 404
    if not is_admin(user) and doctor.user_id != user.id:
        return "Forbidden doctor", 403

    # Data BR
    try:
        day = datetime.strptime(date_str, '%d/%m/%Y').date()
    except ValueError:
        return "Invalid date (use dd/mm/aaaa)", 400

    # Hora obrigatória
    try:
        t = datetime.strptime(time_str, '%H:%M').time()
    except ValueError:
        return "Invalid time (use HH:MM)", 400

    # Validar horário contra blocos da DATA (não mais por weekday)
    blocks = DoctorDateAvailability.query.filter_by(doctor_id=doctor_id, day=day).all()
    if not blocks:
        return "No availability for this date", 409

    # slots já ocupados nesse dia
    taken = {
        c.time.strftime('%H:%M')
        for c in Consult.query.filter_by(doctor_id=doctor_id, date=day)
                              .filter(Consult.time.is_not(None)).all() #type:ignore
    }

    # construir set de horários livres com base nos blocos
    free = set()
    for b in blocks:
        cur  = datetime.combine(day, b.start_time)
        end  = datetime.combine(day, b.end_time)
        step = timedelta(minutes=b.slot_minutes or 30)
        while cur <= end - step + timedelta(seconds=1):
            free.add(cur.strftime('%H:%M'))
            cur += step

    if time_str not in free:
        return "Selected time is outside availability", 409
    if time_str in taken:
        return "Slot already taken", 409

    owner_user_id = user.id

    # Paciente é opcional; só valida quando vier informado.
    if patient_id:
        p = db.session.get(Patient, patient_id)
        if not p:
            return "Patient not found", 404
        if not can_manage_patient(user, p):
            return "Forbidden patient", 403
        owner_user_id = p.owner_user_id or user.id
        if p.doctor_id != doctor_id:
            p.doctor_id = doctor_id

    c = Consult(
        patient_id=patient_id or None,
        doctor_id=doctor_id,
        owner_user_id=owner_user_id,
        date=day,
        time=t,
        notes=notes
    )
    db.session.add(c)
    db.session.commit()
    return "ok", 200


# ------------------------------------------------------------------------------
# Quiz (Autoavaliação)
# ------------------------------------------------------------------------------
@app.route('/quiz')
def quiz():
    return render_template('quiz.html')

@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    data = request.get_json() or {}

    name = data.get('nome', 'Anônimo')
    age_raw = data.get('idade', '0')
    try:
        age = int(age_raw)
    except ValueError:
        age = 0

    admin_raw = (request.args.get('admin') or "").strip()
    doctor_user = None
    if admin_raw:
        if admin_raw.isdigit():
            doctor_user = db.session.get(User, int(admin_raw))
        if not doctor_user:
            admin_norm = admin_raw.lower()
            doctor_user = User.query.filter_by(email=admin_norm).first()
        if not doctor_user:
            doctor_user = User.query.filter_by(username=admin_raw).first()
    elif session.get('user_id'):
        doctor_user = db.session.get(User, session.get('user_id'))

    doctor_id = doctor_user.id if doctor_user else None
    if doctor_id is None:
        return jsonify(status='error', error='doctor_id ausente'), 400
    apply_rls_context(
        user_id=doctor_id,
        auth_uid=getattr(doctor_user, "auth_user_id", None) if doctor_user else None
    )

    patient_id = None
    patient_doctor_id = None
    if doctor_user is not None:
        profile = get_user_public_doctor_profile(user=doctor_user, create_if_missing=False)
        patient_doctor_id = profile.id if profile else None

    try:
        patient = add_patient(
            name=name, age=age, cpf=None, gender=None, phone=None,
            doctor_id=patient_doctor_id, owner_user_id=doctor_id,
            prescription=f"Autoavaliação: {data.get('risco')}"
        )
        patient_id = patient.id
    except Exception:
        db.session.rollback()
        patient_id = None

    fatores = data.get('fatores', [])
    if isinstance(fatores, list):
        fatores = json.dumps(fatores)
    elif isinstance(fatores, str):
        fatores = json.dumps([fatores])
    else:
        fatores = json.dumps([])

    motivacao = data.get('motivacao', [])
    if isinstance(motivacao, list):
        motivacao = '; '.join(motivacao)
    elif isinstance(motivacao, str):
        motivacao = motivacao
    else:
        motivacao = ""

    qr = add_quiz_result(
        name=name, age=age, date=datetime.utcnow(),
        consentimento=data.get('consentimento'),
        nivel_hierarquico=data.get('nivel_hierarquico'),
        setor=data.get('setor'),
        nervosismo=data.get('nervosismo'),
        preocupacao=data.get('preocupacao'),
        interesse=data.get('interesse'),
        depressao_raw=data.get('depressao_raw'),
        estresse_raw=data.get('estresse_raw'),
        hora_extra=data.get('hora_extra'),
        sono=data.get('sono'),
        atividade_fisica=data.get('atividade_fisica'),
        fatores=fatores,
        motivacao=motivacao,
        pronto_socorro=data.get('pronto_socorro'),
        relacionamentos=data.get('relacionamentos'),
        hobbies=data.get('hobbies'),
        ansiedade=data.get('ansiedade'),
        depressao=data.get('depressao'),
        estresse=data.get('estresse'),
        qualidade=data.get('qualidade'),
        risco=data.get('risco'),
        ansiedade_cor=data.get('ansiedade_cor'),
        depressao_cor=data.get('depressao_cor'),
        estresse_cor=data.get('estresse_cor'),
        qualidade_cor=data.get('qualidade_cor'),
        risco_cor=data.get('risco_cor'),
        recomendacao=data.get('recomendacao'),
        doctor_id=doctor_id,
        patient_id=patient_id
    )

    db.session.commit()
    return jsonify(status='ok', quiz_id=qr.id)

@app.route('/selfevaluation')
@login_required
@feature_required('selfevaluations')
def selfevaluation():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    doctor_id = user.id
    results = get_quiz_results_by_doctor(doctor_id)

    counts = defaultdict(int)
    for r in results:
        day = r.date.strftime('%d/%m')
        counts[day] += 1

    labels = list(counts.keys())
    values = list(counts.values())

    return render_template('selfevaluation.html', labels=labels, values=values)

@app.route("/quiz-results")
@login_required
@feature_required('selfevaluations')
def quiz_results():
    user    = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    results = get_quiz_results_by_doctor(user.id)

    def color_of(level):
        return {
            "BAIXO": "#10b981", "NORMAL/LEVE": "#f59e0b",
            "MODERADO": "#f97316", "ALTO": "#ef4444",
            "RUIM": "#f97316", "MUITO RUIM": "#ef4444", "BOA": "#10b981", "REGULAR": "#f59e0b"
        }.get(level, "#000")

    formatted = [{
        "id":            r.id,
        "nome":          r.name,
        "idade":         r.age,
        "data":          r.date.strftime("%d/%m/%Y"),
        "ansiedade":     r.ansiedade,
        "depressao":     r.depressao,
        "estresse":      r.estresse,
        "qualidade":     r.qualidade,
        "risco":         r.risco,
        "ansiedade_cor": color_of(r.ansiedade),
        "depressao_cor": color_of(r.depressao),
        "estresse_cor":  color_of(r.estresse),
        "qualidade_cor": color_of(r.qualidade),
        "risco_cor":     color_of(r.risco),
    } for r in results]

    return render_template("quiz_results.html", results=formatted, user=user)

@app.route('/quiz-patient/<int:quiz_id>')
@login_required
@feature_required('selfevaluations')
def quiz_patient(quiz_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    result = QuizResult.query.get_or_404(quiz_id)
    if result.doctor_id != user.id:
        abort(403)

    fatores_val = result.fatores
    if isinstance(fatores_val, str):
        try:
            fatores_list = json.loads(fatores_val)
            if not isinstance(fatores_list, list):
                fatores_list = [str(fatores_list)]
        except Exception:
            fatores_list = [fatores_val]
    elif isinstance(fatores_val, list):
        fatores_list = fatores_val
    else:
        fatores_list = [str(fatores_val)]
    fatores_texto = ', '.join(fatores_list)

    motivacao_val = result.motivacao
    if isinstance(motivacao_val, str):
        if motivacao_val.startswith("[") and motivacao_val.endswith("]"):
            try:
                motivacao_list = json.loads(motivacao_val)
            except Exception:
                motivacao_list = [motivacao_val]
        else:
            motivacao_list = [s.strip() for s in motivacao_val.split(';') if s.strip()]
    elif isinstance(motivacao_val, list):
        motivacao_list = motivacao_val
    else:
        motivacao_list = [str(motivacao_val)]
    motivacao_texto = ', '.join(motivacao_list)

    patient = {
        "nome":             result.name,
        "idade":            result.age,
        "data":             result.date.strftime('%d/%m/%Y'),

        "consentimento":     getattr(result, "consentimento", None),
        "nivel_hierarquico": getattr(result, "nivel_hierarquico", None),
        "setor":             getattr(result, "setor", None),

        "nervosismo":       result.nervosismo,
        "preocupacao":      result.preocupacao,
        "interesse":        result.interesse,
        "depressao_raw":    result.depressao_raw,
        "estresse_raw":     result.estresse_raw,
        "hora_extra":       result.hora_extra,
        "sono":             result.sono,
        "atividade_fisica": result.atividade_fisica,
        "fatores":          fatores_texto,
        "motivacao":        motivacao_texto,
        "pronto_socorro":   result.pronto_socorro,
        "relacionamentos":  result.relacionamentos,
        "hobbies":          result.hobbies,

        "ansiedade":        result.ansiedade,
        "depressao":        result.depressao,
        "estresse":         result.estresse,
        "qualidade":        result.qualidade,
        "risco":            result.risco,
        "recomendacao":     result.recomendacao,
    }

    questions = {
        "nome":             "Qual seu nome?",
        "idade":            "Qual sua idade?",
        "nervosismo":       "Nas últimas 2 semanas, com que frequência você se sentiu nervoso(a), ansioso(a) ou muito tenso(a)?",
        "preocupacao":      "Nas últimas 2 semanas, com que frequência você teve dificuldade para controlar suas preocupações?",
        "interesse":        "Nas últimas 2 semanas, você teve pouco interesse ou prazer em fazer as coisas?",
        "depressao_raw":    "Nas últimas 2 semanas, você se sentiu desanimado(a), deprimido(a) ou sem esperança?",
        "estresse_raw":     "Considerando as últimas 2 semanas, o quanto você sentiu que estava estressado(a)?",
        "hora_extra":       "Considerando uma semana de trabalho normal, quantos dias você normalmente precisa trabalhar a mais do que a sua carga horária habitual e/ou fazer hora extra?",
        "sono":             "Como você classificaria sua qualidade do sono nas últimas 2 semanas?",
        "atividade_fisica": "Com que frequência você pratica atividade física?",
        "fatores":          "Quando você pensa na sua saúde mental e qualidade de vida, quais os fatores que mais impactam?",
        "motivacao":        "Em qual estágio de motivação você considera que está para tentar resolver a questão apontada?",
        "pronto_socorro":   "Nos últimos 3 meses, quantas vezes você utilizou o pronto socorro?",
        "relacionamentos":  "Como você avalia seu relacionamento com família e amigos?",
        "hobbies":          "Você tem algum hobby ou atividade que lhe dá prazer?",
        "ansiedade":        "Nível de Ansiedade",
        "depressao":        "Nível de Depressão",
        "estresse":         "Nível de Estresse",
        "qualidade":        "Qualidade de Vida",
        "risco":            "Risco Geral",
        "recomendacao":     "Recomendação Final"
    }

    return render_template('quiz_patient.html', patient=patient, questions=questions)

@app.route('/delete_quiz_result', methods=['POST'])
def delete_quiz_result():
    quiz_id = request.form.get('quiz_id', type=int)
    r       = QuizResult.query.get_or_404(quiz_id)
    if r.doctor_id != session.get('user_id'):
        abort(403)
    db.session.delete(r)
    db.session.commit()
    flash('Resultado deletado.', 'success')
    return redirect(url_for('quiz_results'))

# ------------------------------------------------------------------------------
# QUESTIONNAIRE (SRQ-20)
# ------------------------------------------------------------------------------
@app.route('/srq20')
def srq20():
    return render_template("questionnaire.html")

@app.route('/submit_srq20', methods=['POST'])
def submit_srq20():
    """
    Recebe JSON do formulário SRQ-20.
    Espera: sexo, idade, srq_q1..srq_q20, srq20_total, srq20_classificacao, srq20_itens_sim.
    Parâmetro GET ?admin=ID associa o resultado ao profissional.
    """
    try:
        payload = request.get_json(force=True, silent=False) or {}
    except Exception:
        return jsonify({"ok": False, "error": "Invalid JSON"}), 400

    admin_id = request.args.get('admin', type=int)
    if admin_id is not None:
        apply_rls_context(user_id=admin_id)

    name = payload.get('nome') or payload.get('name')  # optional
    age = str(payload.get('idade') or '').strip() or None
    sex = (payload.get('sexo') or '').strip() or None

    srq_total = payload.get('srq20_total')
    srq_class = payload.get('srq20_classificacao')
    srq_items_yes = payload.get('srq20_itens_sim') or []
    srq_q17 = payload.get('srq_q17')

    obj = QuestionnaireResult(
        created_at=datetime.utcnow(),
        admin_id=admin_id,
        name=name,
        age=age,
        sex=sex,
        srq20_total=int(srq_total) if isinstance(srq_total, (int, float, str)) and str(srq_total).isdigit() else None,
        srq20_classification=srq_class,
        srq20_items_yes=srq_items_yes if isinstance(srq_items_yes, list) else None,
        srq_q17=srq_q17 if srq_q17 in ("Sim", "Não") else None,
        raw_payload=payload
    )
    db.session.add(obj)
    db.session.commit()

    return jsonify({"ok": True, "id": obj.id})

# ---- Lista (privado) ----
@app.route('/questionnaire_results')
@login_required
def questionnaire_results():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    q = QuestionnaireResult.query
    if not is_admin(user):
        q = q.filter_by(admin_id=user.id)
    results = q.order_by(QuestionnaireResult.created_at.desc()).all()

    # username consistent for all templates
    username = getattr(user, 'username', None) if user else None

    return render_template(
        'questionnaire_results.html',
        results=results,     # objetos ORM (usa br_date(), attrs em EN)
        user=user,
        username=username
    )

# ---- Detalhe (privado) ----
@app.route('/questionnaire_patient/<int:questionnaire_id>')
@login_required
def questionnaire_patient(questionnaire_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    r = QuestionnaireResult.query.get_or_404(questionnaire_id)
    if not is_admin(user) and r.admin_id != user.id:
        abort(403)

    patient = r.to_dict()  # dictionary with PT/BR keywords
    username = getattr(user, 'username', None) if user else None
    return render_template('questionnaire_patient.html', patient=patient, user=user, username=username)

# ---- Deleção (privado, POST) ----
@app.route('/delete_questionnaire_result', methods=['POST'])
@login_required
def delete_questionnaire_result():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    qid = request.form.get('questionnaire_id', type=int)
    if not qid:
        abort(400)
    r = QuestionnaireResult.query.get_or_404(qid)
    if not is_admin(user) and r.admin_id != user.id:
        abort(403)
    db.session.delete(r)
    db.session.commit()
    return redirect(url_for('questionnaire_results'))

# ------------------------------------------------------------------------------
# Training (Premium)
# ------------------------------------------------------------------------------
@app.route('/training')
@login_required
@feature_required('training')
def training():
    return render_template("training.html")

@app.route('/videos')
@login_required
@feature_required('training')
def videos():
    return render_template("videos.html")

@app.route('/watch_video/<playback_id>')
@login_required
@feature_required('training')
def watch_video(playback_id):
    return render_template("videos.html", playback_id=playback_id)

# ------------------------------------------------------------------------------
# Plans
# ------------------------------------------------------------------------------
@app.route('/plans')
def plans():
    user = get_logged_user()
    return render_template('plans.html', user=user, next=request.args.get('next', '/index'))

@app.route('/subscribe', methods=['POST'])
@login_required
def subscribe():
    user = get_logged_user()
    selected = request.form.get('plan', 'standard')
    pricing = {'standard': 49, 'plus': 99, 'premium': 179}
    if selected not in pricing:
        flash('Plano inválido.', 'danger')
        return redirect(url_for('plans'))
    link = generate_payment_link(selected, pricing[selected])
    return redirect(link or url_for('plans'))

@app.route('/confirm_pix', methods=['POST'])
@login_required
def confirm_pix():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    plan = (request.form.get('plan') or '').strip().lower()
    txid = (request.form.get('txid') or '').strip()
    payload = (request.form.get('payload') or '').strip()
    receipt = request.files.get('receipt')

    if not receipt or not receipt.filename:
        flash('Envie um comprovante para continuar.', 'warning')
        return redirect(url_for('plans'))

    filename = secure_filename(receipt.filename or "receipt.bin")
    mime = receipt.mimetype or "application/octet-stream"
    raw = receipt.read()
    if not raw:
        flash('Comprovante inválido.', 'warning')
        return redirect(url_for('plans'))

    sf = save_secure_file(
        owner_user_id=user.id,
        kind="pix_receipt",
        filename=filename,
        mime_type=mime,
        raw_bytes=raw
    )
    receipt_url = url_for('file_download_signed', token=generate_file_token(sf.id), _external=True)

    amount = PLAN_PRICES.get(plan, 0.0)
    if AUTO_WHATSAPP_ENABLED:
        try:
            send_pix_receipt_admin(
                admin_phone=ADMIN_WHATSAPP,
                user_name=user.name or user.username,
                user_id=user.id,
                user_email=user.email,
                plan=plan,
                amount=float(amount),
                txid=txid,
                receipt_url=receipt_url,
                payload_text=payload or None,
            )
        except Exception as e:
            app.logger.error("Erro ao encaminhar comprovante PIX ao admin: %s", e)
    else:
        app.logger.info("Envio automático por WhatsApp desativado; comprovante PIX não será enviado por WhatsApp.")

    flash('Comprovante enviado. Nossa equipe vai validar o pagamento.', 'success')
    return redirect(url_for('plans'))

# ------------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
