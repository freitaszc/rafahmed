import os
import io
import re
import json
import base64
import secrets
import tempfile
import time as pytime
from io import BytesIO
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Any, Optional, cast

import weasyprint
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
from sqlalchemy import text, inspect, desc, and_

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow

from prescription import analyze_pdf
from whatsapp import send_pdf_whatsapp, send_quote_whatsapp
from mercado_pago import generate_payment_link
from email_utils import send_email_quote
import qrcode

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
DATABASE_URL = os.getenv('DATABASE_URL') or f'sqlite:///{db_path}'

# static dir + uploads (gerais)
STATIC_DIR = os.path.join(app.root_path, 'static')
os.makedirs(STATIC_DIR, exist_ok=True)
UPLOAD_FOLDER = os.path.join(STATIC_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Use stable secret key if provided; otherwise generate one (sessions/tokens persist across restarts if set)
app.secret_key = os.getenv("APP_SECRET_KEY") or secrets.token_hex(32)

db.init_app(app)
migrate = Migrate(app, db)

def ensure_tables():
    with app.app_context():
        insp = inspect(db.engine)
        if not insp.has_table('pdf_files'):
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
    # Optional: add per-file ACL checks here (e.g., owner_user_id == user.id) depending on kind
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

# ------------------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------------------
def get_logged_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return User.query.get(uid)

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

# Expor helpers no Jinja (mantendo compatibilidade nos templates)
app.jinja_env.globals.update(
    has_feature=has_feature,
    pdf_token=generate_file_token,
    make_pdf_token=generate_file_token
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

# ------------------------------------------------------------------------------
# Public pages & auth
# ------------------------------------------------------------------------------
@app.route('/schedule_consultation')
def schedule_consultation():
    doctors = Doctor.query.order_by(Doctor.name).all()
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
        return render_template('register.html')

    username     = (request.form.get('username', '')).strip()
    email        = (request.form.get('email', '')).strip().lower()
    password     = request.form.get('password', '')
    confirm      = request.form.get('confirm_password', '')
    company_code = (request.form.get('company_code', '')).strip().upper()
    account_type = (request.form.get('account_type', '')).strip().lower()

    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        session['register_flash'] = True
        flash('E-mail inválido.', 'warning')
        return redirect(url_for('register'))

    exists_email = User.query.filter_by(email=email).first()
    exists_user  = User.query.filter_by(username=username).first()
    if exists_email or exists_user:
        session['register_flash'] = True
        flash('E-mail ou usuário já cadastrado.', 'warning')
        return redirect(url_for('register'))

    if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        session['register_flash'] = True
        flash('A senha deve ter 8+ caracteres, letras, números e um símbolo.', 'warning')
        return redirect(url_for('register'))
    if password != confirm:
        session['register_flash'] = True
        flash('As senhas não coincidem.', 'warning')
        return redirect(url_for('register'))

    company = None
    if company_code:
        company = Company.query.filter_by(access_code=company_code).first()
        if not company:
            session['register_flash'] = True
            flash('Código da empresa inválido.', 'danger')
            return redirect(url_for('register'))

    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        company_id=company.id if company else None
    )
    db.session.add(user)
    db.session.commit()

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
            return redirect(url_for('index'))

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
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
    bd    = request.form.get("birthdate", "")
    email = request.form.get("email", "").strip()
    user.name = f"{fname} {sname}".strip()
    try:
        user.birthdate = datetime.strptime(bd, "%Y-%m-%d").date()
    except ValueError:
        pass
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

    if not is_package_available(user.id):
        flash('Seu pacote de análises acabou. Por favor, adquira mais para continuar.', 'warning')
        return redirect(url_for('purchase'))

    if request.method == 'POST':
        using_manual = 'manual_entry' in request.form
        patient = None

        if using_manual:
            manual_text = (request.form.get('lab_results') or '').strip()

            result = analyze_pdf(manual_text, manual=True)
            if not isinstance(result, (list, tuple)) or len(result) != 8:
                flash('Erro ao processar análise manual.', 'danger')
                return render_template('upload.html')

            diagnostic, prescription, name, gender, age, cpf, phone, doctor_name = result

            if not cpf:
                cpf = f"no_cpf_{int(pytime.time())}"

            patient = add_patient(
                name=name,
                age=int(age) if str(age).isdigit() else None,
                cpf=cpf,
                gender=gender or None,
                phone=phone or None,
                doctor_id=user.id,
                prescription=prescription
            )
        else:
            pdf_file = request.files.get('pdf_file')
            if not pdf_file or not pdf_file.filename:
                return render_template('upload.html', error='Por favor, selecione um arquivo PDF.')

            raw_pdf = pdf_file.read()
            filename = secure_filename(pdf_file.filename or "doc.pdf")

            orig_sf = save_secure_file(
                owner_user_id=user.id,
                kind="original_pdf",
                filename=filename,
                mime_type=pdf_file.mimetype or "application/pdf",
                raw_bytes=raw_pdf,
            )

            # analyze using a temp file
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as tmp:
                tmp.write(raw_pdf)
                tmp.flush()
                result = analyze_pdf(tmp.name)

            if not isinstance(result, (list, tuple)) or len(result) != 8:
                flash('Erro ao processar o PDF.', 'danger')
                return render_template('upload.html')

            diagnostic, prescription, name, gender, age, cpf, phone, doctor_name = result

            patient = add_patient(
                name=name,
                age=int(age) if str(age).isdigit() else None,
                cpf=cpf or None,
                gender=gender or None,
                phone=phone or None,
                doctor_id=user.id,
                prescription=prescription
            )

        # tenta criar evento no Google Calendar (não bloqueia fluxo)
        start_dt = datetime.now()
        end_dt   = start_dt + timedelta(hours=1)
        notes    = f"Diagnóstico:\n{diagnostic}\n\nPrescrição:\n{prescription}"
        try:
            create_user_event(
                summary=f"Consulta - {name}",
                start_datetime=start_dt.strftime('%Y-%m-%dT%H:%M:%S'),
                end_datetime=end_dt.strftime('%Y-%m-%dT%H:%M:%S'),
                description=notes
            )
        except Exception as e:
            app.logger.error(f"Erro ao criar evento no Google Calendar: {e}")

        session['diagnostic_text']   = diagnostic
        session['prescription_text'] = prescription
        session['doctor_name']       = doctor_name
        session['patient_info']      = (
            f"Paciente: {name}\n"
            f"Idade: {age}\n"
            f"CPF: {cpf}\n"
            f"Sexo: {gender}\n"
            f"Telefone: {phone}"
        )

        html = render_template(
            "result_pdf.html",
            diagnostic_text=diagnostic,
            prescription_text=prescription,
            doctor_name=doctor_name,
            patient_info=session['patient_info'],
            logo_path=url_for('static', filename='images/logo.png', _external=False)
        )
        static_base = os.path.join(app.root_path, 'static')
        pdf_bytes = weasyprint.HTML(string=html, base_url=static_base).write_pdf()

        # Save analyzed report securely
        cpf_clean = (cpf or "").replace(".", "").replace("-", "").strip()
        safe_name = f"result_{cpf_clean or 'no_cpf'}.pdf"
        an_sf = save_secure_file(
            owner_user_id=user.id,
            kind="analyzed_pdf",
            filename=safe_name,
            mime_type="application/pdf",
            raw_bytes=pdf_bytes,
        )

        # Links to send (signed, 1h TTL when used)
        analyzed_link = url_for('file_download_signed', token=generate_file_token(an_sf.id), _external=True)

        original_link = None
        if not using_manual:
            original_link = url_for('file_download_signed', token=generate_file_token(orig_sf.id), _external=True)
        try:
            send_pdf_whatsapp(
                doctor_name=doctor_name,
                patient_name=name,
                analyzed_pdf_link=analyzed_link,
                original_pdf_link=original_link
            )
        except Exception as e:
            app.logger.error(f"Erro ao enviar PDF no WhatsApp: {e}")

        # consumo do pacote
        try:
            info = get_package_info(user.id)
            usage = (info.get('used') or 0) + 1
            update_package_usage(user.id, usage)
        except Exception as e:
            app.logger.error(f"Erro ao atualizar uso de pacote: {e}")

        return render_template(
            'result.html',
            patient=patient,
            diagnostic_text=diagnostic,
            prescription_text=prescription
        )

    return render_template('upload.html')


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

# ------------------------------------------------------------------------------
# Agenda / disponibilidade
# ------------------------------------------------------------------------------
@app.route('/agenda')
@login_required
def agenda():
    return render_template('agenda.html')

@app.route('/doctors')
@login_required
def doctors():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    doctors = Doctor.query.order_by(Doctor.name).all()
    return render_template('doctors.html', doctors=doctors, user=user)

@app.route('/add_doctor', methods=['POST'])
@login_required
def add_doctor_route():
    user = get_logged_user()
    if not user:
        flash("Você não está autorizado.", "danger")
        return redirect(url_for("login"))

    name      = (request.form.get('name') or '').strip()
    phone     = (request.form.get('phone') or '').strip()

    if not name:
        flash("Nome do prescritor é obrigatório.", "warning")
        return redirect(url_for("doctors"))

    if Doctor.query.filter_by(name=name).first():
        flash("Já existe um prescritor com esse nome.", "warning")
        return redirect(url_for("doctors"))

    doctor = Doctor(name=name, phone=phone or None)
    db.session.add(doctor)
    db.session.commit()

    flash(f"Prescritor {doctor.name} cadastrado!", "success")
    return redirect(url_for("doctors"))

@app.route('/update_doctor/<int:doctor_id>', methods=['POST'])
@login_required
def update_doctor(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    doctor.name      = (request.form.get('name') or doctor.name).strip()
    doctor.phone     = (request.form.get('phone') or doctor.phone).strip()
    db.session.commit()
    flash("Prescritor atualizado!", "success")
    return redirect(url_for("doctors"))

@app.route('/delete_doctor/<int:doctor_id>', methods=['POST'])
@login_required
def delete_doctor(doctor_id):
    user = get_logged_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    doc = Doctor.query.get(doctor_id)
    if not doc:
        return jsonify({"ok": False, "error": "Médico não encontrado."}), 404

    try:
        # if admin he can delete any patient
        if user.username.lower() == 'admin':
            DoctorDateAvailability.query.filter_by(doctor_id=doctor_id).delete(synchronize_session=False)
            DoctorAvailability.query.filter_by(doctor_id=doctor_id).delete(synchronize_session=False)
            Patient.query.filter_by(doctor_id=doctor_id).update({"doctor_id": None}, synchronize_session=False)
            Consult.query.filter_by(doctor_id=doctor_id).delete(synchronize_session=False)
            db.session.delete(doc)
            db.session.commit()
            flash("Prescritor excluído com todas as dependências removidas.", "info")
            return redirect(url_for("doctors"))

        # If not admin he can only delete his own patients
        else:
            db.session.delete(doc)
            db.session.commit()
            flash("Prescritor excluído.", "info")
            return redirect(url_for("doctors"))

    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/availability', methods=['GET', 'POST'])
@login_required
def availability():
    # ONly admin
    user = get_logged_user()
    if not user or user.username.lower() != 'admin':
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
    if not user or user.username.lower() != 'admin':
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
    if not user or user.username.lower() != 'admin':
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
    if not user or user.username.lower() != 'admin':
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
    if not user or user.username.lower() != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))

    comp = Company.query.get(company_id)
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
    if not user or user.username.lower() != 'admin':
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
    if not user or user.username.lower() != 'admin':
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
    if not user or user.username.lower() != 'admin':
        abort(403)
    pdf = PdfFile.query.get_or_404(file_id)
    if not pdf.secure_file_id:
        abort(404)
    return redirect(url_for('file_download_auth', file_id=pdf.secure_file_id))

@app.get('/pdfs/download/<int:file_id>')
def download_pdf_admin(file_id):
    user = get_logged_user()
    if not user or user.username.lower() != 'admin':
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
    if not user or user.username.lower() != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))

    if 'PdfFile' not in globals():
        flash('Modelo PdfFile não encontrado.', 'danger')
        return redirect(url_for('admin_pdfs'))

    pdf = PdfFile.query.get(pdf_id)
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
    if user.username.lower() != 'admin':
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
    if not patient or patient.doctor_id != user.id:
        abort(403)
    notes = request.form.get('notes', '').strip()
    if not notes:
        flash('Notas obrigatórias.', 'warning')
        return redirect(url_for('patient_result', patient_id=patient_id))
    add_consult(patient_id=patient_id, doctor_id=user.id, notes=notes)
    flash('Consulta salva.', 'success')
    return redirect(url_for('patient_result', patient_id=patient_id))

@app.route('/product/<int:product_id>')
def product_result(product_id):
    product = get_product_by_id(product_id)
    if not product:
        return "Produto não encontrado", 404
    return render_template('product_result.html', product=product)

@app.route('/download_pdf/<int:patient_id>')
def download_pdf(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient_by_id(patient_id)
    if not patient or patient.doctor_id != user.id:
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
    pdf_bytes: bytes = weasyprint.HTML(string=html, base_url=static_base).write_pdf()  # type: ignore

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
def edit_patient(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient_by_id(patient_id)
    if not patient:
        abort(404)

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
            doctor_id=patient.doctor_id, prescription=prescription, status=status
        )
        return redirect(url_for('catalog'))

    return render_template('edit_patient.html', patient=patient)

@app.route('/patient_result/<int:patient_id>')
def patient_result(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient_by_id(patient_id)
    if not patient or patient.doctor_id != user.id:
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
    if not patient or patient.doctor_id != user.id:
        abort(403)

    return render_template('patient_info.html', patient=patient)

@app.route('/api/edit_patient/<int:patient_id>', methods=['POST'])
@login_required
def edit_patient_api(patient_id):
    user = get_logged_user()
    if not user:
        return jsonify(success=False, error="Não autenticado"), 403

    patient = get_patient_by_id(patient_id)
    if not patient or patient.doctor_id != user.id:
        return jsonify(success=False, error="Paciente não encontrado"), 404

    data = request.get_json() or {}
    update_patient(
        patient_id   = patient_id,
        name         = data.get('name', patient.name),
        age          = int(data.get('age', patient.age) or 0),
        cpf          = data.get('cpf', patient.cpf),
        gender       = data.get('gender', patient.gender),
        phone        = data.get('phone', patient.phone),
        doctor_id    = user.id,
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
    if not patient or patient.doctor_id != user.id:
        abort(403)

    delete_patient_record(patient_id)
    return redirect(url_for('catalog'))

@app.route('/toggle_patient_status/<int:patient_id>/<new_status>', methods=['POST'])
def toggle_patient_status(patient_id, new_status):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient_by_id(patient_id)
    if not patient:
        abort(404)

    update_patient(
        patient_id=patient_id,
        name=patient.name, age=patient.age, cpf=patient.cpf, gender=patient.gender,
        phone=patient.phone, doctor_id=patient.doctor_id,
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

    patient = add_patient(
        name=name, age=age, cpf=cpf or None, gender=gender or None,
        phone=phone or None, doctor_id=user.id, prescription=prescription
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
            if s.phone:
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

        flash('Cotação criada e notificada aos fornecedores!', 'success')
        return redirect(url_for('quote_index'))

    return render_template('create_quote.html', suppliers=suppliers)

@app.route('/quote_index')
@login_required
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
def respond_quote(quote_id, supplier_id):
    quote = Quote.query.get_or_404(quote_id)
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
    docs = Doctor.query.order_by(Doctor.name).all()
    return jsonify([{"id": d.id, "name": d.name} for d in docs])

@app.route('/api/add_consult', methods=['POST'])
def api_add_consult():
    user = get_logged_user()
    if not user:
        return jsonify(success=False, error='UNAUTHORIZED'), 403

    data = request.get_json() or {}
    pid = data.get('patient_id')
    notes = data.get('notes', '').strip() or None
    consult = add_consult(patient_id=pid, doctor_id=user.id, notes=notes)

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
        doctor_id=doctor_id, prescription=None
    )

    c = Consult(
        patient_id=patient.id,
        doctor_id=doctor_id,
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

    doctor = Doctor.query.get(doctor_id)
    summary = f"Consulta — {name} (Dr(a). {doctor.name})" if doctor else f"Consulta — {name}"
    description = f"CPF: {cpf}\nTelefone: {phone}\nData: {date_br}\nHorário: {time_hm}"

    try:
        create_admin_event(summary=summary, start_datetime=start_iso, end_datetime=end_iso, description=description)
    except Exception as e:
        current_app.logger.error(f"[Calendar] Erro ao agendar no calendário do admin: {e}")
        return redirect(url_for('hero'))

    return redirect(url_for('hero'))

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
    if u and u.username.lower() == 'admin':
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
def api_events():
    doctor_id = request.args.get('doctor_id', type=int)
    q = Consult.query
    if doctor_id:
        q = q.filter_by(doctor_id=doctor_id)

    events = []
    for c in q.all():
        if c.time:
            start = datetime.combine(c.date, c.time).isoformat()
            events.append({"title": c.notes or "Consulta", "start": start})
        else:
            events.append({"title": c.notes or "Consulta", "start": c.date.isoformat(), "allDay": True})
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
def submit_consultation():
    """
    Agendamento interno (ex.: agenda/admin) — valida contra DoctorDateAvailability
    e grava a consulta. Cria o paciente se não foi informado.
    """
    patient_id = request.form.get('patient_id', type=int)
    doctor_id  = request.form.get('doctor_id', type=int)
    date_str   = (request.form.get('date') or '').strip()   # dd/mm/aaaa
    time_str   = (request.form.get('time') or '').strip()   # HH:MM (opcional)
    notes      = (request.form.get('title') or '').strip()

    if not doctor_id or not date_str or not notes:
        return "Missing fields", 400

    # Data BR
    try:
        day = datetime.strptime(date_str, '%d/%m/%Y').date()
    except ValueError:
        return "Invalid date (use dd/mm/aaaa)", 400

    # Hora (opcional)
    t = None
    if time_str:
        try:
            t = datetime.strptime(time_str, '%H:%M').time()
        except ValueError:
            return "Invalid time (use HH:MM)", 400

    # Se houver horário, validar contra blocos da DATA (não mais por weekday)
    if t:
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

    # Criar paciente se não veio ID
    if not patient_id:
        p = Patient(name=notes or "Paciente", status='Ativo', doctor_id=doctor_id)
        db.session.add(p)
        db.session.flush()
        patient_id = p.id

    c = Consult(patient_id=patient_id, doctor_id=doctor_id, date=day, time=t, notes=notes)
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

    doctor_id = request.args.get('admin', type=int) or session.get('user_id')
    if doctor_id is None:
        return jsonify(status='error', error='doctor_id ausente'), 400

    patient = add_patient(
        name=name, age=age, cpf=None, gender=None, phone=None,
        doctor_id=doctor_id, prescription=f"Autoavaliação: {data.get('risco')}"
    )

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
        patient_id=patient.id
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
        "preocupacao":      "Nas últimas 2 semanas, você não foi capaz de controlar a preocupação?",
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
def questionnaire_results():
    user = get_logged_user()

    results = QuestionnaireResult.query.order_by(
        QuestionnaireResult.created_at.desc()
    ).all()

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
def questionnaire_patient(questionnaire_id):
    user = get_logged_user()
    r = QuestionnaireResult.query.get_or_404(questionnaire_id)

    patient = r.to_dict()  # dictionary with PT/BR keywords
    username = getattr(user, 'username', None) if user else None
    return render_template('questionnaire_patient.html', patient=patient, user=user, username=username)

# ---- Deleção (privado, POST) ----
@app.route('/delete_questionnaire_result', methods=['POST'])
def delete_questionnaire_result():
    qid = request.form.get('questionnaire_id', type=int)
    if not qid:
        abort(400)
    r = QuestionnaireResult.query.get_or_404(qid)
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

# ------------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
