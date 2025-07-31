import os
import json
import secrets
import uuid
from sqlalchemy import func, cast, Date
from datetime import datetime, timedelta
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    make_response,
    abort,
)
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, or_
from dotenv import load_dotenv
import jwt
import weasyprint
from markupsafe import escape
import re

from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow

from prescription import analyze_pdf
from whatsapp import send_pdf_whatsapp, send_quote_whatsapp
from mercado_pago import generate_payment_link
from email_utils import send_email_quote

from records import (
    add_patient, get_consults, get_patient, get_patients, update_patient,
    update_prescription_in_consult, delete_patient_record, add_product, get_products,
    update_product_status, update_doctor, update_patient_status, save_products, get_doctors,
    add_doctor_if_not_exists, get_package_info,  is_package_available, update_package_usage,
)

from models import (
    db,
    User,
    Company,
    Supplier,
    Quote,
    QuoteResponse,
    Doctor,
    Consult,
    Patient,
    QuizResult,
)

load_dotenv()

app = Flask(__name__)

# ✅ Define caminho absoluto da pasta 'instance' corretamente
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
os.makedirs(base_dir, exist_ok=True)

# ✅ Caminho fixo para o banco de dados sempre dentro da pasta 'web/instance/'
db_path = os.path.join(base_dir, 'web.db')
DATABASE_URL = os.getenv('DATABASE_URL') or f'sqlite:///{db_path}'

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = secrets.token_hex(32)

db.init_app(app)

def get_logged_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return User.query.get(uid)

@app.before_first_request
def create_tables():
    """
    Garante que o banco tenha todas as tabelas antes de atender a primeira requisição.
    Útil em ambientes como Render/Gunicorn onde __main__ não é executado.
    """
    db.create_all()

# lista de endpoints (ou prefixos de caminho) que NÃO exigem login
PUBLIC_ENDPOINTS = {
    'hero', 
    'about',
    'privacy_policy',
    'register',
    'login',
    'static'
}

@app.before_request
def require_login():
    if get_logged_user():
        return

    if request.path.startswith('/static/'):
        return

    endpoint = request.endpoint or ''
    if endpoint.split('.')[-1] in PUBLIC_ENDPOINTS:
        return

    return redirect(url_for('login'))

# ==============================================
# AUTHENTICATION AND ACCOUNT MANAGEMENT
# ==============================================
@app.route('/')
def hero():
    return render_template('hero.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Sanitização
        username     = escape(request.form.get('username', '').strip())
        email        = escape(request.form.get('email', '').strip().lower())
        password     = request.form.get('password', '')
        confirm      = request.form.get('confirm_password', '')
        company_code = escape(request.form.get('company_code', '').strip().upper())

        # Validação de e-mail com regex
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            flash('E-mail inválido.', 'warning')
            return redirect(url_for('register'))

        # Verifica se email ou username já existem
        exists = User.query.filter(
            or_(User.email == email, User.username == username)  # type: ignore
        ).first()
        if exists:
            flash('E-mail ou usuário já cadastrado.', 'warning')
            return redirect(url_for('register'))

        # Verificação da senha
        if len(password) < 8:
            flash('A senha deve ter pelo menos 8 caracteres.', 'warning')
            return redirect(url_for('register'))
        if not re.search(r'[A-ZÀ-ÿa-z]', password):
            flash('A senha deve conter letras.', 'warning')
            return redirect(url_for('register'))
        if not re.search(r'[0-9]', password):
            flash('A senha deve conter números.', 'warning')
            return redirect(url_for('register'))
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('A senha deve conter pelo menos um símbolo especial.', 'warning')
            return redirect(url_for('register'))
        if password != confirm:
            flash('As senhas não coincidem.', 'warning')
            return redirect(url_for('register'))

        # Validação da empresa (opcional)
        company = None
        if company_code:
            company = Company.query.filter_by(access_code=company_code).first()
            if not company:
                flash('Código da empresa inválido.', 'danger')
                return redirect(url_for('register'))

        # Cria o novo usuário
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

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        login = request.form.get('login', '').strip()
        pwd   = request.form.get('password', '')

        # se o login for exatamente 'admin', busca por username
        if login.lower() == 'admin':
            user = User.query.filter_by(username='admin').first()
        else:
            # caso contrário, busca por e‑mail
            user = User.query.filter_by(email=login.lower()).first()

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
    fname = request.form.get("name","").strip()
    sname = request.form.get("secondname","").strip()
    bd    = request.form.get("birthdate","")
    email = request.form.get("email","").strip()
    user.name = f"{fname} {sname}".strip()
    try:
        user.birthdate = datetime.strptime(bd, "%Y-%m-%d").date()
    except:
        pass
    user.email = email
    img = request.files.get("profile_image")
    if img and img.filename:
        folder = os.path.join(app.root_path, "static/profile_images")
        os.makedirs(folder, exist_ok=True)
        fn = f"{user.username}_profile.png"
        path = os.path.join(folder, fn)
        img.save(path)
        user.profile_image = f"profile_images/{fn}"
    db.session.commit()
    return redirect(url_for("account"))

@app.route('/update_password', methods=['POST'])
def update_password():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    cur = request.form.get("current_password","")
    new = request.form.get("new_password","")
    conf= request.form.get("confirm_password","")
    if not check_password_hash(user.password_hash, cur):
        flash("Senha atual incorreta.","danger")
        return redirect(url_for("account"))
    if new != conf:
        flash("As senhas não coincidem.","danger")
        return redirect(url_for("account"))
    user.password_hash = generate_password_hash(new)
    db.session.commit()
    flash("Senha atualizada.","success")
    return redirect(url_for("account"))

@app.route('/remove_profile_image', methods=['POST'])
def remove_profile_image():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    if user.profile_image and user.profile_image != 'images/user-icon.png':
        p = os.path.join(app.root_path, "static", user.profile_image)
        if os.path.exists(p):
            os.remove(p)
    user.profile_image = 'images/user-icon.png'
    db.session.commit()
    return redirect(url_for("account"))

@app.route('/RafahMed-lab')
def RafahMed_lab():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    if not is_package_available(user.id):
        return redirect(url_for('purchase'))
    return render_template('upload.html')

@app.route('/users')
def list_users():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    # only admin may view the list
    if user.username.lower() != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))

    users = User.query.order_by(User.id).all()
    return render_template('users.html', users=users)

@app.route('/admin/companies', methods=['GET', 'POST'])
def admin_companies():
    user = get_logged_user()
    if not user or user.username.lower() != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))

    # POST: criar nova empresa
    if request.method == 'POST':
        name = request.form.get('company_name', '').strip()
        code = request.form.get('access_code', '').strip()
        if not (name and code):
            flash('Nome e código são obrigatórios.', 'warning')
        else:
            exists = Company.query.filter_by(access_code=code).first()
            if exists:
                flash(f'Empresa com código "{code}" já existe.', 'warning')
            else:
                db.session.add(Company(name=name, access_code=code))
                db.session.commit()
                flash(f'Empresa "{name}" criada com sucesso!', 'success')
        return redirect(url_for('admin_companies'))

    # GET: listar empresas e usuários
    companies = Company.query.order_by(Company.name).all()
    # supõe-se que User tenha company_id (nullable)
    personal_users = User.query.filter(User.company_id.is_(None)).order_by(User.id).all()  # type: ignore
    return render_template(
        'admin_companies.html',
        companies=companies,
        personal_users=personal_users
    )

@app.route('/add_company', methods=['POST'])
def add_company():
    user = get_logged_user()
    if not user or user.username.lower() != 'admin':
        abort(403)

    name = request.form.get('company_name','').strip()
    code = request.form.get('access_code','').strip()
    if not name or not code:
        flash('Nome e código são obrigatórios.', 'warning')
        return redirect(url_for('admin_companies'))

    # evita duplicados
    if Company.query.filter_by(access_code=code).first():
        flash(f'Já existe empresa com código {code}.', 'warning')
        return redirect(url_for('admin_companies'))

    c = Company(name=name, access_code=code)
    db.session.add(c)
    db.session.commit()
    flash(f'Empresa “{name}” cadastrada.', 'success')
    return redirect(url_for('admin_companies'))

@app.route('/delete_company/<int:company_id>', methods=['POST'])
def delete_company(company_id):
    user = get_logged_user()
    # só admin pode excluir
    if not user or user.username.lower() != 'admin':
        abort(403)

    company = Company.query.get_or_404(company_id)
    # opcional: se desejar evitar excluir empresas com usuários vinculados
    if company.users:
         flash('Não é possível excluir empresa com usuários vinculados.', 'warning')
         return redirect(url_for('admin_companies'))

    db.session.delete(company)
    db.session.commit()
    flash(f'Empresa "{company.name}" removida com sucesso.', 'success')
    return redirect(url_for('admin_companies'))

# ==============================================
# DASHBOARD AND PDF UPLOAD
# ==============================================
@app.route('/index')
def index():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    try:
        used = user.packets_used or 0
        remaining = user.packets_remaining or 50
    except AttributeError:
        used = 0
        remaining = 50

    # Coleta dados de quiz dos últimos 7 dias
    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=6)

    results = (
        db.session.query(
            func.date(QuizResult.date).label('day'),
            func.count().label('count')
        )
        .filter(
            QuizResult.doctor_id == user.id,
            cast(QuizResult.date, Date) >= week_ago
        )
        .group_by(func.date(QuizResult.date))
        .order_by(func.date(QuizResult.date))
        .all()
    )

    date_counts = {r.day.strftime('%d/%m'): r.count for r in results}
    total_count = sum(date_counts.values()) #type: ignore
    media = round(total_count / 7, 2) if total_count else 0

    quiz_chart_data = []
    for i in range(7):
        day = (week_ago + timedelta(days=i)).strftime('%d/%m')
        count = date_counts.get(day, 0)
        quiz_chart_data.append({
            'date': day,
            'count': count,
            'media': media
        })

    return render_template(
        'index.html',
        quiz_chart_data=quiz_chart_data,
        used=used,
        remaining=remaining,
        username=user.username,
        user=user
    )

# ==============================================
# UPLOAD DE PDF / ENTRADA MANUAL E GERAÇÃO DE RESULTADOS
# ==============================================
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    # Verifica pacote disponível
    if not is_package_available(user.id):
        flash('Seu pacote de análises acabou. Por favor, adquira mais para continuar.', 'warning')
        return redirect(url_for('purchase'))

    if request.method == 'POST':
        # === Inserção Manual ===
        if 'manual_entry' in request.form:
            name        = request.form['name']
            age         = int(request.form['age'])
            cpf         = request.form['cpf']
            gender      = request.form['gender']
            phone       = request.form['phone']
            doctor_name = request.form['doctor']
            manual_text = request.form['lab_results']

            doctor_id, _ = add_doctor_if_not_exists(doctor_name)
            diagnostic, prescription = analyze_pdf(manual_text, manual=True)  # type: ignore

            # Salva paciente no banco
            patient_id = add_patient(name, age, cpf, gender, phone, doctor_id, prescription)

            # Agenda no Google Calendar
            title = f"Consulta - {name}"
            notes = f"Diagnóstico:\n{diagnostic}\n\nPrescrição:\n{prescription}"
            start_dt = datetime.now()
            end_dt   = start_dt + timedelta(hours=1)
            try:
                create_user_event(title,
                                  start_dt.strftime('%Y-%m-%dT%H:%M:%S'),
                                  end_dt.strftime('%Y-%m-%dT%H:%M:%S'),
                                  notes)
            except Exception as e:
                print("Erro ao criar evento:", e)

            # Prepara PDF
            session['diagnostic_text'] = diagnostic
            session['prescription_text'] = prescription
            session['doctor_name']      = doctor_name
            session['patient_info']     = (
                f"Paciente: {name}\n"
                f"Idade: {age}\n"
                f"CPF: {cpf}\n"
                f"Sexo: {gender}\n"
                f"Telefone: {phone}\n"
                f"Médico: {doctor_name}"
            )

            html = render_template(
                "result_pdf.html",
                diagnostic_text=session['diagnostic_text'],
                prescription_text=session['prescription_text'],
                doctor_name=session['doctor_name'],
                patient_info=session['patient_info'],
                logo_path=os.path.join(app.root_path, 'static', 'images', 'logo.png')
            )
            pdf = weasyprint.HTML(string=html,
                                  base_url=os.path.join(app.root_path, 'static')).write_pdf()

            # Salva PDF em disco
            cpf_clean = cpf.replace('.', '').replace('-', '')
            pdf_filename = f"result_{cpf_clean}.pdf"
            output_folder = os.path.join(app.root_path, "static", "output")
            os.makedirs(output_folder, exist_ok=True)
            pdf_path = os.path.join(output_folder, pdf_filename)
            with open(pdf_path, 'wb') as f:
                f.write(pdf)  # type: ignore

            # Envia por WhatsApp
            pdf_link = url_for('static', filename=f"output/{pdf_filename}", _external=True)
            send_pdf_whatsapp(
                doctor_name=doctor_name,
                patient_name=name,
                analyzed_pdf_link=pdf_link,
                original_pdf_link=None
            )

            # Atualiza uso de pacote
            update_package_usage(user.id, get_package_info(user.id)['used'] + 1)

            return render_template('result.html',
                                   diagnostic_text=diagnostic,
                                   prescription_text=prescription)

        # === Upload de arquivo PDF ===
        pdf_file = request.files.get('pdf_file')
        if not pdf_file or pdf_file.filename == '':
            return render_template('upload.html', error='Por favor, selecione um arquivo PDF.')

        # Salva no disco
        uploads_folder = os.path.join(app.root_path, "static", "uploads")
        os.makedirs(uploads_folder, exist_ok=True)
        filename = pdf_file.filename
        if not filename:
            filename = "file.pdf"
        upload_path = os.path.join(uploads_folder, filename)
        pdf_file.save(upload_path)

        # Analisa e extrai dados
        diagnostic, prescription, name, gender, age, cpf, phone, doctor_name = analyze_pdf(upload_path)  # type: ignore
        doctor_id, _ = add_doctor_if_not_exists(doctor_name)
        patient_id   = add_patient(name, age, cpf, gender, phone, doctor_id, prescription)

        # Agenda no Google Calendar
        title   = f"Consulta - {name}"
        notes   = f"Diagnóstico:\n{diagnostic}\n\nPrescrição:\n{prescription}"
        start_dt = datetime.now()
        end_dt   = start_dt + timedelta(hours=1)
        try:
            create_user_event(title,
                              start_dt.strftime('%Y-%m-%dT%H:%M:%S'),
                              end_dt.strftime('%Y-%m-%dT%H:%M:%S'),
                              notes)
        except Exception as e:
            print("Erro ao criar evento:", e)

        # Prepara sessão
        session['diagnostic_text']   = diagnostic
        session['prescription_text'] = prescription
        session['doctor_name']       = doctor_name
        session['patient_info']      = (
            f"Paciente: {name}\n"
            f"Idade: {age}\n"
            f"CPF: {cpf}\n"
            f"Sexo: {gender}\n"
            f"Telefone: {phone}\n"
            f"Médico: {doctor_name}"
        )

        # Gera PDF
        html = render_template(
            "result_pdf.html",
            diagnostic_text=session['diagnostic_text'],
            prescription_text=session['prescription_text'],
            doctor_name=session['doctor_name'],
            patient_info=session['patient_info'],
            logo_path=os.path.join(app.root_path, 'static', 'images', 'logo.png')
        )
        pdf = weasyprint.HTML(string=html,
                              base_url=os.path.join(app.root_path, 'static')).write_pdf()

        # Salva PDF
        cpf_clean   = cpf.replace('.', '').replace('-', '')
        pdf_filename= f"result_{cpf_clean}.pdf"
        output_folder = os.path.join(app.root_path, "static", "output")
        os.makedirs(output_folder, exist_ok=True)
        pdf_path    = os.path.join(output_folder, pdf_filename)
        with open(pdf_path, 'wb') as f:
            f.write(pdf)  # type: ignore

        # Envio WhatsApp
        analyzed_link = url_for('static', filename=f"output/{pdf_filename}", _external=True)
        original_link = url_for('static', filename=f"uploads/{filename}", _external=True)
        send_pdf_whatsapp(doctor_name, name, analyzed_link, original_link)

        # Atualiza pacote
        update_package_usage(user.id, get_package_info(user.id)['used'] + 1)

        return render_template('result.html',
                               diagnostic_text=diagnostic,
                               prescription_text=prescription)

    return render_template('upload.html')

# ==============================================
# DOWNLOAD DO PDF GERADO
# ==============================================
@app.route('/download_pdf')
def download_pdf():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    diagnostic   = session.get('diagnostic_text', '')
    prescription = session.get('prescription_text', '')
    doctor_name  = session.get('doctor_name', '')
    patient_info = session.get('patient_info', '')

    html = render_template(
        "result_pdf.html",
        diagnostic_text=diagnostic,
        prescription_text=prescription,
        doctor_name=doctor_name,
        patient_info=patient_info,
        logo_path=os.path.join(app.root_path, 'static', 'images', 'logo.png')
    )
    pdf = weasyprint.HTML(string=html,
                          base_url=os.path.join(app.root_path, 'static')).write_pdf()

    response = make_response(pdf)
    response.headers['Content-Type']        = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=prescription.pdf'
    return response


# ==============================================
# PATIENT MANAGEMENT
# ==============================================
@app.route('/catalog')
def catalog():
    patients = Patient.query.order_by(Patient.name).all()
    doctors  = Doctor.query.order_by(Doctor.name).all()
    return render_template('catalog.html', patients=patients, doctors=doctors)

@app.route('/edit_patient/<int:patient_id>', methods=['GET', 'POST'])
def edit_patient(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient(patient_id)
    if not patient:
        return "Patient not found", 404

    doctors = get_doctors()
    if request.method == 'POST':
        update_patient(
            patient_id,
            request.form['name'],
            request.form['age'],
            request.form['cpf'],
            request.form['gender'],
            request.form['phone'],
            int(request.form['doctor']),
            request.form.get('prescription', '').strip()
        )
        return redirect(url_for('catalog'))

    return render_template('edit_patient.html', patient=patient, doctors=doctors)

@app.route('/patient_result/<int:patient_id>')
def patient_result(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    patient = get_patient(patient_id)
    if not patient:
        return render_template('result.html',
                               diagnostic_text="Paciente não encontrado.",
                               prescription_text="")

    consultations = get_consults(patient_id)
    if consultations:
        latest = consultations[-1]
        parts = latest.split("Prescrição:\n")
        diagnostic_text  = parts[0].strip()
        prescription_text = parts[1].strip() if len(parts) > 1 else ""
    else:
        diagnostic_text  = "Nenhuma consulta registrada."
        prescription_text= ""

    if not prescription_text:
        prescription_text = patient.get("prescription", "")

    return render_template(
        'result.html',
        diagnostic_text=diagnostic_text,
        prescription_text=prescription_text,
        doctor_name=patient.get("doctor_name", "Desconhecido")
    )

@app.route('/delete_patient/<int:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    user = get_logged_user()

    if not user:
        return redirect(url_for('login'))

    patient = Patient.query.get_or_404(patient_id)
    
    if patient.doctor_id != user.id:
        abort(403)

    db.session.delete(patient)
    db.session.commit()

    return redirect(url_for('catalog'))


@app.route('/toggle_patient_status/<int:patient_id>/<new_status>')
def toggle_patient_status(patient_id, new_status):
    patient = Patient.query.get_or_404(patient_id)
    patient.status = new_status
    db.session.commit()
    return redirect(url_for('catalog'))

@app.route('/api/add_patient', methods=['POST'])
def api_add_patient():
    user = get_logged_user()
    if not user:
        return jsonify(success=False, error='Unauthorized'), 403

    data = request.get_json() or {}
    name = data.get("name", "").strip()
    age_raw = data.get("age", "").strip()
    cpf = data.get("cpf", "").strip()
    gender = data.get("gender", "").strip()
    phone = data.get("phone", "").strip()
    prescription = data.get("prescription", "").strip()

    if not (name and age_raw):
        return jsonify(success=False, error='Preencha todos os campos obrigatórios'), 400

    try:
        age = int(age_raw)
    except ValueError:
        return jsonify(success=False, error='Idade inválida'), 400

    patient = Patient(
        name=name,
        age=age,
        cpf=cpf or None,
        gender=gender or None,
        phone=phone or None,
        doctor_id=user.id,
        prescription=prescription or None
    )

    db.session.add(patient)
    db.session.commit()

    return jsonify(success=True, patient_id=patient.id), 201

@app.route('/api/patients')
def api_get_patients():
    user = get_logged_user()
    if not user:
        return jsonify([]) 

    patients = Patient.query.filter_by(doctor_id=user.id).all()
    result = [{
        'id': patient.id,
        'name': patient.name,
        'phone': patient.phone,
        'doctor_id': patient.doctor_id,
        'doctor_name': patient.doctor.name,
        'status': patient.status
    } for patient in patients]
    return jsonify(result)

# ==============================================
# PRODUCT MANAGEMENT
# ==============================================
@app.route('/products')
def products():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    produtos           = get_products()
    category_filter    = request.args.get('category', '')
    via_filter         = request.args.get('application_route', '')
    status_filter      = request.args.get('status', '')
    stock_filter       = request.args.get('stock_filter', 'all')
    search             = request.args.get('search', '').lower()

    def keep(p):
        return (
            (not category_filter or p.get('category') == category_filter) and
            (not via_filter      or p.get('application_route') == via_filter) and
            (not status_filter   or p.get('status') == status_filter) and
            (stock_filter != 'in_stock' or p.get('quantity', 0) > 0) and
            (stock_filter != 'min_stock' or p.get('quantity', 0) <= p.get('min_stock', 0)) and
            (not search or search in p.get('name', '').lower())
        )

    filtered = [p for p in produtos if keep(p)]
    categories         = sorted({p.get('category','')         for p in produtos if p.get('category')})
    application_routes = sorted({p.get('application_route','') for p in produtos if p.get('application_route')})

    return render_template('products.html',
                           products=filtered,
                           categories=categories,
                           application_routes=application_routes)

@app.route('/add_product', methods=['POST'])
def add_product_route():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    name           = request.form.get('name', '').strip()
    quantity       = int(request.form.get('quantity', 0))
    purchase_price = float(request.form.get('purchase_price', 0))
    sale_price     = float(request.form.get('sale_price', 0))

    if not name:
        return "Product name is required.", 400

    add_product(name, purchase_price, sale_price, quantity)
    return redirect(url_for('products'))

@app.route('/toggle_product_status/<int:product_id>/<new_status>')
def toggle_product_status(product_id, new_status):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    update_product_status(product_id, new_status)
    return redirect(url_for('products'))

@app.route('/stock_view/<int:product_id>')
def stock_view(product_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    product = next((p for p in get_products() if p['id'] == product_id), None)
    if not product:
        return "Product not found", 404
    return render_template('stock_view.html', product=product)

@app.route('/stock_edit/<int:product_id>', methods=['GET','POST'])
def stock_edit(product_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    produtos = get_products()
    product  = next((p for p in produtos if p['id'] == product_id), None)
    if not product:
        return "Product not found", 404

    if request.method == 'POST':
        product['code']           = request.form['code']
        product['name']           = request.form['name']
        product['quantity']       = int(request.form['quantity'])
        product['purchase_price'] = float(request.form['purchase_price'])
        product['sale_price']     = float(request.form['sale_price'])
        save_products(produtos)
        return redirect(url_for('products'))

    return render_template('stock_edit.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    produtos = [p for p in get_products() if p['id'] != product_id]
    save_products(produtos)
    return redirect(url_for('products'))


# ==============================================
# DOCTOR MANAGEMENT
# ==============================================
@app.route("/doctors")
def doctors():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    doctors = get_doctors()
    return render_template("doctors.html", doctors=doctors)

@app.route("/update_doctor/<int:doctor_id>", methods=["POST"])
def update_doctor_route(doctor_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    update_doctor(doctor_id, request.form["name"], request.form["phone"])
    return redirect(url_for("doctors"))

@app.route('/add_doctor', methods=['POST'])
def add_doctor_route():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    name = request.form.get('name', '').strip()
    phone = request.form.get('phone', '').strip()

    if not name:
        flash("Nome do médico é obrigatório.", "warning")
        return redirect(url_for('doctors'))

    new_doc = Doctor(name=name, phone=phone)
    db.session.add(new_doc)
    db.session.commit()

    flash("Médico adicionado com sucesso.", "success")
    return redirect(url_for('doctors'))


@app.route('/delete_doctor/<int:doctor_id>', methods=['POST'])
def delete_doctor(doctor_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    doctor = Doctor.query.get_or_404(doctor_id)
    db.session.delete(doctor)
    db.session.commit()

    flash("Médico removido com sucesso.", "info")
    return redirect(url_for('doctors'))

# ==============================================
# PAYMENT AND WEBHOOK
# ==============================================
@app.route('/purchase', methods=['GET', 'POST'])
def purchase():
    user = get_logged_user()
    if request.method == 'POST':
        pacote = request.form.get('package', '')
        valor  = {'50': 120, '150': 300, '500': 950}.get(pacote)
        if not valor:
            flash('Selecione um pacote válido.', 'warning')
            return redirect(url_for('purchase'))
        link = generate_payment_link(pacote, valor)
        return redirect(link or url_for('pagamento_falha'))
    return render_template('purchase.html')

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid payload'}), 400
    print("[Webhook received]", data)
    return jsonify({'status': 'received'}), 200

# ==============================================
# QUOTE SYSTEM
# ==============================================
@app.route('/quotes/create', methods=['GET', 'POST'])
def create_quote():
    if request.method == 'POST':
        suppliers = Supplier.query.all()
        title     = request.form['title']
        items     = [i.strip() for i in request.form['items'].split('\n') if i.strip()]
        supplier_ids = request.form.getlist('supplier_ids')
        quote = Quote(title=title, items=json.dumps(items), suppliers=json.dumps(supplier_ids))
        db.session.add(quote)
        db.session.commit()
        # notifications via WhatsApp/email...
        return redirect(url_for('quote_success', quote_id=quote.id))

    suppliers = Supplier.query.all()
    return render_template('create_quote.html', suppliers=suppliers)

@app.route('/quotes/success/<int:quote_id>')
def quote_success(quote_id):
    return f'Cotação criada com sucesso! ID: {quote_id}'

@app.route('/quote/<int:quote_id>/supplier/<int:supplier_id>', methods=['GET','POST'])
def respond_quote(quote_id, supplier_id):
    quote    = Quote.query.get_or_404(quote_id)
    suppliers= json.loads(quote.suppliers)
    if supplier_id not in map(int, suppliers):
        return "Forbidden", 403
    if request.method == 'POST':
        answers = []
        items   = json.loads(quote.items)
        for idx, _ in enumerate(items):
            price    = request.form.get(f'price_{idx}')
            deadline = request.form.get(f'deadline_{idx}')
            answers.append({'price': price, 'deadline': deadline})
        response = QuoteResponse(
            quote_id=quote.id,
            supplier_id=supplier_id,
            answers=json.dumps(answers)
        )
        db.session.add(response)
        db.session.commit()
        return "Cotação enviada com sucesso."
    return render_template('quote_response.html', quote=quote)

@app.route('/quotes/<int:quote_id>/results')
def quote_results(quote_id):
    quote     = Quote.query.get_or_404(quote_id)
    items     = json.loads(quote.items)
    responses = QuoteResponse.query.filter_by(quote_id=quote.id).all()
    # compute best per item...
    return render_template('quote_results.html', quote=quote, items=items, responses=responses)

@app.route('/quotes')
def quote_index():
    quotes = Quote.query.all()
    return render_template('quote_index.html', quotes=quotes)

def get_quiz_chart_data(doctor_id):
    today = datetime.utcnow().date()
    last_7_days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    data = []

    for day in last_7_days:
        count = QuizResult.query.filter(
            func.date(QuizResult.date) == day,
            QuizResult.doctor_id == doctor_id
        ).count()
        data.append({
            "date": day.strftime("%d/%m"),
            "count": count,
            "media": count 
        })

    return data

# ==============================================
# SUPPLIER MANAGEMENT
# ==============================================
@app.route('/suppliers')
def suppliers():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    suppliers = Supplier.query.order_by(Supplier.name).all()
    return render_template('suppliers.html', suppliers=suppliers)

@app.route('/add_supplier', methods=['POST'])
def add_supplier():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    name  = request.form.get('name','').strip()
    phone = request.form.get('phone','').strip()
    email = request.form.get('email','').strip()

    if not name:
        flash("Nome do fornecedor é obrigatório.", "warning")
        return redirect(url_for('suppliers'))

    new_sup = Supplier(name=name, phone=phone or None, email=email or None)
    db.session.add(new_sup)
    db.session.commit()

    flash("Fornecedor cadastrado com sucesso.", "success")
    return redirect(url_for('suppliers'))

@app.route('/update_supplier/<int:supplier_id>', methods=['POST'])
def update_supplier(supplier_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    sup = Supplier.query.get_or_404(supplier_id)
    sup.name  = request.form.get('name','').strip() or sup.name
    sup.phone = request.form.get('phone','').strip() or sup.phone
    sup.email = request.form.get('email','').strip() or sup.email
    db.session.commit()

    flash("Fornecedor atualizado com sucesso.", "success")
    return redirect(url_for('suppliers'))

@app.route('/delete_supplier/<int:supplier_id>', methods=['POST'])
def delete_supplier(supplier_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    sup = Supplier.query.get_or_404(supplier_id)
    db.session.delete(sup)
    db.session.commit()

    flash("Fornecedor removido.", "info")
    return redirect(url_for('suppliers'))


# ==============================================
# GOOGLE CALENDAR
# ==============================================
@app.route('/agenda')
def agenda():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('agenda.html')

@app.route('/schedule_consultation', methods=['GET','POST'])
def schedule_consultation():
    if request.method == 'POST':
        name, cpf, phone = request.form['name'], request.form['cpf'], request.form['phone']
        date, time       = request.form['date'], request.form['time']
        start = f"{date}T{time}:00"
        hh, mm = map(int, time.split(':'))
        end   = f"{date}T{hh+1:02d}:{mm:02d}:00"
        creds = service_account.Credentials.from_service_account_file(
            os.getenv('GOOGLE_CREDS_JSON'),
            scopes=['https://www.googleapis.com/auth/calendar']
        )
        svc = build('calendar','v3',credentials=creds)
        event = {
            "summary": f"Consulta com {name}",
            "description": f"CPF: {cpf}\nTel: {phone}",
            "start": {"dateTime": start, "timeZone": "America/Sao_Paulo"},
            "end":   {"dateTime": end,   "timeZone": "America/Sao_Paulo"}
        }
        svc.events().insert(calendarId='primary', body=event).execute()
        return render_template('schedule_success.html', name=name)
    return render_template('schedule_consultation.html')

@app.route('/api/add_consult', methods=['POST'])
def api_add_consult():
    # 1) busca o user e garante que não seja None
    user = get_logged_user()
    if user is None:
        return jsonify(success=False, error='UNAUTHORIZED'), 403

    # 2) valida o JSON
    data = request.get_json() or {}
    patient_id = data.get('patient_id')
    if not patient_id:
        return jsonify(success=False, error='Missing patient_id'), 400
    try:
        pid = int(patient_id)
    except ValueError:
        return jsonify(success=False, error='Invalid patient_id'), 400

    # 3) garante que o paciente exista
    patient = Patient.query.get(pid)
    if patient is None:
        return jsonify(success=False, error='Patient not found'), 404

    # 4) cria a consulta
    consult = Consult(
        patient_id=patient.id,
        doctor_id = user.id,
        notes     = data.get('notes', '').strip() or None
    )
    db.session.add(consult)
    db.session.commit()

    # 5) devolve o ID da nova consulta
    return jsonify(success=True, consult_id=consult.id), 201


@app.route('/submit_patient_consultation', methods=['POST'])
def submit_patient_consultation():
    name    = request.form.get('name','').strip()
    cpf     = request.form.get('cpf','').strip()
    phone   = request.form.get('phone','').strip()
    start   = request.form.get('start','')
    if not start:
        return "Data de início ausente", 400
    try:
        date_part, time_part = start.split('T')
        day, month, year     = date_part.split('/')
        date_iso             = f"{year}-{month}-{day}"
        start_iso            = f"{date_iso}T{time_part}:00"
        hh, mm               = map(int, time_part.split(':'))
        end_iso              = f"{date_iso}T{hh+1:02d}:{mm:02d}:00"
    except:
        return "Formato inválido", 400

    try:
        create_user_event(
            summary=f"Consulta Agendada: {name}",
            start_datetime=start_iso,
            end_datetime=end_iso,
            description=f"CPF: {cpf}\nTel: {phone}"
        )
        return redirect(url_for('hero'))
    except Exception as e:
        print("Erro:", e)
        return "Erro ao agendar", 500

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
        "client_secret.json",
        scopes=["https://www.googleapis.com/auth/calendar"],
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True),
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

    return redirect(url_for("agenda"))

def create_user_event(
    summary: str,
    start_datetime: str,
    end_datetime: str,
    description: str
) -> None:
    info = session.get("credentials")
    if not info:
        raise Exception("Usuário não autenticado no Google")

    # Usa o Credentials da google.oauth2.credentials
    creds = Credentials.from_authorized_user_info(info)  # type: ignore[attr-defined]
    service = build("calendar", "v3", credentials=creds)

    event = {
        "summary": summary,
        "description": description,
        "start": {"dateTime": start_datetime, "timeZone": "America/Sao_Paulo"},
        "end":   {"dateTime": end_datetime,   "timeZone": "America/Sao_Paulo"},
    }

    service.events().insert(calendarId='primary', body=event).execute()

# ==============================================
# QUIZ
# ==============================================
@app.route('/quiz')
def quiz():
    return render_template('quiz.html')

@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    data      = request.get_json() or {}
    name      = data.get('nome', 'Anônimo')
    age       = data.get('idade', '0')
    # Pega o admin_id da query string ou do usuário logado
    doctor_id = request.args.get('admin', type=int) or session.get('user_id')

    # ==== Extrai todas as respostas textuais e de checkbox ====
    respostas = {
        'nervosismo':       data.get('nervosismo'),
        'preocupacao':      data.get('preocupacao'),
        'interesse':        data.get('interesse'),
        'depressao':        data.get('depressao'),
        'estresse':         data.get('estresse'),
        'hora_extra':       data.get('hora_extra'),
        'sono':             data.get('sono'),
        'atividade_fisica': data.get('atividade_fisica'),
        'fatores':          data.get('fatores', []),
        'motivacao':        data.get('motivacao'),
        'pronto_socorro':   data.get('pronto_socorro'),
        'relacionamentos':  data.get('relacionamentos'),
        'hobbies':          data.get('hobbies'),
    }

    # ==== Cálculo dos escores ====
    ansiedadeScore = 0
    depressaoScore = 0
    estresseScore  = 0
    qualidadeScore = 0

    # Ansiedade
    if respostas['nervosismo'] == "Quase todos os dias": ansiedadeScore += 3
    elif respostas['nervosismo'] == "Alguns dias": ansiedadeScore += 2
    elif respostas['nervosismo'] == "Poucos dias": ansiedadeScore += 1

    if respostas['preocupacao'] == "Quase todos os dias": ansiedadeScore += 3
    elif respostas['preocupacao'] == "Alguns dias": ansiedadeScore += 2
    elif respostas['preocupacao'] == "Poucos dias": ansiedadeScore += 1

    # Depressão
    if respostas['interesse'] == "Quase todos os dias": depressaoScore += 3
    elif respostas['interesse'] == "Alguns dias": depressaoScore += 2
    elif respostas['interesse'] == "Poucos dias": depressaoScore += 1

    if respostas['depressao'] == "Quase todos os dias": depressaoScore += 3
    elif respostas['depressao'] == "Alguns dias": depressaoScore += 2
    elif respostas['depressao'] == "Poucos dias": depressaoScore += 1

    # Estresse
    if respostas['estresse'] == "Quase todos os dias": estresseScore += 3
    elif respostas['estresse'] == "Alguns dias": estresseScore += 2
    elif respostas['estresse'] == "Poucos dias": estresseScore += 1

    if respostas['hora_extra'] == "Todos os dias da semana": estresseScore += 3
    elif respostas['hora_extra'] == "De 3 a 4 dias da semana": estresseScore += 2
    elif respostas['hora_extra'] == "De 1 a 2 dias da semana": estresseScore += 1

    # Qualidade de vida (sono + atividade + relacionamentos)
    if respostas['sono'] == "Muito ruim": qualidadeScore += 3
    elif respostas['sono'] == "Ruim": qualidadeScore += 2
    elif respostas['sono'] == "Regular": qualidadeScore += 1

    if respostas['atividade_fisica'] == "Nunca": qualidadeScore += 2
    elif respostas['atividade_fisica'] == "Raramente": qualidadeScore += 1

    if respostas['relacionamentos'] == "Muito ruim": qualidadeScore += 3
    elif respostas['relacionamentos'] == "Ruim": qualidadeScore += 2
    elif respostas['relacionamentos'] == "Regular": qualidadeScore += 1

    # Bônus por fatores
    fatores = respostas['fatores']
    if isinstance(fatores, list):
        if "Ansiedade" in fatores:     ansiedadeScore += 1
        if "Depressão" in fatores:     depressaoScore += 1
        if "Estresse" in fatores:      estresseScore += 1

    # ==== Função de classificação ====
    def getClassificacao(score: int, maxScore: int):
        pct = (score / maxScore) * 100
        if pct <= 25: return {"nivel": "BAIXO",       "cor": "#10b981"}
        if pct <= 50: return {"nivel": "NORMAL/LEVE", "cor": "#f59e0b"}
        if pct <= 75: return {"nivel": "MODERADO",    "cor": "#f97316"}
        return {"nivel": "ALTO",        "cor": "#ef4444"}

    ansiedadeClass = getClassificacao(ansiedadeScore, 8)
    depressaoClass = getClassificacao(depressaoScore, 8)
    estresseClass  = getClassificacao(estresseScore, 8)
    qualidadeClass = getClassificacao(qualidadeScore, 8)

    totalScore     = ansiedadeScore + depressaoScore + estresseScore + qualidadeScore
    riscoClass     = getClassificacao(totalScore, 32)

    # ==== Monta texto de recomendação ====
    if   riscoClass['nivel'] == "BAIXO":
        recomendacao = "Sua saúde mental aparenta estar preservada. Continue cuidando de si!"
    elif riscoClass['nivel'] == "NORMAL/LEVE":
        recomendacao = "Há alguns sinais que merecem atenção. Considere práticas de autocuidado."
    elif riscoClass['nivel'] == "MODERADO":
        recomendacao = "Identificamos sinais importantes. Recomendamos acompanhamento psicológico."
    else:
        recomendacao = "Indica necessidade urgente de suporte. Busque ajuda profissional."

    # ==== Salva o paciente genérico (somente para retornar o ID) ====
    pid = add_patient(name, age, "", "", "", doctor_id, f"Resultado do quiz: {riscoClass['nivel']}")

    # ==== Cria o registro completo no quiz_results ====
    novo = QuizResult(
        name            = name,
        age             = age,
        date            = datetime.utcnow(),
        ansiedade       = ansiedadeClass['nivel'],
        depressao       = depressaoClass['nivel'],
        estresse        = estresseClass['nivel'],
        qualidade       = qualidadeClass['nivel'],
        risco           = riscoClass['nivel'],
        nervosismo      = respostas['nervosismo'],
        preocupacao     = respostas['preocupacao'],
        interesse       = respostas['interesse'],
        sono            = respostas['sono'],
        atividade_fisica= respostas['atividade_fisica'],
        fatores         = respostas['fatores'],        
        motivacao       = respostas['motivacao'],
        hora_extra      = respostas['hora_extra'],
        pronto_socorro  = respostas['pronto_socorro'],
        relacionamentos = respostas['relacionamentos'],
        hobbies         = respostas['hobbies'],
        recomendacao    = recomendacao,
        doctor_id       = doctor_id
    )
    db.session.add(novo)
    db.session.commit()

    return jsonify(status='ok', patient_id=pid)

@app.route('/selfevaluation')
def selfevaluation():
    doctor_id = session.get('user_id')
    patients  = get_patients()
    quiz_patients = [
        p for p in patients
        if p.doctor_id==doctor_id and p.prescription.startswith("Resultado do quiz")
    ]
    from collections import Counter
    counts = Counter()
    for p in quiz_patients:
        d = p.created_at.strftime('%d/%m')
        counts[d] += 1
    labels = list(counts.keys())
    values = list(counts.values())
    return render_template('selfevaluation.html', labels=labels, values=values)

@app.route("/quiz-results")
def quiz_results():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    results_raw = QuizResult.query.filter_by(doctor_id=user.id)

    def get_color(nivel):
        return {
            "BAIXO": "#10b981",
            "NORMAL/LEVE": "#f59e0b",
            "MODERADO": "#f97316",
            "ALTO": "#ef4444",
            "RUIM": "#f97316",
            "MUITO RUIM": "#ef4444",
            "BOA": "#10b981",
            "REGULAR": "#f59e0b",
        }.get(nivel, "#000")

    results = []
    for r in results_raw:
        results.append({
            "id": r.id,
            "nome": r.name,
            "idade": r.age,
            "data": r.date.strftime("%d/%m/%Y"),
            "ansiedade": r.ansiedade,
            "depressao": r.depressao,
            "estresse": r.estresse,
            "qualidade": r.qualidade,
            "risco": r.risco,
            "ansiedade_cor": get_color(r.ansiedade),
            "depressao_cor": get_color(r.depressao),
            "estresse_cor": get_color(r.estresse),
            "qualidade_cor": get_color(r.qualidade),
            "risco_cor": get_color(r.risco)
        })

    return render_template("quiz_results.html", results=results, user=user)

@app.route('/quiz-patient/<int:patient_id>')
def quiz_patient(patient_id):
    result = QuizResult.query.get_or_404(patient_id)

    user = get_logged_user()
    if not user or result.doctor_id != user.id:
        abort(403)

    # Paciente com todos os campos relevantes para a página
    patient = {
        "nome": result.name,
        "idade": result.age,
        "data": result.date.strftime('%d/%m/%Y') if result.date else "",
        "ansiedade": result.ansiedade,
        "depressao": result.depressao,
        "estresse": result.estresse,
        "qualidade": result.qualidade,
        "risco": result.risco,
        "nervosismo": result.nervosismo,
        "preocupacao": result.preocupacao,
        "interesse": result.interesse,
        "sono": result.sono,
        "atividade_fisica": result.atividade_fisica,
        "fatores": result.fatores,
        "motivacao": result.motivacao,
        "hora_extra": result.hora_extra,
        "pronto_socorro": result.pronto_socorro,
        "relacionamentos": result.relacionamentos,
        "hobbies": result.hobbies,
        "recomendacao": result.recomendacao
    }

    # Perguntas do questionário
    questions = {
        "nome": "Qual seu nome?",
        "idade": "Qual sua idade?",
        "nervosismo": "Nas últimas 2 semanas, com que frequência você se sentiu nervoso(a), ansioso(a) ou muito tenso(a)?",
        "preocupacao": "Nas últimas 2 semanas, você não foi capaz de controlar a preocupação?",
        "interesse": "Nas últimas 2 semanas, você teve pouco interesse ou prazer em fazer as coisas?",
        "depressao": "Nas últimas 2 semanas, você se sentiu desanimado(a), deprimido(a) ou sem esperança?",
        "estresse": "Considerando as últimas 2 semanas, o quanto você sentiu que estava estressado(a)?",
        "hora_extra": "Considerando uma semana de trabalho normal, quantos dias você normalmente precisa trabalhar a mais do que a sua carga horária habitual e/ou fazer hora extra?",
        "sono": "Como você classificaria sua qualidade do sono nas últimas 2 semanas?",
        "atividade_fisica": "Com que frequência você pratica atividade física?",
        "fatores": "Quando você pensa na sua saúde mental e qualidade de vida, quais os fatores que mais impactam?",
        "motivacao": "Com relação à questão apontada, em qual estágio de motivação você considera que está para tentar resolver a questão?",
        "pronto_socorro": "Nos últimos 3 meses, quantas vezes você utilizou o pronto socorro?",
        "relacionamentos": "Como você avalia seu relacionamento com família e amigos?",
        "hobbies": "Você tem algum hobby ou atividade que lhe dá prazer?"
    }

    return render_template('quiz_patient.html', patient=patient, questions=questions)

@app.route('/delete_quiz_result', methods=['GET','POST'])
def delete_quiz_result():
    # obtém o ID do resultado pela query string
    patient_id = request.args.get('patient_id', type=int)
    # busca o registro ou 404
    result = QuizResult.query.get_or_404(patient_id)
    
    # deleta e confirma no banco
    db.session.delete(result)
    db.session.commit()
    
    # feedback opcional ao usuário
    flash('Resultado de autoavaliação deletado com sucesso.', 'success')
    # redireciona de volta para a lista de resultados
    return redirect(url_for('quiz_results'))


# ==============================================
# APPLICATION EXECUTION
# ==============================================
if __name__ == '__main__':
    app.run(debug=True)
