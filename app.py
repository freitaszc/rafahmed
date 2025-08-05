import os
import json
import secrets
import uuid
from sqlalchemy import func, cast, Date
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
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
    send_file,
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
    get_suppliers_by_user,
    add_supplier_db,
    update_supplier_db,
    delete_supplier_db,
    update_product,
    get_product_by_id,
    get_products,
    save_products,
    is_package_available,
    update_package_usage,
    get_package_info,
    get_user_by_id,
    get_user_by_username,
    create_user,
    get_company_by_id,
    get_company_by_access_code,
    create_company,
    add_supplier_record,
    get_suppliers,
    add_quote,
    get_quotes,
    add_quote_response,
    get_responses_by_quote,
    add_doctor,
    get_doctors,
    get_doctor_by_id,
    add_patient,
    get_patient_by_id,
    get_patients_by_doctor,
    update_patient,
    delete_patient_record,
    add_consult,
    get_consults_by_patient,
    update_prescription_in_consult,
    add_quiz_result,
    get_quiz_results_by_doctor,
    get_quiz_results_by_doctor_and_range,
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

# Define caminho absoluto da pasta 'instance'
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
os.makedirs(base_dir, exist_ok=True)

# Caminho fixo para o banco de dados
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

def create_tables():
    db.create_all()

PUBLIC_ENDPOINTS = {
    'hero',
    'about',
    'privacy_policy',
    'register',
    'login',
    'static'
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_logged_user()
        if not user:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

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
        username     = escape(request.form.get('username', '').strip())
        email        = escape(request.form.get('email', '').strip().lower())
        password     = request.form.get('password', '')
        confirm      = request.form.get('confirm_password', '')
        company_code = escape(request.form.get('company_code', '').strip().upper())

        # Validação de e-mail
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            flash('E-mail inválido.', 'warning')
            return redirect(url_for('register'))

        # Verifica se já existe usuário com mesmo e-mail ou username
        exists_email = User.query.filter_by(email=email).first()
        exists_user  = User.query.filter_by(username=username).first()
        if exists_email or exists_user:
            flash('E-mail ou usuário já cadastrado.', 'warning')
            return redirect(url_for('register'))

        # Validação de senha
        if len(password) < 8:
            flash('A senha deve ter pelo menos 8 caracteres.', 'warning')
            return redirect(url_for('register'))
        if not re.search(r'[A-Za-z]', password):
            flash('A senha deve conter letras.', 'warning')
            return redirect(url_for('register'))
        if not re.search(r'\d', password):
            flash('A senha deve conter números.', 'warning')
            return redirect(url_for('register'))
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('A senha deve conter pelo menos um símbolo especial.', 'warning')
            return redirect(url_for('register'))
        if password != confirm:
            flash('As senhas não coincidem.', 'warning')
            return redirect(url_for('register'))

        # Validação do código da empresa (opcional)
        company = None
        if company_code:
            company = Company.query.filter_by(access_code=company_code).first()
            if not company:
                flash('Código da empresa inválido.', 'danger')
                return redirect(url_for('register'))

        # Cria o usuário
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

    pkg = get_package_info(user.id)
    if pkg['total'] - pkg['used'] <= 0:
        return redirect(url_for('purchase'))

    return render_template('upload.html')


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


@app.route('/admin/companies', methods=['GET', 'POST'])
def admin_companies():
    user = get_logged_user()
    if not user or user.username.lower() != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))

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

    companies = Company.query.order_by(Company.name).all()
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

    name = request.form.get('company_name', '').strip()
    code = request.form.get('access_code', '').strip()
    if not name or not code:
        flash('Nome e código são obrigatórios.', 'warning')
        return redirect(url_for('admin_companies'))

    if Company.query.filter_by(access_code=code).first():
        flash(f'Já existe empresa com código {code}.', 'warning')
        return redirect(url_for('admin_companies'))

    db.session.add(Company(name=name, access_code=code))
    db.session.commit()
    flash(f'Empresa "{name}" cadastrada.', 'success')
    return redirect(url_for('admin_companies'))


@app.route('/delete_company/<int:company_id>', methods=['POST'])
def delete_company(company_id):
    user = get_logged_user()
    if not user or user.username.lower() != 'admin':
        abort(403)

    company = Company.query.get_or_404(company_id)
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

    used = getattr(user, 'packets_used', 0) or 0
    remaining = getattr(user, 'packets_remaining', 50) or 50

    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=6)

    quizzes = QuizResult.query.filter_by(doctor_id=user.id).all()

    date_counts = { (week_ago + timedelta(days=i)).strftime('%d/%m'): 0 for i in range(7) }
    dep_stats = defaultdict(lambda: {'sum_score': 0, 'num': 0})

    score_map = {
        'BAIXO': 1,
        'NORMAL/LEVE': 2,
        'MODERADO': 3,
        'ALTO': 4
    }
    inv_map = {v: k for k, v in score_map.items()}

    for q in quizzes:
        # Converte string para datetime se necessário
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
            'date': key,
            'count': cnt,
            'media': mavg,
            'dep_avg': round(avg_score, 2),
            'dep_class': dep_class
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

    # Verifica pacote disponível
    if not is_package_available(user.id):
        flash('Seu pacote de análises acabou. Por favor, adquira mais para continuar.', 'warning')
        return redirect(url_for('purchase'))

    if request.method == 'POST':
        # === Inserção Manual ===
        if 'manual_entry' in request.form:
            name        = request.form['name'].strip()
            age         = int(request.form['age'])
            cpf         = request.form['cpf'].strip()
            gender      = request.form['gender'].strip()
            phone       = request.form['phone'].strip()
            doctor_name = request.form['doctor'].strip()
            manual_text = request.form['lab_results'].strip()

            result = analyze_pdf(manual_text, manual=True)
            if not isinstance(result, (list, tuple)) or len(result) != 2:
                flash('Erro ao processar análise manual.', 'danger')
                return render_template('upload.html')
            diagnostic, prescription = result

        else:
            # === Upload de arquivo PDF ===
            pdf_file = request.files.get('pdf_file')
            if not pdf_file or not pdf_file.filename:
                return render_template('upload.html', error='Por favor, selecione um arquivo PDF.')

            uploads_folder = os.path.join(app.root_path, "static", "uploads")
            os.makedirs(uploads_folder, exist_ok=True)
            filename    = pdf_file.filename
            upload_path = os.path.join(uploads_folder, filename)
            pdf_file.save(upload_path)

            result = analyze_pdf(upload_path)
            if not isinstance(result, (list, tuple)) or len(result) != 8:
                flash('Erro ao processar o PDF.', 'danger')
                return render_template('upload.html')

            diagnostic, prescription, name, gender, age, cpf, phone, doctor_name = result

            patient = add_patient(
                name=name,
                age=int(age),
                cpf=cpf or None,
                gender=gender or None,
                phone=phone or None,
                doctor_id=user.id, 
                prescription=prescription
            )


        # Agenda no Google Calendar
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

        # Prepara sessão e gera PDF
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
            logo_path=os.path.join(app.root_path, 'static', 'images', 'logo.png')
        )
        pdf_bytes = weasyprint.HTML(string=html, base_url=os.path.join(app.root_path, 'static')).write_pdf()
        if not pdf_bytes:
            flash('Erro ao gerar o PDF.', 'danger')
            return render_template('upload.html')

        cpf_clean    = cpf.replace('.', '').replace('-', '')
        pdf_filename = f"result_{cpf_clean}.pdf"
        output_folder= os.path.join(app.root_path, "static", "output")
        os.makedirs(output_folder, exist_ok=True)
        pdf_path     = os.path.join(output_folder, pdf_filename)
        with open(pdf_path, 'wb') as f:
            f.write(pdf_bytes)

        # Envia por WhatsApp
        pdf_link = url_for('static', filename=f"output/{pdf_filename}", _external=True)
        send_pdf_whatsapp(
            doctor_name=doctor_name,
            patient_name=name,
            analyzed_pdf_link=pdf_link,
            original_pdf_link=(None if 'manual_entry' in request.form else url_for('static', filename=f"uploads/{filename}", _external=True))
        )

        # Atualiza uso de pacote
        usage = get_package_info(user.id)['used'] + 1
        update_package_usage(user.id, usage)

        return render_template('result.html',
                               diagnostic_text=diagnostic,
                               prescription_text=prescription)

    return render_template('upload.html')

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

@app.route('/agenda')
@login_required
def agenda():
    return render_template('agenda.html')

@app.route('/doctors')
@login_required
def doctors():
    return render_template('doctors.html')

@app.route('/add_doctor', methods=['POST'])
@login_required
def add_doctor_route():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    name = request.form.get('name', '').strip()
    phone = request.form.get('phone', '').strip()
    if not name:
        flash('Nome e CRM são obrigatórios.', 'warning')
        return redirect(url_for('upload'))
    add_doctor(name=name, phone=phone)
    flash('Médico adicionado com sucesso.', 'success')
    return redirect(url_for('upload'))

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
    # Busque o produto do banco pelo ID (ajuste conforme seu ORM/banco)
    product = get_product_by_id(product_id)
    if not product:
        return "Produto não encontrado", 404
    return render_template('product_result.html', product=product)


# ==============================================
# DOWNLOAD DO PDF GERADO
# ==============================================
@app.route('/download_pdf/<int:patient_id>')
def download_pdf(patient_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))
    patient = get_patient_by_id(patient_id)
    if not patient or patient.doctor_id != user.id:
        abort(403)
    # O caminho do PDF pode depender de como você salva. Ajuste para o seu padrão:
    cpf = (patient.cpf or '').replace('.', '').replace('-', '')
    pdf_filename = f"result_{cpf}.pdf"
    pdf_path = os.path.join(app.root_path, "static", "output", pdf_filename)
    if not os.path.exists(pdf_path):
        flash('Arquivo PDF não encontrado.', 'danger')
        return redirect(url_for('patient_info', patient_id=patient_id))
    return send_file(pdf_path, as_attachment=True, download_name='prescription.pdf')

# ==============================================
# PATIENT MANAGEMENT
# ==============================================

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
        abort(404)  # Paciente não existe

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
            name=name,
            age=age,
            cpf=cpf,
            gender=gender,
            phone=phone,
            doctor_id=patient.doctor_id,  # mantém o médico já cadastrado (ou None)
            prescription=prescription,
            status=status
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
        return render_template('result.html',
                               diagnostic_text="Paciente não encontrado.",
                               prescription_text="")

    consults = get_consults_by_patient(patient_id)
    if consults:
        latest = consults[-1].notes
        parts = latest.split("Prescrição:\n", 1) #type:ignore
        diagnostic_text  = parts[0].strip()
        prescription_text = parts[1].strip() if len(parts) > 1 else patient.prescription or ""
    else:
        diagnostic_text  = "Nenhuma consulta registrada."
        prescription_text= patient.prescription or ""

    return render_template(
        'result.html',
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
    # Atualize os campos conforme enviados
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

    # Chama a função importada corretamente
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
        name=patient.name,
        age=patient.age,
        cpf=patient.cpf,
        gender=patient.gender,
        phone=patient.phone,
        doctor_id=patient.doctor_id,  # Use o que está cadastrado!
        prescription=patient.prescription,
        status=new_status
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

    # OBRIGATÓRIO: ASSOCIA O PACIENTE AO USUÁRIO LOGADO
    patient = add_patient(
        name=name,
        age=age,
        cpf=cpf or None,
        gender=gender or None,
        phone=phone or None,
        doctor_id=user.id,  # <-- ESTA LINHA É ESSENCIAL!
        prescription=prescription
    )

    return jsonify(success=True, patient_id=patient.id), 201



@app.route('/api/patients')
def api_get_patients():
    user = get_logged_user()
    if not user:
        return jsonify([])

    patients = Patient.query.order_by(Patient.name).all()
    result = [{
        'id':          p.id,
        'name':        p.name,
        'phone':       p.phone,
        'doctor_id':   p.doctor_id,
        'doctor_name': p.doctor.name,
        'status':      p.status
    } for p in patients]
    return jsonify(result)


# ==============================================
# PRODUCT MANAGEMENT
# ==============================================

@app.route('/products')
@login_required
def products():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    produtos           = get_products(user.id)  # <-- agora filtrando!
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

    # Busca produto só do usuário logado
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
            product_id=product_id,
            doctor_id=user.id,
            name=name,
            code=code,
            purchase_price=purchase_price,
            sale_price=sale_price,
            quantity=quantity
        )
        flash('Produto atualizado com sucesso.', 'success')
        return redirect(url_for('products'))

    return render_template('stock_edit.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    produtos = get_products()
    produtos = [
        p for p in produtos
        if not (p['id'] == product_id and p.get('doctor_id') == user.id)
    ]
    save_products(produtos)
    flash('Produto removido.', 'info')
    return redirect(url_for('products'))

# ==============================================
# SUPPLIERS
# ==============================================

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

@app.route('/create_quote', methods=['GET', 'POST'])
@login_required
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

        # Salva IDs como string separada por vírgula
        suppliers_str = ",".join(supplier_ids)

        # Cria cotação e salva no banco
        quote = Quote(title=title, items=items_raw, suppliers=suppliers_str)
        db.session.add(quote)
        db.session.commit()

        # ENVIO WHATSAPP + EMAIL
        items_list = [i.strip() for i in items_raw.split('\n') if i.strip()]
        items_text = "\n".join([f"• {item}" for item in items_list])

        for s in suppliers:
            if str(s.id) not in supplier_ids:
                continue

            # Link para responder (ajuste se necessário)
            response_url = url_for('respond_quote', quote_id=quote.id, supplier_id=s.id, _external=True)
            # WhatsApp
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
            # E-mail
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
def quote_index():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    quotes = Quote.query.order_by(Quote.created_at.desc()).all()
    suppliers_all = {str(s.id): s.name for s in get_suppliers_by_user(user.id)}

    for quote in quotes:
        if quote.suppliers:
            quote.supplier_list = [suppliers_all.get(sid, f"ID {sid}") for sid in quote.suppliers.split(',') if sid]
        else:
            quote.supplier_list = []
        quote.responses = QuoteResponse.query.filter_by(quote_id=quote.id).all()

    return render_template('quote_index.html', quotes=quotes)

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
def quote_results(quote_id):
    # 1. Busca cotação e respostas do banco
    quote = Quote.query.get_or_404(quote_id)
    responses = QuoteResponse.query.filter_by(quote_id=quote_id).all()
    # 2. Monta lista de fornecedores (em ordem)
    supplier_ids = [int(x) for x in (quote.suppliers or '').split(',') if x]
    supplier_objs = Supplier.query.filter(Supplier.id.in_(supplier_ids)).all()
    # Mantém a ordem original dos IDs
    supplier_map = {s.id: s.name for s in supplier_objs}
    supplier_names = [supplier_map.get(sid, f'Fornecedor {sid}') for sid in supplier_ids]
    quote_suppliers = supplier_ids

    # 3. Monta lista de produtos
    quote_items = list(enumerate([item.strip() for item in (quote.items or '').split('\n') if item.strip()]))

    # 4. Map de respostas (id -> resposta com lista de answers)
    quote_responses = {}
    for r in responses:
        try:
            answers = json.loads(r.answers)
        except Exception:
            answers = []
        quote_responses[r.supplier_id] = {'answers': answers}

    # 5. Melhor fornecedor para cada produto
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

    # 6. Renderiza o template usando exatamente o padrão do seu HTML novo
    return render_template(
        'quote_results.html',
        quote=quote,
        supplier_names=supplier_names,    # lista de nomes dos fornecedores (header)
        quote_items=quote_items,          # lista de tuplas (idx, nome do produto)
        quote_suppliers=quote_suppliers,  # lista de ids (ordem dos fornecedores)
        quote_responses=quote_responses,  # dict: fornecedor_id -> {'answers': [ ... ]}
        best_per_item=best_per_item       # dict: idx_produto -> id_fornecedor_com_menor_preco
    )

@app.route('/delete_quote/<int:quote_id>', methods=['POST'])
@login_required
def delete_quote(quote_id):
    user = get_logged_user()
    quote = Quote.query.get_or_404(quote_id)
    db.session.delete(quote)
    db.session.commit()
    flash('Cotação excluída com sucesso!', 'success')
    return redirect(url_for('quote_index'))

# ==============================================
# API & CONSULT ROUTES
# ==============================================

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
    name  = request.form.get('name','').strip()
    cpf   = request.form.get('cpf','').strip()
    phone = request.form.get('phone','').strip()
    start = request.form.get('start','')
    if not start:
        return "Data de início ausente", 400

    try:
        date_part, time_part = start.split('T')
        day, month, year     = date_part.split('/')
        date_iso             = f"{year}-{month}-{day}"
        hh, mm               = map(int, time_part.split(':'))
        start_iso            = f"{date_iso}T{hh:02d}:{mm:02d}:00"
        end_iso              = f"{date_iso}T{(hh+1)%24:02d}:{mm:02d}:00"
    except Exception:
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
        app.logger.error(f"Erro ao agendar no Google: {e}")
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
    return redirect(url_for("agenda"))


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


# ==============================================
# QUIZ ROUTES
# ==============================================
@app.route('/quiz')
def quiz():
    return render_template('quiz.html')


@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    data = request.get_json() or {}
    print("DEBUG SUBMIT_QUIZ:", data)

    name = data.get('nome', 'Anônimo')
    age_raw = data.get('idade', '0')
    try:
        age = int(age_raw)
    except ValueError:
        age = 0

    doctor_id = request.args.get('admin', type=int) or session.get('user_id')
    if doctor_id is None:
        return jsonify(status='error', error='doctor_id ausente'), 400

    # 1. Cria o paciente
    patient = add_patient(
        name=name,
        age=age,
        cpf=None,
        gender=None,
        phone=None,
        doctor_id=doctor_id,
        prescription=f"Autoavaliação: {data.get('risco')}"
    )

    # --- TRATAMENTO DE LISTAS PARA CAMPOS MULTIVALORADOS ---
    fatores = data.get('fatores', [])
    if isinstance(fatores, list):
        fatores = json.dumps(fatores)  # armazene como string JSON
    elif isinstance(fatores, str):
        fatores = json.dumps([fatores])
    else:
        fatores = json.dumps([])

    motivacao = data.get('motivacao', [])
    if isinstance(motivacao, list):
        motivacao = '; '.join(motivacao)  # separa por ponto e vírgula
    elif isinstance(motivacao, str):
        motivacao = motivacao
    else:
        motivacao = ""

    # 2. Cria o resultado do quiz
    qr = add_quiz_result(
        name=name,
        age=age,
        date=datetime.utcnow(),
        nervosismo=data.get('nervosismo'),
        preocupacao=data.get('preocupacao'),
        interesse=data.get('interesse'),
        depressao_raw=data.get('depressao_raw'),
        estresse_raw=data.get('estresse_raw'),
        hora_extra=data.get('hora_extra'),
        sono=data.get('sono'),
        atividade_fisica=data.get('atividade_fisica'),
        fatores=fatores,              # agora sempre string
        motivacao=motivacao,          # agora sempre string
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
        patient_id=patient.id  # <-- associa quiz ao paciente
    )

    print("QUIZ RESULT ADDED:", qr)
    
    # 3. Atualiza o paciente para apontar para o quiz
    patient.quiz_result_id = qr.id
    db.session.commit()

    return jsonify(status='ok', quiz_id=qr.id)

@app.route('/selfevaluation')
def selfevaluation():
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    # garanta que doctor_id seja um int válido
    doctor_id = user.id

    # usa a função de records para buscar resultados
    results = get_quiz_results_by_doctor(doctor_id)

    # conta quantos quizzes por dia
    counts = defaultdict(int)
    for r in results:
        day = r.date.strftime('%d/%m')
        counts[day] += 1

    labels = list(counts.keys())
    values = list(counts.values())

    return render_template('selfevaluation.html', labels=labels, values=values)


@app.route("/quiz-results")
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
def quiz_patient(quiz_id):
    user = get_logged_user()
    if not user:
        return redirect(url_for('login'))

    result = QuizResult.query.get_or_404(quiz_id)
    if result.doctor_id != user.id:
        abort(403)

    # Decodifica fatores (JSON string para lista legível)
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

    # Motivação pode ser lista ou string separada por ';'
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

    return render_template(
        'quiz_patient.html',
        patient=patient,
        questions=questions
    )

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


# ==============================================
# APPLICATION ENTRY POINT
# ==============================================
if __name__ == '__main__':
    app.run(debug=True)
