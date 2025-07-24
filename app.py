# ==============================================
# INITIAL CONFIGURATION AND UTILITIES
# ==============================================

from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify, flash
from datetime import datetime, timedelta
import os
import json
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import weasyprint
from prescription import analyze_pdf
from records import (
    add_consultation, add_patient, get_consults, get_patient, get_patients, update_patient,
    delete_patient_record, add_product, get_products, update_product_status, update_doctor,
    update_patient_status, save_products, get_doctors, add_doctor_if_not_exists, get_consults,
    get_package_info, is_package_available, update_package_usage, update_prescription_in_consult,
)
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
import jwt
from typing import cast
from whatsapp import send_pdf_whatsapp, send_quote_whatsapp
from mercado_pago import generate_payment_link
import uuid
from email_utils import send_email_quote


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
load_dotenv()

USERNAME = os.getenv("APP_USERNAME")
PASSWORD = os.getenv("APP_PASSWORD")

MUX_TOKEN_ID = os.getenv("MUX_TOKEN_ID")
MUX_TOKEN_SECRET = os.getenv("MUX_TOKEN_SECRET")
MUX_SIGNING_KEY = os.getenv("MUX_SIGNING_KEY")
MUX_PRIVATE_KEY_PATH = os.getenv("MUX_PRIVATE_KEY")

required_env = {
    "MUX_TOKEN_ID": os.getenv("MUX_TOKEN_ID"),
    "MUX_TOKEN_SECRET": os.getenv("MUX_TOKEN_SECRET"),
    "MUX_SIGNING_KEY": os.getenv("MUX_SIGNING_KEY"),
    "MUX_PRIVATE_KEY": os.getenv("MUX_PRIVATE_KEY")
}

missing = [key for key, value in required_env.items() if not value]
if missing:
    raise EnvironmentError(f"The following MUX environment variables are missing: {', '.join(missing)}")

token_id = required_env["MUX_TOKEN_ID"]
token_secret = required_env["MUX_TOKEN_SECRET"]
signing_key = required_env["MUX_SIGNING_KEY"]
mux_key_content = required_env["MUX_PRIVATE_KEY"]
if mux_key_content:
    os.makedirs("Keys", exist_ok=True)
    private_key_path = "Keys/mux_private.key"
    with open(private_key_path, "w") as f:
        f.write(mux_key_content.replace("\\n", "\n"))
else:
    raise EnvironmentError("MUX_PRIVATE_KEY is missing or invalid.")


@app.route('/hero')
def hero():
    return render_template('hero.html')

def load_users():
    with open('json/users.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def load_agenda():
    if os.path.exists('json/agenda.json'):
        with open('json/agenda.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_agenda(events):
    with open('json/agenda.json', 'w', encoding='utf-8') as f:
        json.dump(events, f, ensure_ascii=False, indent=2)

def get_videos():
    if os.path.exists('json/videos.json'):
        with open('json/videos.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def create_signed_token(playback_id: str) -> str:
    with open(private_key_path, 'r') as f:
        private_key = f.read()
    payload = {
        "exp": datetime.utcnow() + timedelta(hours=1),
        "kid": signing_key,
        "aud": "v",
        "sub": playback_id
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")
    return token.decode("utf-8") if isinstance(token, bytes) else token

@app.before_request
def protect_admin_routes():
    if request.path.startswith(('/purchase', '/webhook', '/api/')) and 'user' not in session:
        return redirect(url_for('login'))

# ==============================================
# AUTHENTICATION AND ACCOUNT MANAGEMENT
# ==============================================

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_users()
        user = next((u for u in users if u['username'] == username), None)
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/update_personal_info', methods=['POST'])
def update_personal_info():
    if 'user' not in session:
        return redirect(url_for('login'))

    users = load_users()
    user = next((u for u in users if u['username'] == session['user']), None)

    if not user:
        return "User not found", 404

    firstname = request.form.get("name", "")
    secondname = request.form.get("secondname", "")
    birthdate = request.form.get("birthdate", "")
    email = request.form.get("email", "")

    user["name"] = f"{firstname.strip()} {secondname.strip()}"
    user["birthdate"] = birthdate
    user["email"] = email

    profile_image = request.files.get("profile_image")
    if profile_image and profile_image.filename:
        uploads_folder = os.path.join("static", "profile_images")
        os.makedirs(uploads_folder, exist_ok=True)
        image_filename = f"{session['user']}_profile.png"
        image_path = os.path.join(uploads_folder, image_filename)
        profile_image.save(image_path)
        user["profile_image"] = f"profile_images/{image_filename}"

    with open('json/users.json', 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

    return redirect(url_for("account"))

@app.route('/update_password', methods=['POST'])
def update_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    users = load_users()
    user = next((u for u in users if u['username'] == session['user']), None)

    if not user:
        return "User not found", 404

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not check_password_hash(user['password'], current_password):
        return render_template("account.html", user=user, error="Incorrect current password.")

    if new_password != confirm_password:
        return render_template("account.html", user=user, error="Passwords do not match.")

    user['password'] = generate_password_hash(new_password)

    with open('json/users.json', 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

    return redirect(url_for("account"))

@app.route("/account")
def account():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_data = get_logged_user()
    if not user_data:
        return "User not found", 404

    return render_template("account.html", user=user_data)

@app.route('/remove_profile_image', methods=['POST'])
def remove_profile_image():
    if 'user' not in session:
        return redirect(url_for('login'))

    users = load_users()
    user = next((u for u in users if u['username'] == session['user']), None)

    if not user:
        return "User not found", 404

    if user.get('profile_image') and user['profile_image'] != 'images/user-icon.png':
        image_path = os.path.join("static", user['profile_image'])
        if os.path.exists(image_path):
            os.remove(image_path)
    
    user['profile_image'] = 'images/user-icon.png'

    with open('json/users.json', 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

    return redirect(url_for('account'))

@app.route('/BioO3-lab')
def BioO3_lab():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_data = get_logged_user()
    if not user_data:
        return redirect(url_for('login'))

    if not is_package_available(user_data['id']):
        return redirect(url_for('purchase'))

    return render_template('upload.html')

def get_logged_user():
    if 'user' not in session:
        return None
    users = load_users()
    return next((u for u in users if u['username'] == session['user']), None)

# ==============================================
#  - DASHBOARD AND PDF UPLOAD
# ==============================================

@app.route('/index')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Consultas por dia
    file_path = os.path.join(os.path.dirname(__file__), 'json', 'consults.json')
    with open(file_path, encoding="utf-8") as f:
        consults = json.load(f)

    counts = {}
    for consultas in consults.values():
        for consulta in consultas:
            lines = consulta.splitlines()
            for line in lines:
                if "Data:" in line:
                    date_str = line.split("Data:")[1].strip()
                    try:
                        date_obj = datetime.strptime(date_str, "%d-%m-%Y")
                        date_obj = date_obj.replace(hour=0, minute=0, second=0, microsecond=0)
                        counts[date_obj] = counts.get(date_obj, 0) + 1
                    except ValueError:
                        continue

    today = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
    chart_data = []
    total = 0
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        count = counts.get(day, 0)
        total += count
        dias_passados = 7 - i
        media_acumulada = round(total / dias_passados, 2)
        chart_data.append({
            "date": day.strftime("%d/%m"),
            "count": count,
            "media": media_acumulada
        })

    # Dados do usuário  
    user_data = get_logged_user() or {}
    full_name = user_data.get('name', session['user'])

    # Pacotes
    package_info = get_package_info(user_data['id'])
    remaining = package_info['total'] - package_info['used']
    used = package_info['used']

    return render_template(
        "index.html",
        chart_data=chart_data,
        username=full_name,
        user=user_data,
        remaining=remaining,
        used=used
    )

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    user_data = get_logged_user()
    if not user_data:
        return redirect(url_for('login'))

    if not is_package_available(user_data['id']):
        flash('Seu pacote de análises acabou. Por favor, adquira mais para continuar usando o Ponza Lab.')
        return redirect(url_for('purchase', message='pacote'))

    if request.method == 'POST':
        if 'manual_entry' in request.form:
            # === Inserção Manual ===
            name = request.form['name']
            age = int(request.form['age'])
            cpf = request.form['cpf']
            gender = request.form['gender']
            phone = request.form['phone']
            doctor_name = request.form['doctor']
            manual_text = request.form['lab_results']

            doctor_id, doctor_phone = add_doctor_if_not_exists(doctor_name)
            diagnostic, prescription = analyze_pdf(manual_text, manual=True) #type: ignore

            patient_id = add_patient(name, age, cpf, gender, phone, doctor_id, prescription)
            today = datetime.today().strftime('%d-%m-%Y')
            add_consultation(
                patient_id,
                f"Data: {today}\n\nDiagnóstico:\n{diagnostic}\n\nPrescrição:\n{prescription}",
                user_data['id']
            )

            patient_info = f"Paciente: {name}\nIdade: {age}\nCPF: {cpf}\nSexo: {gender}\nTelefone: {phone}\nMédico: {doctor_name}"
            session['diagnostic_text'] = diagnostic
            session['prescription_text'] = prescription
            session['doctor_name'] = doctor_name
            session['patient_info'] = patient_info

            html = render_template(
                "result_pdf.html",
                diagnostic_text=diagnostic,
                prescription_text=prescription,
                doctor_name=doctor_name,
                patient_info=patient_info,
                logo_path=os.path.join(app.root_path, 'static', 'images', 'logo.png')
            )
            pdf = weasyprint.HTML(string=html, base_url=os.path.join(app.root_path, 'static')).write_pdf()

            cpf_clean = (cpf or "").replace('.', '').replace('-', '')
            pdf_filename = f"result_{cpf_clean}.pdf"
            output_folder = os.path.join("static", "output")
            os.makedirs(output_folder, exist_ok=True)
            pdf_path = os.path.join(output_folder, pdf_filename)

            if not isinstance(pdf, bytes):
                raise ValueError("Falha ao gerar o PDF: o resultado não é um objeto válido.")

            with open(pdf_path, 'wb') as f:
                f.write(pdf)

            pdf_link = url_for('static', filename=f"output/{pdf_filename}", _external=True)
            send_pdf_whatsapp(
                doctor_name=doctor_name,
                patient_name=name,
                analyzed_pdf_link=pdf_link,
                original_pdf_link=None  # sem original no modo manual
            )

            update_package_usage(user_data['id'], get_package_info(user_data['id'])['used'] + 1)

            return render_template(
                'result.html',
                diagnostic_text=diagnostic,
                prescription_text=prescription
            )

        else:
            # === Upload de PDF ===
            pdf_file = request.files.get('pdf_file')
            if not pdf_file or pdf_file.filename == '':
                return render_template('upload.html', error='Por favor, selecione um arquivo PDF.')

            uploads_folder = os.path.join("static", "uploads")
            os.makedirs(uploads_folder, exist_ok=True)

            filename = pdf_file.filename or "file.pdf"
            upload_path = os.path.join(uploads_folder, filename)
            pdf_file.save(upload_path)

            diagnostic, prescription, name, gender, age, cpf, phone, doctor_name = analyze_pdf(upload_path) # type: ignore
            doctor_id, doctor_phone = add_doctor_if_not_exists(doctor_name)
            patient_id = add_patient(name, age, cpf, gender, phone, doctor_id, prescription)
            today = datetime.today().strftime('%d-%m-%Y')

            add_consultation(patient_id, f"Data: {today}\n\nDiagnóstico:\n{diagnostic}\n\nPrescrição:\n{prescription}", user_data['id'])

            patient_info = f"Paciente: {name}\nIdade: {age}\nCPF: {cpf}\nSexo: {gender}\nTelefone: {phone}\nMédico: {doctor_name}"
            session['diagnostic_text'] = diagnostic
            session['prescription_text'] = prescription
            session['doctor_name'] = doctor_name
            session['patient_info'] = patient_info

            html = render_template("result_pdf.html",
                diagnostic_text=diagnostic,
                prescription_text=prescription,
                doctor_name=doctor_name,
                patient_info=patient_info,
                logo_path=os.path.join(app.root_path, 'static', 'images', 'logo.png')
            )
            pdf = weasyprint.HTML(string=html, base_url=os.path.join(app.root_path, 'static')).write_pdf()

            cpf_clean = (cpf or "").replace('.', '').replace('-', '')
            pdf_filename = f"result_{cpf_clean}.pdf"
            output_folder = os.path.join("static", "output")
            os.makedirs(output_folder, exist_ok=True)
            pdf_path = os.path.join(output_folder, pdf_filename)

            with open(pdf_path, 'wb') as f:
                f.write(pdf) #type: ignore

            pdf_link_analyzed = url_for('static', filename=f"output/{pdf_filename}", _external=True)
            pdf_link_original = url_for('static', filename=f"uploads/{pdf_file.filename}", _external=True)

            send_pdf_whatsapp(
                doctor_name=doctor_name,
                patient_name=name,
                analyzed_pdf_link=pdf_link_analyzed,
                original_pdf_link=pdf_link_original
            )

            update_package_usage(user_data['id'], get_package_info(user_data['id'])['used'] + 1)

            return render_template('result.html',
                diagnostic_text=diagnostic,
                prescription_text=prescription
            )

    return render_template('upload.html')

@app.route("/download_pdf")
def download_pdf():
    if 'user' not in session:
        return redirect(url_for('login'))

    diagnostic_text = session.get('diagnostic_text', '')
    prescription_text = session.get('prescription_text', '')
    doctor_name = session.get('doctor_name', '')
    patient_info = session.get('patient_info', '')

    logo_path = os.path.join(app.root_path, 'static', 'images', 'logo.png')
    html = render_template(
        "result_pdf.html",
        diagnostic_text=diagnostic_text,
        prescription_text=prescription_text,
        doctor_name=doctor_name,
        patient_info=patient_info,
        logo_path=logo_path
    )

    pdf = weasyprint.HTML(string=html, base_url=os.path.join(app.root_path, 'static')).write_pdf()

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=prescription.pdf'
    return response

# ==============================================
#  - PATIENT MANAGEMENT
# ==============================================

@app.route('/catalog')
def catalog():
    if 'user' not in session:
        return redirect(url_for('login'))

    search = request.args.get('search', '').lower()
    status_filter = request.args.get('status', '')
    patients = get_patients()
    doctors = get_doctors()

    def match(p):
        return (not search or search in p.name.lower()) and (not status_filter or p.status == status_filter)

    filtered_patients = [p for p in patients if match(p)]
    return render_template('catalog.html', patients=filtered_patients, doctors=doctors)

@app.route('/edit_patient/<int:patient_id>', methods=['GET', 'POST'])
def edit_patient(patient_id):
    if 'user' not in session:
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
    
    update_prescription_in_consult(patient_id, request.form.get('prescription', '').strip())
    return render_template('edit_patient.html', patient=patient, doctors=doctors)

@app.route('/patient_result/<int:patient_id>')
def patient_result(patient_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    patient = get_patient(patient_id)
    if not patient:
        return render_template('result.html', diagnostic_text="Paciente não encontrado.", prescription_text="")

    consultations = get_consults(patient_id)
    if consultations:
        latest = consultations[-1]
        parts = latest.split("Prescrição:\n")
        diagnostic_text = parts[0].strip() if len(parts) > 0 else ""
        prescription_text = parts[1].strip() if len(parts) > 1 else ""
    else:
        diagnostic_text = "Nenhuma consulta registrada."
        prescription_text = ""

    # Inclui a prescrição configurada no cadastro do paciente (prioridade ao histórico)
    if not prescription_text.strip():
        prescription_text = patient.get("prescription", "")

    return render_template(
        'result.html',
        diagnostic_text=diagnostic_text,
        prescription_text=prescription_text,
        doctor_name=patient.get("doctor_name", "Desconhecido")
    )

@app.route('/delete_patient/<int:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    delete_patient_record(patient_id)
    return redirect(url_for('catalog'))

@app.route('/toggle_patient_status/<int:patient_id>/<new_status>')
def toggle_patient_status(patient_id, new_status):
    update_patient_status(patient_id, new_status)
    return redirect(url_for('catalog'))

@app.route('/api/add_patient', methods=['POST'])
def api_add_patient():
    if 'user' not in session:
        return jsonify(success=False, error='Unauthorized'), 403

    data = request.get_json()
    if not data:
        return jsonify(success=False, error='Invalid JSON data'), 400

    name = data.get("name", "").strip()
    age = data.get("age", "").strip()
    cpf = data.get("cpf", "").strip()
    gender = data.get("gender", "").strip()
    phone = data.get("phone", "").strip()
    doctor_id = data.get("doctor")
    prescription = data.get("prescription", "").strip()

    if not name or not age or not doctor_id:
        return jsonify(success=False, error='Missing required fields'), 400

    try:
        patient_id = add_patient(name, age, cpf, gender, phone, int(doctor_id), prescription)
        return jsonify(success=True, patient_id=patient_id)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500


# ==============================================
#  - CONSULTATION MANAGEMENT
# ==============================================

@app.route('/add_consultation/<int:patient_id>', methods=['GET', 'POST'])
def add_consultation_route(patient_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    patient = get_patient(patient_id)
    if not patient:
        return "Patient not found", 404

    if request.method == 'POST':
        data = request.form['date']
        notes = request.form.get('notes', '')
        try:
            data_obj = datetime.strptime(data, '%d/%m/%Y')
            datetime_str = data_obj.strftime('%Y-%m-%dT00:00:00')
        except ValueError:
            return "Invalid date format. Use dd/mm/yyyy.", 400

        events = load_agenda()
        events.append({
            'title': f"Consultation - {patient['name']}",
            'datetime': datetime_str,
            'notes': notes
        })
        save_agenda(events)
        return redirect(url_for('agenda'))

    user_data = get_logged_user()
    return render_template(
        'add_consultation.html',
        patients=[patient],
        user=user_data
    )




@app.route('/submit_consultation', methods=['POST'])
def submit_consultation():
    patient_id = int(request.form['patient']) if request.form['patient'] else None
    consultation_text = f"Data: {request.form['date']}\nObservações: {request.form['notes']}"
    user_id = int(request.form['user_id'])

    if patient_id:
        add_consultation(patient_id, consultation_text, user_id)

    return redirect(url_for('agenda'))

@app.route('/add_general_consultation', methods=['POST'])
def add_general_consultation():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    date_str = data.get('date', '')
    notes = data.get('notes', '')
    patient_id = data.get('patient_id')

    try:
        date_obj = datetime.strptime(date_str, '%d/%m/%Y')
        datetime_str = date_obj.strftime('%Y-%m-%dT00:00:00')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use dd/mm/yyyy.'}), 400

    title = "General Consultation"
    if patient_id:
        try:
            patient = get_patient(int(patient_id))
            if patient:
                title = f"Consultation - {patient['name']}"
        except Exception:
            pass

    events = load_agenda()
    events.append({
        'title': title,
        'datetime': datetime_str,
        'notes': notes
    })
    save_agenda(events)

    return jsonify({'success': True})

@app.route('/modal_consultation')
def modal_consultation():
    if 'user' not in session:
        return redirect(url_for('login'))
    patients = get_patients()
    return render_template('add_consultation.html', patients=patients)

# ==============================================
#  - PRODUCT MANAGEMENT
# ==============================================

@app.route('/products')
def products():
    if 'user' not in session:
        return redirect(url_for('login'))

    produtos = get_products()
    cat = request.args.get('category', '')
    via = request.args.get('application_route', '')
    stat = request.args.get('status', '')
    stock_f = request.args.get('stock_filter', 'all')
    search = request.args.get('search', '').lower()

    def keep(p):
        return (
            (not cat or p.get('category') == cat) and
            (not via or p.get('application_route') == via) and
            (not stat or p.get('status') == stat) and
            (stock_f != 'in_stock' or p.get('quantity', 0) > 0) and
            (stock_f != 'min_stock' or p.get('quantity', 0) <= p.get('min_stock', 0)) and
            (not search or search in p.get('name', '').lower())
        )

    filtered = [p for p in produtos if keep(p)]
    categories = sorted({p.get('category','') for p in produtos if p.get('category')})
    application_routes = sorted({p.get('application_route','') for p in produtos if p.get('application_route')})

    return render_template('products.html', products=filtered, categories=categories, application_routes=application_routes)

@app.route('/add_product', methods=['POST'])
def add_product_route():
    if 'user' not in session:
        return redirect(url_for('login'))

    name = request.form.get('name', '').strip()
    quantity = int(request.form.get('quantity', 0))
    purchase_price = float(request.form.get('purchase_price', 0))
    sale_price = float(request.form.get('sale_price', 0))

    if not name:
        return "Product name is required.", 400

    add_product(name, purchase_price, sale_price, quantity)
    return redirect(url_for('products'))

@app.route('/toggle_product_status/<int:product_id>/<new_status>')
def toggle_product_status(product_id, new_status):
    update_product_status(product_id, new_status)
    return redirect(url_for('products'))

@app.route('/stock_view/<int:product_id>')
def stock_view(product_id):
    product = next((p for p in get_products() if p['id'] == product_id), None)
    if not product:
        return "Product not found", 404
    return render_template('stock_view.html', product=product)

@app.route('/stock_edit/<int:product_id>', methods=['GET','POST'])
def stock_edit(product_id):
    produtos = get_products()
    product = next((p for p in produtos if p['id'] == product_id), None)
    if not product:
        return "Product not found", 404
    if request.method == 'POST':
        product['code'] = request.form['code']
        product['name'] = request.form['name']
        product['quantity'] = int(request.form['quantity'])
        product['purchase_price'] = float(request.form['purchase_price'])
        product['sale_price'] = float(request.form['sale_price'])
        save_products(produtos)
        return redirect(url_for('products'))
    return render_template('stock_edit.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    produtos = [p for p in get_products() if p['id'] != product_id]
    save_products(produtos)
    return redirect(url_for('products'))

# ==============================================
#  - SCHEDULER (AGENDA)
# ==============================================

@app.route('/agenda')
def agenda():
    if 'user' not in session:
        return redirect(url_for('login'))
    doctors = get_doctors()
    return render_template('agenda.html', doctors=doctors)

@app.route('/api/events')
def api_events():
    events = load_agenda()
    calendar_events = [
        {
            "title": event["title"],
            "start": event["datetime"],
            "end": event["datetime"],
            "description": event["notes"]
        } for event in events
    ]
    return jsonify(calendar_events)

@app.route('/api/add_event', methods=['POST'])
def api_add_event():
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.get_json()
    title = data.get('title', '')
    datetime_str = data.get('start', '')
    notes = data.get('notes', '')
    doctor_id = data.get('doctor_id')

    if not title or not datetime_str:
        return jsonify({'success': False, 'error': 'All fields are required.'}), 400

    # Salvar o evento incluindo o ID do médico:
    events = load_agenda()
    events.append({
        'title': title,
        'datetime': datetime_str,
        'notes': notes,
    })
    save_agenda(events)

    return jsonify({'success': True})

# ==============================================
#  - DOCTOR MANAGEMENT
# ==============================================

@app.route("/doctors")
def doctors():
    doctors = get_doctors()
    return render_template("doctors.html", doctors=doctors)

@app.route("/update_doctor/<int:doctor_id>", methods=["POST"])
def update_doctor_route(doctor_id):
    update_doctor(doctor_id, request.form["name"], request.form["phone"])
    return redirect(url_for("doctors"))

@app.route('/add_doctor', methods=['POST'])
def add_doctor_route():
    name = request.form['name']
    phone = request.form['phone']
    doctors = get_doctors()
    new_id = max((d['id'] for d in doctors), default=0) + 1
    doctors.append({'id': new_id, 'name': name, 'phone': phone})
    with open('json/doctors.json', 'w', encoding='utf-8') as f:
        json.dump(doctors, f, ensure_ascii=False, indent=2)
    return redirect(url_for('doctors'))

@app.route('/edit_doctor/<int:doctor_id>', methods=['GET', 'POST'])
def edit_doctor(doctor_id):
    doctors = get_doctors()
    doctor = next((d for d in doctors if d['id'] == doctor_id), None)
    if not doctor:
        return "Doctor not found", 404
    if request.method == 'POST':
        doctor['name'] = request.form['name']
        doctor['phone'] = request.form['phone']
        with open('json/doctors.json', 'w', encoding='utf-8') as f:
            json.dump(doctors, f, indent=4, ensure_ascii=False)
        return redirect(url_for('doctors'))
    return render_template('edit_doctor.html', doctor=doctor)

@app.route('/delete_doctor/<int:doctor_id>', methods=['POST'])
def delete_doctor(doctor_id):
    doctors = get_doctors()
    doctors = [d for d in doctors if d['id'] != doctor_id]
    with open('json/doctors.json', 'w', encoding='utf-8') as f:
        json.dump(doctors, f, ensure_ascii=False, indent=2)
    return redirect(url_for('doctors'))


# ==============================================
#  - PAYMENT AND WEBHOOK
# ==============================================

@app.route('/purchase', methods=['GET', 'POST'])
def purchase():
    try:
        if request.method == 'POST':
            pacote = request.form.get('package')
            valor = {'50': 120, '150': 300, '500': 950}.get(pacote or "")

            if not valor:
                print("[DEBUG] Invalid package selected:", pacote)
                return redirect(url_for('purchase'))

            payment_link = generate_payment_link(pacote, valor)
            if payment_link:
                print("[DEBUG] Payment link generated successfully:", payment_link)
                return redirect(payment_link)
            else:
                print("[DEBUG] Error generating payment link (empty link)")
                return redirect(url_for('pagamento_falha'))

        return render_template('purchase.html', user={})

    except Exception as e:
        print("[ERROR IN /purchase ROUTE]", str(e))
        return redirect(url_for('pagamento_falha'))

@app.route('/pagamento-sucesso')
def pagamento_sucesso():
    return "Pagamento completo com sucesso."

@app.route('/pagamento-falha')
def pagamento_falha():
    return "Pagamento falhou."

@app.route('/pagamento-pendente')
def pagamento_pendente():
    return "Pagamento está pendente. Por favor espere pela confirmação"

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid payload'}), 400

    print("[Webhook received]", data)
    return jsonify({'status': 'received'}), 200

# ==============================================
#  - VIDEO MANAGEMENT (MUX)
# ==============================================

@app.route('/videos')
def videos():
    if 'user' not in session:
        return redirect(url_for('login'))
    raw_videos = get_videos()
    videos = [
        {
            "title": v["title"],
            "playback_id": v["playback_id"],
            "token": create_signed_token(v["playback_id"])
        }
        for v in raw_videos
    ]
    return render_template('videos.html', videos=videos)

@app.route('/watch/<playback_id>')
def watch_video(playback_id):
    videos = get_videos()
    video = next((v for v in videos if v["playback_id"] == playback_id), None)
    if not video:
        return "Video not found", 404

    token = create_signed_token(playback_id)
    pdf_filename = video.get("pdf")

    return render_template(
        'watch_video.html',
        title=video["title"],
        playback_id=playback_id,
        token=token,
        pdf_filename=pdf_filename
    )

# ==============================================
# QUOTE SYSTEM
# ==============================================

@app.route('/quotes/create', methods=['GET', 'POST'])
def create_quote():
    with open('json/suppliers.json', 'r', encoding='utf-8') as f:
        suppliers = json.load(f)

    if request.method == 'POST':
        title = request.form['title']
        items_raw = request.form['items']
        supplier_ids = request.form.getlist('supplier_ids')

        quote_id = str(uuid.uuid4())[:8]
        quote = {
            "id": quote_id,
            "title": title,
            "created_at": datetime.now().strftime('%d/%m/%Y %H:%M'),
            "items": [i.strip() for i in items_raw.split('\n') if i.strip()],
            "suppliers": supplier_ids,
            "responses": {}
        }

        try:
            with open('json/quotes.json', 'r', encoding='utf-8') as f:
                quotes = json.load(f)
        except FileNotFoundError:
            quotes = []

        quotes.append(quote)

        with open('json/quotes.json', 'w', encoding='utf-8') as f:
            json.dump(quotes, f, indent=4, ensure_ascii=False)

        # ================== WHATSAPP + EMAIL ===================
        supplier_map = {str(s['id']): s for s in suppliers}
        items_text = "\n".join([f"• {item}" for item in quote['items']])
        base_message = f"📦 *Nova Cotação: {title}*\n\n{items_text}"

        for sid in supplier_ids:
            supplier = supplier_map.get(sid)
            if supplier:
                response_url = f"https://Ponza Health.com.br/quote/{quote_id}/supplier/{sid}"
                message = f"{base_message}\n\nResponda aqui: {response_url}"
                message = message.replace("\n", " ").replace("\t", " ").replace("  ", " ").strip()

                # WhatsApp
                if supplier.get("phone"):
                    try:
                        send_quote_whatsapp(
                            supplier_name=supplier['name'],
                            phone=supplier['phone'],
                            quote_title=title,
                            quote_items=quote['items'],
                            response_url=response_url
                        )
                    except Exception as e:
                        print(f"[Erro WhatsApp - {supplier['name']}] {e}")

                # Email
                if supplier.get("email"):
                    try:
                        email_subject = f"Cotação Ponza Health: {title}"
                        email_body = f"""
Olá {supplier['name']},

Você recebeu uma nova cotação da plataforma Ponza Health.

Título: {title}
Itens:
{items_text}

Responda acessando o link abaixo:
{response_url}

Atenciosamente,
Equipe Ponza Health
"""
                        send_email_quote(supplier['email'], email_subject, email_body)
                    except Exception as e:
                        print(f"Erro ao enviar e-mail para {supplier['email']}: {e}")

        return redirect(url_for('quote_success', quote_id=quote_id))

    return render_template('create_quote.html', suppliers=suppliers)


@app.route('/quotes/success/<quote_id>')
def quote_success(quote_id):
    return f'Cotação criada com sucesso! ID: {quote_id}'

@app.route('/quote/<quote_id>/supplier/<supplier_id>', methods=['GET', 'POST'])
def respond_quote(quote_id, supplier_id):
    try:
        with open('json/quotes.json', 'r', encoding='utf-8') as f:
            quotes = json.load(f)
    except FileNotFoundError:
        return "Nenhuma cotação encontrada."

    quote = next((q for q in quotes if q['id'] == quote_id), None)
    if not quote or supplier_id not in quote['suppliers']:
        return "Cotação inválida ou fornecedor não autorizado."

    if request.method == 'POST':
        prices = []
        for idx in range(len(quote['items'])):
            price = request.form.get(f'price_{idx}')
            deadline = request.form.get(f'deadline_{idx}')
            prices.append({"price": price, "deadline": deadline})

        if "responses" not in quote:
            quote['responses'] = {}

        quote['responses'][supplier_id] = {
            "submitted_at": datetime.now().strftime('%d/%m/%Y %H:%M'),
            "answers": prices
        }

        # Atualizar a lista com a nova resposta
        for i, q in enumerate(quotes):
            if q['id'] == quote_id:
                quotes[i] = quote
                break

        with open('json/quotes.json', 'w', encoding='utf-8') as f:
            json.dump(quotes, f, indent=4, ensure_ascii=False)

        return "Cotação enviada com sucesso. Obrigado!"

    return render_template('quote_response.html', quote=quote)

@app.route('/quotes/<quote_id>/results')
def quote_results(quote_id):
    with open('json/quotes.json', 'r', encoding='utf-8') as f:
        quotes = json.load(f)

    quote = next((q for q in quotes if q['id'] == quote_id), None)
    if not quote:
        return "Cotação não encontrada."

    # Mapear nomes dos fornecedores
    with open('json/suppliers.json', 'r', encoding='utf-8') as f:
        suppliers = json.load(f)

    supplier_names = []
    supplier_map = {str(s["id"]): s["name"] for s in suppliers}
    for sid in quote["suppliers"]:
        supplier_names.append(supplier_map.get(sid, f"Fornecedor {sid}"))

    # Melhor preço por item
    best_per_item = {}
    for idx in range(len(quote["items"])):
        best_price = float('inf')
        best_supplier = None
        for sid, response in quote.get("responses", {}).items():
            try:
                price = float(response["answers"][idx]["price"])
                if price < best_price:
                    best_price = price
                    best_supplier = sid
            except (KeyError, ValueError, IndexError):
                continue
        best_per_item[idx] = best_supplier

    quote_items = list(enumerate(quote["items"]))
    
    return render_template(
        "quote_results.html",
        quote=quote,
        quote_items=quote_items,
        supplier_names=supplier_names,
        best_per_item=best_per_item
    )

@app.route('/quotes')
def quote_index():
    try:
        with open('json/quotes.json', 'r', encoding='utf-8') as f:
            quotes = json.load(f)
    except FileNotFoundError:
        quotes = []

    return render_template('quote_index.html', quotes=quotes)

@app.route('/add_supplier', methods=['POST'])
def add_supplier():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')

    try:
        with open('json/suppliers.json', 'r', encoding='utf-8') as f:
            suppliers = json.load(f)
    except FileNotFoundError:
        suppliers = []

    new_id = max([s['id'] for s in suppliers], default=0) + 1
    suppliers.append({
        "id": new_id,
        "name": name,
        "email": email,
        "phone": phone
    })

    with open('json/suppliers.json', 'w', encoding='utf-8') as f:
        json.dump(suppliers, f, indent=4, ensure_ascii=False)

    return redirect(url_for('suppliers'))

@app.route('/quotes/delete/<quote_id>', methods=['POST'])
def delete_quote(quote_id):
    try:
        with open('json/quotes.json', 'r', encoding='utf-8') as f:
            quotes = json.load(f)
    except FileNotFoundError:
        quotes = []

    updated_quotes = [q for q in quotes if q['id'] != quote_id]

    with open('json/quotes.json', 'w', encoding='utf-8') as f:
        json.dump(updated_quotes, f, indent=4, ensure_ascii=False)

    return redirect(url_for('quote_index'))

@app.route('/send_quote/<quote_id>', methods=['POST'])
def send_quote(quote_id):
    import requests

    # Carregar cotação
    try:
        with open('json/quotes.json', 'r', encoding='utf-8') as f:
            quotes = json.load(f)
    except FileNotFoundError:
        return "Erro: Nenhuma cotação encontrada."

    quote = next((q for q in quotes if q['id'] == quote_id), None)
    if not quote:
        return "Erro: Cotação não encontrada."

    # Carregar fornecedores
    with open('json/suppliers.json', 'r', encoding='utf-8') as f:
        suppliers = json.load(f)

    supplier_dict = {str(s['id']): s for s in suppliers}

    # Mensagem base
    item_list = "\n".join([f"• {item}" for item in quote['items']])
    base_message = f"📦 *Nova Cotação: {quote['title']}*\n\n{item_list}\n\nResponda por aqui:"

    # Enviar para cada fornecedor
    for sid in quote['suppliers']:
        supplier = supplier_dict.get(sid)
        if supplier and supplier.get("phone"):
            phone = supplier["phone"]
            response_url = f"https://BioO3.com.br/quote/{quote_id}/supplier/{sid}"
            message = f"{base_message}\n{response_url}"

            # --- Envio WhatsApp (simulado) ---
            # Substitua este bloco por sua API real
            print(f"Enviando para {phone}:")
            print(message)
            # Exemplo usando Meta API:
            # send_whatsapp_message(phone, message)
            # -------------------------------

    return redirect(url_for('quote_results', quote_id=quote_id))

@app.route('/suppliers')
def suppliers():
    with open('json/suppliers.json', 'r', encoding='utf-8') as f:
        suppliers = json.load(f)
    return render_template('suppliers.html', suppliers=suppliers)

@app.route('/delete_supplier/<int:supplier_id>', methods=['POST'])
def delete_supplier(supplier_id):
    try:
        with open('json/suppliers.json', 'r', encoding='utf-8') as f:
            suppliers = json.load(f)
    except FileNotFoundError:
        suppliers = []

    updated = [s for s in suppliers if s['id'] != supplier_id]

    with open('json/suppliers.json', 'w', encoding='utf-8') as f:
        json.dump(updated, f, indent=4, ensure_ascii=False)

    return redirect(url_for('suppliers'))

@app.route('/update_supplier/<int:supplier_id>', methods=['POST'])
def update_supplier(supplier_id):
    with open('json/suppliers.json', 'r', encoding='utf-8') as f:
        suppliers = json.load(f)

    supplier = next((s for s in suppliers if s['id'] == supplier_id), None)
    if not supplier:
        return "Fornecedor não encontrado.", 404

    supplier['name'] = request.form.get('name', supplier['name'])
    supplier['phone'] = request.form.get('phone', supplier['phone'])
    supplier['email'] = request.form.get('email', supplier['email'])

    with open('json/suppliers.json', 'w', encoding='utf-8') as f:
        json.dump(suppliers, f, indent=2, ensure_ascii=False)

    return redirect(url_for('suppliers'))



# ==============================================
# APPLICATION EXECUTION
# ==============================================

if __name__ == '__main__':
    app.run(debug=True)
