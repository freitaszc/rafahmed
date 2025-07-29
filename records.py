import json
import os
from datetime import datetime

# Files Paths (Constants)

PATIENTS_FILE = 'json/patients.json'
CONSULTS_FILE = 'json/consults.json'
PRODUCTS_FILE = 'json/products.json'
DOCTORS_FILE = 'json/doctors.json'
PACKAGES_FILE = 'json/packages.json'

# Patient Model (Class)

class Patient:
    def __init__(self, id, name, age, cpf, gender, phone, doctor, prescription="", status='Ativo', doctor_name="Não informado"):
        self.id = id
        self.name = name
        self.age = age
        self.cpf = cpf
        self.gender = gender
        self.phone = phone
        self.doctor = doctor
        self.status = status
        self.prescription = prescription
        self.doctor_name = doctor_name

# Patient Management

def get_patients():
    if not os.path.exists(PATIENTS_FILE):
        return []

    with open(PATIENTS_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    doctors = get_doctors()
    doctor_dict = {d["id"]: d["name"] for d in doctors}

    patients = []
    for item in data:
        doctor_name = doctor_dict.get(item.get('doctor'), "Não informado")
        patient = Patient(
            id=item.get('id'),
            name=item.get('name', ''),
            age=item.get('age', 0),
            cpf=item.get('cpf', ''),
            gender=item.get('gender', ''),
            phone=item.get('phone', ''),
            doctor=item.get('doctor', ''),
            prescription=item.get('prescription', ''),
            status=item.get('status', 'Ativo'),
            doctor_name=doctor_name
        )
        patients.append(patient)

    return patients

def get_patient(patient_id):
    with open(PATIENTS_FILE, "r", encoding="utf-8") as f:
        patients = json.load(f)
    patient = next((p for p in patients if p["id"] == patient_id), None)
    if patient:
        doctor_name = get_doctor_by_id(patient["doctor"])
        patient["doctor_name"] = doctor_name or "Não informado"
    return patient

def add_patient(name, age, cpf, gender, phone, doctor, prescription=""):
    patients = get_patients()
    new_id = max((p.id for p in patients), default=0) + 1

    new_patient = Patient(new_id, name, int(age), cpf, gender, phone, doctor)
    new_patient.prescription = prescription
    patients.append(new_patient)

    patients_data = []
    for p in patients:
        data = {
            "id": p.id,
            "name": p.name,
            "age": p.age,
            "cpf": p.cpf,
            "gender": p.gender,
            "phone": p.phone,
            "doctor": p.doctor,
            "status": p.status,
            "prescription": getattr(p, 'prescription', '')
        }
        if hasattr(p, 'created_at'):
            data["created_at"] = p.created_at
        elif p == new_patient:
            data["created_at"] = datetime.now().strftime("%Y-%m-%d")
        patients_data.append(data)

    with open(PATIENTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(patients_data, f, indent=4, ensure_ascii=False)

    return new_id

def update_patient(patient_id, name, age, cpf, gender, phone, doctor, prescription):
    patients = get_patients()
    for p in patients:
        if p.id == patient_id:
            p.name = name
            p.age = int(age)
            p.cpf = cpf
            p.gender = gender
            p.phone = phone
            p.doctor = doctor
            p.doctor_name = get_doctor_by_id(doctor) or "Não informado"
            p.prescription = prescription
            break
    save_patients(patients)

def save_patients(patients):
    patients_data = []
    for p in patients:
        patients_data.append({
            "id": p.id,
            "name": p.name,
            "age": p.age,
            "cpf": p.cpf,
            "gender": p.gender,
            "phone": p.phone,
            "doctor": p.doctor,
            "status": p.status,
            "prescription": p.prescription
        })
    with open(PATIENTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(patients_data, f, indent=4, ensure_ascii=False)

# Consultation Management

def save_consultation_text(patient_id, consultation_text, user_id):
    consults = {}
    if os.path.exists(CONSULTS_FILE):
        with open(CONSULTS_FILE, 'r', encoding='utf-8') as f:
            consults = json.load(f)
    pid = str(patient_id)
    consults.setdefault(pid, []).append(consultation_text)
    with open(CONSULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(consults, f, indent=4, ensure_ascii=False)

    package_info = get_package_info(user_id)
    update_package_usage(user_id, package_info['used'] + 1)


def get_consults(patient_id):
    if not os.path.exists(CONSULTS_FILE):
        return []
    with open(CONSULTS_FILE, 'r', encoding='utf-8') as f:
        consults = json.load(f)
    return consults.get(str(patient_id), [])

def delete_patient_record(patient_id):
    patients = [p for p in get_patients() if p.id != patient_id]
    save_patients(patients)
    if os.path.exists(CONSULTS_FILE):
        with open(CONSULTS_FILE, 'r', encoding='utf-8') as f:
            consults = json.load(f)
        consults.pop(str(patient_id), None)
        with open(CONSULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(consults, f, indent=4, ensure_ascii=False)

# Product Management

def get_products():
    if not os.path.exists(PRODUCTS_FILE):
        return []

    with open(PRODUCTS_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for product in data:
        if 'min_stock' not in product:
            product['min_stock'] = 5
    return data

def save_products(products):
    with open(PRODUCTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(products, f, ensure_ascii=False, indent=2)

def add_product(name, purchase_price, sale_price, quantity):
    products = get_products()
    next_id = max((p["id"] for p in products), default=0) + 1
    product = {
        "id": next_id,
        "name": name,
        "purchase_price": purchase_price,
        "sale_price": sale_price,
        "quantity": quantity,
        "status": "Ativo"
    }
    products.append(product)
    save_products(products)

def update_product_status(product_id, new_status):
    products = get_products()
    for p in products:
        if p['id'] == product_id:
            p['status'] = new_status
            break
    save_products(products)

def update_patient_status(patient_id, new_status):
    patients = get_patients()
    for p in patients:
        if p.id == patient_id:
            p.status = new_status
            break
    save_patients(patients)

# Doctor Management

def get_doctors():
    if not os.path.exists(DOCTORS_FILE):
        return []
    with open(DOCTORS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def get_doctor_by_id(doc_id):
    doctors = get_doctors()
    return next((d["name"] for d in doctors if d["id"] == doc_id), None)

def add_doctor_if_not_exists(doctor_name):
    doctors = get_doctors()
    for doc in doctors:
        if doc['name'].strip().lower() == doctor_name.strip().lower():
            return doc['id'], doc.get('phone', '')

    new_id = max((d['id'] for d in doctors), default=0) + 1
    new_doctor = {
        "id": new_id,
        "name": doctor_name,
        "phone": ""
    }
    doctors.append(new_doctor)

    with open(DOCTORS_FILE, "w", encoding="utf-8") as f:
        json.dump(doctors, f, indent=4, ensure_ascii=False)

    return new_id, ""

def update_doctor(doctor_id, name, phone):
    doctors = get_doctors()
    for doctor in doctors:
        if doctor['id'] == doctor_id:
            doctor['name'] = name
            doctor['phone'] = phone
            break
    with open(DOCTORS_FILE, 'w', encoding='utf-8') as f:
        json.dump(doctors, f, indent=4, ensure_ascii=False)


# Utility Functions

def get_patients_dict():
    return [
        {
            "id": p.id,
            "name": p.name,
            "age": p.age,
            "cpf": p.cpf,
            "gender": p.gender,
            "phone": p.phone,
            "doctor": p.doctor,
            "status": p.status,
            "doctor_name": p.doctor_name
        }
        for p in get_patients()
    ]

def count_completed_analysis():
    try:
        with open(CONSULTS_FILE, 'r', encoding='utf-8') as f:
            consults = json.load(f)
        total = sum(len(v) for v in consults.values())
        return total
    except FileNotFoundError:
        return 0

#Packages Management

def get_package_info(user_id):
    if not os.path.exists(PACKAGES_FILE):
        return {"total": 0, "used": 0}

    with open(PACKAGES_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    user_data = next((u for u in data['users'] if u['user_id'] == user_id), None)
    if user_data:
        return user_data
    else:
        return {"total": 50, "used": 0}  # starts with 50 free analysis
    
def update_package_usage(user_id, new_used_value):
    if not os.path.exists(PACKAGES_FILE):
        data = {"users": []}
    else:
        with open(PACKAGES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)

    for user in data['users']:
        if user['user_id'] == user_id:
            user['used'] = min(new_used_value, user['total'])
            break

    with open(PACKAGES_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def is_package_available(user_id):
    data = get_package_info(user_id)
    return data['total'] - data['used'] > 0

def update_prescription_in_consult(patient_id, new_prescription):
    import re

    if not os.path.exists(CONSULTS_FILE):
        return

    with open(CONSULTS_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    key = str(patient_id)
    if key not in data or not data[key]:
        return

    original = data[key][-1]
    updated = re.sub(r'Prescrição:(.|\n)*', f'Prescrição:\n{new_prescription.strip()}', original)

    data[key][-1] = updated

    with open(CONSULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

