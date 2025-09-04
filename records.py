# records.py

import os
import json
from datetime import datetime, date
from typing import List, Optional, Tuple
from flask import abort
from models import (
    db,
    User,
    Company,
    Supplier,
    Quote,
    QuoteResponse,
    Doctor,
    Patient,
    Consult,
    QuizResult,
    Product,
)

BASE_DIR = os.path.dirname(__file__)
PACKAGES_FILE = os.path.join(BASE_DIR, 'json', 'packages.json')
PRODUCTS_FILE = os.path.join(BASE_DIR, 'json', 'products.json')

#
# ── USER ───────────────────────────────────────────────────────────────────────
#
def get_user_by_id(user_id: int) -> Optional[User]:
    return User.query.get(user_id)

def get_user_by_username(username: str) -> Optional[User]:
    return User.query.filter_by(username=username).first()

def create_user(
    username: str,
    email: str,
    password_hash: str,
    name: Optional[str] = None,
    birthdate: Optional[date] = None,
    profile_image: Optional[str] = None,
    company_id: Optional[int] = None
) -> User:
    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        name=name,
        birthdate=birthdate,
        profile_image=profile_image,
        company_id=company_id
    )
    db.session.add(user)
    db.session.commit()
    return user

#
# ── COMPANY ───────────────────────────────────────────────────────────────────
#
def get_company_by_id(company_id: int) -> Optional[Company]:
    return Company.query.get(company_id)

def get_company_by_access_code(access_code: str) -> Optional[Company]:
    return Company.query.filter_by(access_code=access_code).first()

def create_company(name: str, access_code: str) -> Company:
    c = Company(name=name, access_code=access_code)
    db.session.add(c)
    db.session.commit()
    return c

#
# ── SUPPLIER ──────────────────────────────────────────────────────────────────
#
def add_supplier_record(name: str, email: Optional[str]=None, phone: Optional[str]=None) -> Supplier:
    s = Supplier(name=name, email=email, phone=phone)
    db.session.add(s)
    db.session.commit()
    return s

def get_suppliers() -> List[Supplier]:
    return Supplier.query.order_by(Supplier.name).all()

#
# ── QUOTE & QUOTE RESPONSE ────────────────────────────────────────────────────
#
def add_quote(title: str, items: str, suppliers: str) -> Quote:
    q = Quote(title=title, items=items, suppliers=suppliers)
    db.session.add(q)
    db.session.commit()
    return q

def get_quotes() -> List[Quote]:
    return Quote.query.order_by(Quote.created_at.desc()).all()

def add_quote_response(quote_id: int, supplier_id: int, answers: str) -> QuoteResponse:
    r = QuoteResponse(quote_id=quote_id, supplier_id=supplier_id, answers=answers)
    db.session.add(r)
    db.session.commit()
    return r

def get_responses_by_quote(quote_id: int) -> List[QuoteResponse]:
    return (
        QuoteResponse.query
        .filter_by(quote_id=quote_id)
        .order_by(QuoteResponse.submitted_at)
        .all()
    )

#
# ── DOCTOR ────────────────────────────────────────────────────────────────────
#
def add_doctor(name: str, phone: Optional[str]=None) -> Doctor:
    d = Doctor(name=name, phone=phone)
    db.session.add(d)
    db.session.commit()
    return d

def get_doctors() -> List[Doctor]:
    return Doctor.query.order_by(Doctor.name).all()

def get_doctor_by_id(doctor_id: int) -> Optional[Doctor]:
    return Doctor.query.get(doctor_id)

#
# ── PATIENT ───────────────────────────────────────────────────────────────────
#
def add_patient(
    name: str,
    age: Optional[int],
    cpf: Optional[str],
    gender: Optional[str],
    phone: Optional[str],
    doctor_id: Optional[int],
    prescription: Optional[str]=None,
    status: str='Ativo'
) -> Patient:
    p = Patient(
        name=name,
        age=age,
        cpf=cpf,
        gender=gender,
        phone=phone,
        doctor_id=doctor_id,
        prescription=prescription,
        status=status
    )
    db.session.add(p)
    db.session.commit()
    return p


def get_patient_by_id(patient_id: int) -> Optional[Patient]:
    return Patient.query.get(patient_id)

def get_patients_by_doctor(doctor_id: int) -> List[Patient]:
    return (
        Patient.query
        .filter_by(doctor_id=doctor_id)
        .order_by(Patient.name)
        .all()
    )

def update_patient(
    patient_id: int,
    name: str,
    age: Optional[int],
    cpf: Optional[str],
    gender: Optional[str],
    phone: Optional[str],
    doctor_id: Optional[int], 
    prescription: Optional[str]=None,
    status: Optional[str]=None
) -> None:
    p = Patient.query.get(patient_id)
    if not p:
        return
    p.name         = name
    p.age          = age
    p.cpf          = cpf
    p.gender       = gender
    p.phone        = phone
    p.doctor_id    = doctor_id
    p.prescription = prescription
    if status is not None:
        p.status = status
    db.session.commit()


def delete_patient_record(patient_id: int) -> None:
    p = Patient.query.get(patient_id)
    if not p:
        return
    db.session.delete(p)
    db.session.commit()

#
# ── CONSULT ───────────────────────────────────────────────────────────────────
#
def add_consult(patient_id, doctor_id, notes, date=None, time=None):
    if date is None:
        date = datetime.utcnow().date()
        
    consult = Consult(patient_id=patient_id, doctor_id=doctor_id, notes=notes, date=date, time=time)
    db.session.add(consult)
    db.session.commit()
    return consult


def get_consults_by_patient(patient_id: int) -> List[Consult]:
    return (
        Consult.query
        .filter_by(patient_id=patient_id)
        .order_by(Consult.created_at)
        .all()
    )

def update_prescription_in_consult(patient_id: int, new_prescription: str) -> None:
    last = (
        Consult.query
        .filter_by(patient_id=patient_id)
        .order_by(Consult.created_at.desc())
        .first()
    )
    if not last or not last.notes:
        return
    import re
    last.notes = re.sub(
        r'(Prescrição:)(.|\n)*',
        f'Prescrição:\n{new_prescription.strip()}',
        last.notes
    )
    db.session.commit()

#
# ── QUIZ RESULT ──────────────────────────────────────────────────────────────
#
def add_quiz_result(**fields) -> QuizResult:
    # Garante que fatores seja uma string (JSON), nunca lista
    fatores = fields.get('fatores', [])
    if isinstance(fatores, list):
        fields['fatores'] = json.dumps(fatores)
    elif isinstance(fatores, str):
        try:
            json.loads(fatores)
            fields['fatores'] = fatores
        except Exception:
            fields['fatores'] = json.dumps([fatores])
    else:
        fields['fatores'] = json.dumps([])

    motivacao = fields.get('motivacao', [])
    if isinstance(motivacao, list):
        fields['motivacao'] = '; '.join(motivacao)
    elif isinstance(motivacao, str):
        fields['motivacao'] = motivacao
    else:
        fields['motivacao'] = ""

    q = QuizResult(**fields)
    db.session.add(q)
    db.session.commit()
    return q

def get_quiz_results_by_doctor(doctor_id: int) -> List[QuizResult]:
    return (
        QuizResult.query
        .filter_by(doctor_id=doctor_id)
        .order_by(QuizResult.date.desc())
        .all()
    )

def get_quiz_results_by_doctor_and_range(
    doctor_id: int,
    start_date: date,
    end_date: date
) -> List[QuizResult]:
    return (
        QuizResult.query
        .filter(
            QuizResult.doctor_id == doctor_id,
            db.func.date(QuizResult.date) >= start_date,
            db.func.date(QuizResult.date) <= end_date
        )
        .order_by(QuizResult.date)
        .all()
    )

#
# ── PACKAGE MANAGEMENT (JSON fallback) ─────────────────────────────────────────
#
def get_package_info(user_id: int) -> dict:
    if not os.path.exists(PACKAGES_FILE):
        return {"total": 50, "used": 0}
    with open(PACKAGES_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    user_data = next((u for u in data.get('users', []) if u['user_id'] == user_id), None)
    return user_data or {"total": 50, "used": 0}

def is_package_available(user_id: int) -> bool:
    info = get_package_info(user_id)
    return (info.get('total', 0) - info.get('used', 0)) > 0

def update_package_usage(user_id: int, new_used: int) -> None:
    data = {"users": []}
    if os.path.exists(PACKAGES_FILE):
        with open(PACKAGES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    users = data.get('users', [])
    for u in users:
        if u['user_id'] == user_id:
            u['used'] = min(new_used, u.get('total', 0))
            break
    else:
        users.append({"user_id": user_id, "total": 50, "used": new_used})
    data['users'] = users
    with open(PACKAGES_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

#
# ── PRODUCT MANAGEMENT (JSON fallback) ─────────────────────────────────────────
#
def get_products(doctor_id: Optional[int] = None) -> List[dict]:
    if not os.path.exists(PRODUCTS_FILE):
        return []
    with open(PRODUCTS_FILE, 'r', encoding='utf-8') as f:
        products = json.load(f)
    if doctor_id is not None:
        products = [p for p in products if p.get('doctor_id') == doctor_id]
    return products

def save_products(products: List[dict]) -> None:
    with open(PRODUCTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(products, f, indent=4, ensure_ascii=False)

def update_product_status(product_id: int, doctor_id: int, new_status: str) -> None:
    products = get_products()
    updated = False
    for p in products:
        if p.get('id') == product_id and p.get('doctor_id') == doctor_id:
            p['status'] = new_status
            updated = True
            break
    if not updated:
        abort(404, description="Produto não encontrado ou sem permissão")
    save_products(products)

def add_product(name: str, code: str, purchase_price: float, sale_price: float, quantity: int, doctor_id: int) -> dict:
    products = get_products()
    new_id = max((p.get('id', 0) for p in products), default=0) + 1
    prod = {
        "id": new_id,
        "name": name,
        "code": code,
        "purchase_price": purchase_price,
        "sale_price": sale_price,
        "quantity": quantity,
        "status": "Ativo",
        "doctor_id": doctor_id
    }
    products.append(prod)
    save_products(products)
    return prod

def get_product_by_id(product_id: int, doctor_id: Optional[int] = None) -> Optional[dict]:
    products = get_products()
    for p in products:
        if p.get('id') == product_id:
            if doctor_id is None or p.get('doctor_id') == doctor_id:
                return p
    abort(404, description="Produto não encontrado ou sem permissão")

def update_product(product_id: int, doctor_id: int, name, code, purchase_price, sale_price, quantity) -> dict:
    products = get_products()
    for p in products:
        if p.get('id') == product_id and p.get('doctor_id') == doctor_id:
            p['name'] = name
            p['code'] = code
            p['purchase_price'] = purchase_price
            p['sale_price'] = sale_price
            p['quantity'] = quantity
            save_products(products)
            return p 
    abort(404, description="Produto não encontrado ou sem permissão")

def get_suppliers_by_user(user_id: int):
    return Supplier.query.filter_by(user_id=user_id).order_by(Supplier.name).all()

def add_supplier_db(name: str, phone: str, email: str, user_id: int):
    supplier = Supplier(name=name, phone=phone, email=email, user_id=user_id)
    db.session.add(supplier)
    db.session.commit()
    return supplier

def update_supplier_db(supplier_id: int, name: str, phone: str, email: str, user_id: int):
    supplier = Supplier.query.filter_by(id=supplier_id, user_id=user_id).first()
    if supplier:
        supplier.name = name
        supplier.phone = phone
        supplier.email = email
        db.session.commit()
        return supplier
    return None

def delete_supplier_db(supplier_id: int, user_id: int):
    supplier = Supplier.query.filter_by(id=supplier_id, user_id=user_id).first()
    if supplier:
        db.session.delete(supplier)
        db.session.commit()
        return True
    return False

