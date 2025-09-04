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
    UserPackage,
)

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _product_to_dict(p: Product) -> dict:
    return {
        "id": p.id,
        "doctor_id": getattr(p, "doctor_id", None),
        "name": p.name,
        "code": getattr(p, "code", None),
        "purchase_price": p.purchase_price,
        "sale_price": p.sale_price,
        "quantity": p.quantity,
        "status": p.status,
        "category": getattr(p, "category", None),
        "application_route": getattr(p, "application_route", None),
        "min_stock": getattr(p, "min_stock", 0),
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }

# ---------------------------------------------------------------------
# USER
# ---------------------------------------------------------------------

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

# ---------------------------------------------------------------------
# COMPANY
# ---------------------------------------------------------------------

def get_company_by_id(company_id: int) -> Optional[Company]:
    return Company.query.get(company_id)

def get_company_by_access_code(access_code: str) -> Optional[Company]:
    return Company.query.filter_by(access_code=access_code).first()

def create_company(name: str, access_code: str) -> Company:
    c = Company(name=name, access_code=access_code)
    db.session.add(c)
    db.session.commit()
    return c

# ---------------------------------------------------------------------
# SUPPLIERS  (names used by app.py routes)
# ---------------------------------------------------------------------

def get_suppliers() -> List[Supplier]:
    return Supplier.query.order_by(Supplier.name).all()

def get_suppliers_by_user(user_id: int) -> List[Supplier]:
    return Supplier.query.filter_by(user_id=user_id).order_by(Supplier.name).all()

def add_supplier_db(name: str, phone: str, email: str, user_id: int) -> Supplier:
    s = Supplier(name=name, phone=phone, email=email, user_id=user_id)
    db.session.add(s)
    db.session.commit()
    return s

def update_supplier_db(supplier_id: int, name: str, phone: str, email: str, user_id: int) -> Optional[Supplier]:
    s = Supplier.query.filter_by(id=supplier_id, user_id=user_id).first()
    if not s:
        return None
    s.name = name
    s.phone = phone
    s.email = email
    db.session.commit()
    return s

def delete_supplier_db(supplier_id: int, user_id: int) -> bool:
    s = Supplier.query.filter_by(id=supplier_id, user_id=user_id).first()
    if not s:
        return False
    db.session.delete(s)
    db.session.commit()
    return True

# ---------------------------------------------------------------------
# QUOTES
# ---------------------------------------------------------------------

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

# ---------------------------------------------------------------------
# DOCTORS
# ---------------------------------------------------------------------

def add_doctor(name: str, phone: Optional[str]=None) -> Doctor:
    d = Doctor(name=name, phone=phone)
    db.session.add(d)
    db.session.commit()
    return d

def get_doctors() -> List[Doctor]:
    return Doctor.query.order_by(Doctor.name).all()

def get_doctor_by_id(doctor_id: int) -> Optional[Doctor]:
    return Doctor.query.get(doctor_id)

# ---------------------------------------------------------------------
# PATIENTS
# ---------------------------------------------------------------------

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

# ---------------------------------------------------------------------
# CONSULTS
# ---------------------------------------------------------------------

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

# ---------------------------------------------------------------------
# QUIZ RESULTS
# ---------------------------------------------------------------------

def add_quiz_result(**fields) -> QuizResult:
    # Normaliza 'fatores' para JSON string
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

    # Normaliza 'motivacao' para string
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

# ---------------------------------------------------------------------
# PACKAGES (DB instead of JSON)
# ---------------------------------------------------------------------

def _ensure_user_package(user_id: int) -> UserPackage:
    pkg = UserPackage.query.filter_by(user_id=user_id).first()
    if not pkg:
        pkg = UserPackage(user_id=user_id, total=50, used=0)
        db.session.add(pkg)
        db.session.commit()
    return pkg

def get_package_info(user_id: int) -> dict:
    pkg = _ensure_user_package(user_id)
    return {"total": pkg.total, "used": pkg.used}

def is_package_available(user_id: int) -> bool:
    info = get_package_info(user_id)
    return (info["total"] - info["used"]) > 0

def update_package_usage(user_id: int, new_used: int) -> None:
    pkg = _ensure_user_package(user_id)
    pkg.used = max(0, min(int(new_used or 0), int(pkg.total or 0)))
    db.session.commit()

# ---------------------------------------------------------------------
# PRODUCTS (DB instead of JSON)
# ---------------------------------------------------------------------

def get_products(doctor_id: Optional[int] = None) -> List[dict]:
    q = Product.query
    if doctor_id is not None:
        q = q.filter_by(doctor_id=doctor_id)
    products = q.order_by(Product.created_at.desc()).all()
    return [_product_to_dict(p) for p in products]

def save_products(products: List[dict]) -> None:
    """
    Back-compat helper: accept a list of dicts and upsert into DB.
    Does not delete products that aren't in the list.
    """
    if not isinstance(products, list):
        return

    for item in products:
        if not isinstance(item, dict):
            continue

        pid = item.get("id")
        doctor_id = item.get("doctor_id")
        name = (item.get("name") or "").strip()
        if not name:
            continue

        try:
            purchase_price = float(item.get("purchase_price", 0) or 0)
            sale_price     = float(item.get("sale_price", 0) or 0)
            quantity       = int(item.get("quantity", 0) or 0)
        except Exception:
            continue

        status    = (item.get("status") or "Ativo").strip() or "Ativo"
        code      = (item.get("code") or None) or None
        category  = (item.get("category") or None) or None
        app_route = (item.get("application_route") or None) or None
        min_stock = int(item.get("min_stock", 0) or 0)

        if pid:
            q = Product.query.filter_by(id=pid)
            if doctor_id is not None:
                q = q.filter_by(doctor_id=doctor_id)
            obj = q.first()
            if obj:
                obj.name = name
                obj.purchase_price = purchase_price
                obj.sale_price = sale_price
                obj.quantity = quantity
                obj.status = status
                if doctor_id is not None:
                    obj.doctor_id = doctor_id
                obj.code = code
                obj.category = category
                obj.application_route = app_route
                obj.min_stock = min_stock
            else:
                obj = Product(
                    name=name,
                    purchase_price=purchase_price,
                    sale_price=sale_price,
                    quantity=quantity,
                    status=status,
                    doctor_id=doctor_id,
                    code=code,
                    category=category,
                    application_route=app_route,
                    min_stock=min_stock,
                )
                db.session.add(obj)
        else:
            obj = Product(
                name=name,
                purchase_price=purchase_price,
                sale_price=sale_price,
                quantity=quantity,
                status=status,
                doctor_id=doctor_id,
                code=code,
                category=category,
                application_route=app_route,
                min_stock=min_stock,
            )
            db.session.add(obj)

    db.session.commit()

def update_product_status(product_id: int, doctor_id: int, new_status: str) -> None:
    p = Product.query.filter_by(id=product_id, doctor_id=doctor_id).first()
    if not p:
        abort(404, description="Produto não encontrado ou sem permissão")
    p.status = (new_status or "Ativo").strip() or "Ativo"
    db.session.commit()

def add_product(name: str, code: str, purchase_price: float, sale_price: float, quantity: int, doctor_id: int) -> dict:
    p = Product(
        name=name.strip(),
        code=code or None,
        purchase_price=float(purchase_price or 0),
        sale_price=float(sale_price or 0),
        quantity=int(quantity or 0),
        status="Ativo",
        doctor_id=doctor_id,
    )
    db.session.add(p)
    db.session.commit()
    return _product_to_dict(p)

def delete_product_record(product_id: int, doctor_id: int) -> bool:
    p = Product.query.filter_by(id=product_id, doctor_id=doctor_id).first()
    if not p:
        return False
    db.session.delete(p)
    db.session.commit()
    return True

def get_product_by_id(product_id: int, doctor_id: Optional[int] = None) -> Optional[dict]:
    q = Product.query.filter_by(id=product_id)
    if doctor_id is not None:
        q = q.filter_by(doctor_id=doctor_id)
    p = q.first()
    if not p:
        abort(404, description="Produto não encontrado ou sem permissão")
    return _product_to_dict(p)

def update_product(product_id: int, doctor_id: int, name, code, purchase_price, sale_price, quantity) -> dict:
    p = Product.query.filter_by(id=product_id, doctor_id=doctor_id).first()
    if not p:
        abort(404, description="Produto não encontrado ou sem permissão")

    # Sanitization / defaults
    name = (name or p.name).strip()
    code = code or None
    purchase_price = float(purchase_price if purchase_price is not None else p.purchase_price)
    sale_price = float(sale_price if sale_price is not None else p.sale_price)
    quantity = int(quantity if quantity is not None else p.quantity)

    p.name = name
    p.code = code
    p.purchase_price = purchase_price
    p.sale_price = sale_price
    p.quantity = quantity

    db.session.commit()
    return _product_to_dict(p)
