from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from typing import Optional

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(80),  nullable=False, unique=True, index=True)
    email           = db.Column(db.String(120), nullable=False, unique=True, index=True)
    password_hash   = db.Column(db.String(128), nullable=False)
    name            = db.Column(db.String(120))
    birthdate       = db.Column(db.Date)
    profile_image   = db.Column(db.String(200), default='images/user-icon.png')
    company_id      = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=True)
    company         = db.relationship('Company', backref='users')
    plan            = db.Column(db.String(20), default='standard')
    plan_status     = db.Column(db.String(20), default='inactive')
    plan_expires_at = db.Column(db.DateTime, nullable=True)
    trial_until     = db.Column(db.DateTime, nullable=True)

    def __init__(self, username: str, email: str, password_hash: str,
                 name: Optional[str] = None, birthdate: Optional[date] = None,
                 profile_image: Optional[str] = None, company_id: Optional[int] = None):
        self.username      = username
        self.email         = email
        self.password_hash = password_hash
        self.name          = name
        self.birthdate     = birthdate
        self.profile_image = profile_image or 'images/user-icon.png'
        self.company_id    = company_id


class Company(db.Model):
    __tablename__ = 'companies'
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    access_code = db.Column(db.String(50), unique=True, nullable=False)

    def __init__(self, name: str, access_code: str):
        self.name        = name
        self.access_code = access_code

    def __repr__(self) -> str:
        return f"<Company {self.name} ({self.access_code})>"


class Supplier(db.Model):
    __tablename__ = 'suppliers'
    id      = db.Column(db.Integer, primary_key=True)
    name    = db.Column(db.String(120), nullable=False)
    email   = db.Column(db.String(120))
    phone   = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    user    = db.relationship('User', backref='suppliers')

    def __init__(self, name: str, email: Optional[str] = None, phone: Optional[str] = None, user_id: Optional[int] = None):
        self.name    = name
        self.email   = email
        self.phone   = phone
        self.user_id = user_id


class Quote(db.Model):
    __tablename__ = 'quotes'
    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(200), nullable=False)
    items      = db.Column(db.Text, nullable=False)
    suppliers  = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), index=True, nullable=True)

    def __init__(self, title: str, items: str, suppliers: str, user_id: int | None = None):
        self.title     = title
        self.items     = items
        self.suppliers = suppliers
        self.user_id   = user_id


class QuoteResponse(db.Model):
    __tablename__ = 'quote_responses'
    id           = db.Column(db.Integer, primary_key=True)
    quote_id     = db.Column(db.Integer, db.ForeignKey('quotes.id'), nullable=False)
    supplier_id  = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=False)
    answers      = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, quote_id: int, supplier_id: int, answers: str):
        self.quote_id    = quote_id
        self.supplier_id = supplier_id
        self.answers     = answers


class Doctor(db.Model):
    __tablename__ = 'doctors'
    id    = db.Column(db.Integer, primary_key=True)
    name  = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=True)

    def __init__(self, name: str, phone: Optional[str] = None):
        self.name  = name
        self.phone = phone


class Patient(db.Model):
    __tablename__ = 'patients'
    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(120), nullable=False)
    age          = db.Column(db.Integer, nullable=True)
    cpf          = db.Column(db.String(20), nullable=True, index=True)
    gender       = db.Column(db.String(20), nullable=True)
    phone        = db.Column(db.String(20), nullable=True)
    doctor_id    = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=True)
    prescription = db.Column(db.Text, nullable=True)
    status       = db.Column(db.String(20), default='Ativo', nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    doctor       = db.relationship('Doctor', backref='patients')
    # One-to-one via QuizResult.patient_id
    quiz_result  = db.relationship('QuizResult', back_populates='patient', uselist=False)

    def __init__(self, name: str, age: Optional[int] = None, cpf: Optional[str] = None,
                 gender: Optional[str] = None, phone: Optional[str] = None,
                 doctor_id: Optional[int] = None, prescription: Optional[str] = None,
                 status: str = 'Ativo'):
        self.name         = name
        self.age          = age
        self.cpf          = cpf
        self.gender       = gender
        self.phone        = phone
        self.doctor_id    = doctor_id
        self.prescription = prescription
        self.status       = status


class Consult(db.Model):
    __tablename__ = 'consults'
    id         = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    doctor_id  = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    notes      = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    date       = db.Column(db.Date, nullable=False)
    time       = db.Column(db.Time, nullable=True)

    def __init__(self, patient_id: int, doctor_id: int, date, time=None, notes: Optional[str] = None):
        self.patient_id = patient_id
        self.doctor_id  = doctor_id
        self.date       = date
        self.time       = time
        self.notes      = notes


class QuizResult(db.Model):
    __tablename__ = 'quiz_results'

    id               = db.Column(db.Integer, primary_key=True)
    name             = db.Column(db.String(120))
    age              = db.Column(db.Integer)
    date             = db.Column(db.DateTime, default=datetime.utcnow)

    # — raw answers —
    consentimento     = db.Column(db.String(64))
    nivel_hierarquico = db.Column(db.String(64))
    setor             = db.Column(db.String(128))
    estresse_raw      = db.Column(db.String(64))
    nervosismo        = db.Column(db.String(50))
    preocupacao       = db.Column(db.String(50))
    interesse         = db.Column(db.String(50))
    depressao_raw     = db.Column(db.String(50))
    hora_extra        = db.Column(db.String(50))
    sono              = db.Column(db.String(50))
    atividade_fisica  = db.Column(db.String(50))
    fatores           = db.Column(db.PickleType)  # mantém compatibilidade
    motivacao         = db.Column(db.String(255))
    pronto_socorro    = db.Column(db.String(10))
    relacionamentos   = db.Column(db.String(50))
    hobbies           = db.Column(db.String(50))
    ansiedade         = db.Column(db.String(20))
    depressao         = db.Column(db.String(20))
    estresse          = db.Column(db.String(20))
    qualidade         = db.Column(db.String(20))
    risco             = db.Column(db.String(20))
    ansiedade_cor     = db.Column(db.String(7))
    depressao_cor     = db.Column(db.String(7))
    estresse_cor      = db.Column(db.String(7))
    qualidade_cor     = db.Column(db.String(7))
    risco_cor         = db.Column(db.String(7))
    recomendacao      = db.Column(db.String(255))

    doctor_id   = db.Column(db.Integer, db.ForeignKey('users.id'))
    patient_id  = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=True, unique=True)
    patient     = db.relationship('Patient', back_populates='quiz_result', uselist=False)

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)


class Product(db.Model):
    __tablename__ = 'products'
    id                = db.Column(db.Integer, primary_key=True)
    doctor_id         = db.Column(db.Integer, db.ForeignKey('users.id'), index=True, nullable=False)
    name              = db.Column(db.String(120), nullable=False)
    purchase_price    = db.Column(db.Float, nullable=False)
    sale_price        = db.Column(db.Float, nullable=False)
    quantity          = db.Column(db.Integer, nullable=False, default=0)
    status            = db.Column(db.String(20), default='Ativo', nullable=False)
    created_at        = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    code              = db.Column(db.String(64))
    category          = db.Column(db.String(80))
    application_route = db.Column(db.String(80))
    min_stock         = db.Column(db.Integer, default=0)

    owner = db.relationship('User', backref='products', foreign_keys=[doctor_id])

class UserPackage(db.Model):
    __tablename__ = 'user_packages'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, index=True, nullable=False)
    total      = db.Column(db.Integer, nullable=False, default=50)
    used       = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = db.relationship('User', backref='package_balance', foreign_keys=[user_id])


class DoctorAvailability(db.Model):
    __tablename__ = 'doctor_availability'
    id           = db.Column(db.Integer, primary_key=True)
    doctor_id    = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    weekday      = db.Column(db.Integer, nullable=False)
    start_time   = db.Column(db.Time, nullable=False)
    end_time     = db.Column(db.Time, nullable=False)
    slot_minutes = db.Column(db.Integer, nullable=False, default=30)

    doctor = db.relationship('Doctor', backref='availabilities')

    def __init__(self, doctor_id: int, weekday: int, start_time, end_time, slot_minutes: int = 30):
        self.doctor_id = doctor_id
        self.weekday = weekday
        self.start_time = start_time
        self.end_time = end_time
        self.slot_minutes = slot_minutes


class QuestionnaireResult(db.Model):
    __tablename__ = 'questionnaire_results'

    id          = db.Column(db.Integer, primary_key=True)
    created_at  = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    admin_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    admin       = db.relationship('User', backref='questionnaire_results', foreign_keys=[admin_id])

    name        = db.Column(db.String(180), nullable=True)
    age         = db.Column(db.String(30), nullable=True)
    sex         = db.Column(db.String(30), nullable=True)

    srq20_total           = db.Column(db.Integer, nullable=True)
    srq20_classification  = db.Column(db.String(120), nullable=True)
    srq20_items_yes       = db.Column(db.JSON, nullable=True)
    raw_payload           = db.Column(db.JSON, nullable=True)

    srq_q17     = db.Column(db.String(10), nullable=True)  # "Sim"/"Não"

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def br_date(self) -> str:
        dt = self.created_at or datetime.utcnow()
        return dt.strftime('%d/%m/%Y')

    def to_dict(self):
        return {
            "id": self.id,
            "data": self.br_date(),
            "admin_id": self.admin_id,
            "nome": self.name,
            "idade": self.age,
            "sexo": self.sex,
            "srq20_total": self.srq20_total,
            "srq20_classificacao": self.srq20_classification,
            "srq20_itens_sim": self.srq20_items_yes or [],
            "srq_q17": self.srq_q17,
            **(self.raw_payload or {})
        }


class DoctorDateAvailability(db.Model):
    __tablename__ = 'doctor_date_availability'
    id           = db.Column(db.Integer, primary_key=True)
    doctor_id    = db.Column(db.Integer, db.ForeignKey('doctors.id'), index=True, nullable=False)
    day          = db.Column(db.Date, index=True, nullable=False)
    start_time   = db.Column(db.Time, nullable=False)
    end_time     = db.Column(db.Time, nullable=False)
    slot_minutes = db.Column(db.Integer, nullable=False, default=30)

    def __init__(self, doctor_id: int, day, start_time, end_time, slot_minutes: int = 30):
        self.doctor_id = doctor_id
        self.day = day
        self.start_time = start_time
        self.end_time = end_time
        self.slot_minutes = slot_minutes


class SecureFile(db.Model):
    __tablename__ = "secure_files"

    id            = db.Column(db.Integer, primary_key=True)
    owner_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    kind          = db.Column(db.String(40),  nullable=False)
    filename      = db.Column(db.String(255), nullable=False)
    mime_type     = db.Column(db.String(100), nullable=False)
    size_bytes    = db.Column(db.Integer,     nullable=False)
    data          = db.Column(db.LargeBinary, nullable=False)  # ENCRYPTED
    created_at    = db.Column(db.DateTime,    default=datetime.utcnow, nullable=False)

    owner = db.relationship("User", backref="secure_files", foreign_keys=[owner_user_id])

    def __init__(self, owner_user_id, kind, filename, mime_type, size_bytes, data):
        self.owner_user_id = owner_user_id
        self.kind          = kind
        self.filename      = filename
        self.mime_type     = mime_type
        self.size_bytes    = size_bytes
        self.data          = data


class PdfFile(db.Model):
    __tablename__ = 'pdf_files'
    id            = db.Column(db.Integer, primary_key=True)
    filename      = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    size_bytes    = db.Column(db.Integer, nullable=False, default=0)
    uploaded_at   = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    secure_file_id = db.Column(db.Integer, db.ForeignKey('secure_files.id'), index=True, nullable=True)
    secure_file    = db.relationship('SecureFile', foreign_keys=[secure_file_id])

    def __init__(self, filename: str, original_name: str, size_bytes: int = 0, secure_file_id: Optional[int] = None):
        self.filename       = filename
        self.original_name  = original_name
        self.size_bytes     = size_bytes
        self.secure_file_id = secure_file_id
