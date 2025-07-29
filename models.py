from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from typing import Optional

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  nullable=False, unique=True)
    email         = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    name          = db.Column(db.String(120))
    birthdate     = db.Column(db.Date)
    profile_image = db.Column(db.String(200), default='images/user-icon.png')
    company_id    = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=True)
    company       = db.relationship('Company', backref='users')

    def __init__(self, username: str, email: str, password_hash: str,
                 name: Optional[str] = None, birthdate: Optional[datetime] = None,
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
    id    = db.Column(db.Integer, primary_key=True)
    name  = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))

    def __init__(self, name: str, email: Optional[str] = None, phone: Optional[str] = None):
        self.name  = name
        self.email = email
        self.phone = phone

class Quote(db.Model):
    __tablename__ = 'quotes'
    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(200), nullable=False)
    items      = db.Column(db.Text, nullable=False)
    suppliers  = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, title: str, items: str, suppliers: str):
        self.title     = title
        self.items     = items
        self.suppliers = suppliers

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
    cpf          = db.Column(db.String(20), nullable=True)
    gender       = db.Column(db.String(20), nullable=True)
    phone        = db.Column(db.String(20), nullable=True)
    doctor_id    = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    prescription = db.Column(db.Text, nullable=True)
    status       = db.Column(db.String(20), default='Ativo', nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    doctor = db.relationship('Doctor', backref='patients')

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

    def __init__(self, patient_id: int, doctor_id: int, notes: Optional[str] = None):
        self.patient_id = patient_id
        self.doctor_id  = doctor_id
        self.notes      = notes

class QuizResult(db.Model):
    __tablename__ = 'quiz_results'

    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(100))
    age             = db.Column(db.String(10))
    date            = db.Column(db.Date, default=datetime.utcnow)
    # seus antigos
    ansiedade       = db.Column(db.String(50))
    depressao       = db.Column(db.String(50))
    estresse        = db.Column(db.String(50))
    qualidade       = db.Column(db.String(50))
    risco           = db.Column(db.String(50))
    # novas colunas
    nervosismo      = db.Column(db.String(50))
    preocupacao     = db.Column(db.String(50))
    interesse       = db.Column(db.String(50))
    sono            = db.Column(db.String(50))
    atividade_fisica= db.Column(db.String(50))
    fatores         = db.Column(db.Text)     # pode armazenar JSON ou comma‑separated
    motivacao       = db.Column(db.Text)
    hora_extra      = db.Column(db.String(50))
    pronto_socorro  = db.Column(db.String(20))
    relacionamentos = db.Column(db.String(50))
    hobbies         = db.Column(db.String(50))
    recomendacao    = db.Column(db.Text)

    doctor_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor          = db.relationship('User', backref='quiz_results')

    def __init__(self, name: str, age: str, date: Optional[datetime]=None,
                 ansiedade: Optional[str]=None, depressao: Optional[str]=None,
                 estresse: Optional[str]=None, qualidade: Optional[str]=None,
                 risco: Optional[str]=None,
                 nervosismo: Optional[str]=None, preocupacao: Optional[str]=None,
                 interesse: Optional[str]=None, sono: Optional[str]=None,
                 atividade_fisica: Optional[str]=None, fatores: Optional[str]=None,
                 motivacao: Optional[str]=None, hora_extra: Optional[str]=None,
                 pronto_socorro: Optional[str]=None, relacionamentos: Optional[str]=None,
                 hobbies: Optional[str]=None, recomendacao: Optional[str]=None,
                 doctor_id: Optional[int]=None):
        self.name             = name
        self.age              = age
        self.date             = date or datetime.utcnow()
        self.ansiedade        = ansiedade
        self.depressao        = depressao
        self.estresse         = estresse
        self.qualidade        = qualidade
        self.risco            = risco
        self.nervosismo       = nervosismo
        self.preocupacao      = preocupacao
        self.interesse        = interesse
        self.sono             = sono
        self.atividade_fisica = atividade_fisica
        self.fatores          = fatores
        self.motivacao        = motivacao
        self.hora_extra       = hora_extra
        self.pronto_socorro   = pronto_socorro
        self.relacionamentos  = relacionamentos
        self.hobbies          = hobbies
        self.recomendacao     = recomendacao
        self.doctor_id        = doctor_id
