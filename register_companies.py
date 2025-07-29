#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from flask import Flask
from models import db, Company

def main():
    load_dotenv()

    # configure a minimal Flask app just to bind SQLAlchemy
    app = Flask(__name__)
    DATABASE_URL = os.getenv('DATABASE_URL') or 'sqlite:///web.db'
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # initialize the same db instance you use in models.py
    db.init_app(app)

    with app.app_context():
        # ensure tables exist
        db.create_all()

        print("=== Registro de nova Empresa ===")
        access_code = input("Código da empresa: ").strip()
        company_name = input("Nome da empresa: ").strip()

        if not (access_code and company_name):
            print("❌ Ambos os campos são obrigatórios.")
            return

        # check for duplicates
        exists = Company.query.filter_by(access_code=access_code).first()
        if exists:
            print(f"❌ Já existe uma empresa com o código “{access_code}”.")
            return

        # create and persist
        company = Company(name=company_name, access_code=access_code)
        db.session.add(company)
        db.session.commit()

        print(f"✔ Empresa “{company_name}” ({access_code}) registrada com sucesso! (ID: {company.id})")

if __name__ == "__main__":
    main()
