#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from getpass import getpass
from flask import Flask
from werkzeug.security import generate_password_hash
from models import db, User, Company

def main():
    load_dotenv()

    app = Flask(__name__)

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
    os.makedirs(base_dir, exist_ok=True)
    DATABASE_URL = os.getenv('DATABASE_URL') or f'sqlite:///{os.path.join(base_dir, "web.db")}'
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    db.init_app(app)

    with app.app_context():
        print("=== Registro de novo usuário ===")
        username = input("Nome de usuário: ").strip()
        email    = input("E‑mail         : ").strip()
        password = getpass("Senha          : ").strip()
        confirm  = getpass("Confirme senha : ").strip()

        if not (username and email and password):
            print("❌ Todos os campos são obrigatórios.")
            return

        if password != confirm:
            print("❌ Senhas não conferem.")
            return

        db.create_all()

        exists = User.query.filter(
            (User.username == username) | (User.email == email)  # type: ignore
        ).first()
        if exists:
            print("❌ Usuário ou e‑mail já cadastrado.")
            return

        companies = Company.query.order_by(Company.id).all()
        if not companies:
            print("⚠️ Nenhuma empresa encontrada. Criando empresa padrão...")
            existing = Company.query.filter_by(access_code="DEFAULT").first()
            if not existing:
                company = Company(name="Empresa Padrão", access_code="DEFAULT")
                db.session.add(company)
                db.session.commit()
            else:
                company = existing
        else:
            print("\nEmpresas disponíveis:")
            for c in companies:
                print(f"  {c.id} - {c.name} (código: {c.access_code})")

            try:
                company_id = int(input("\nDigite o ID da empresa para vincular o usuário: ").strip())
                company = Company.query.get(company_id)
                if not company:
                    print("❌ Empresa não encontrada.")
                    return
            except ValueError:
                print("❌ ID inválido.")
                return

        hashed = generate_password_hash(password)
        user = User(username=username, email=email, password_hash=hashed, company_id=company.id)
        db.session.add(user)
        db.session.commit()

        print(f"✔ Usuário “{username}” registrado com sucesso! (ID: {user.id}, Empresa: {company.name})")

if __name__ == "__main__":
    main()
