import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

def _smtp_config():
    smtp_server = (os.getenv("SMTP_SERVER") or "").strip()
    smtp_port_raw = (os.getenv("SMTP_PORT") or "").strip()
    smtp_username = (os.getenv("SMTP_USERNAME") or "").strip()
    smtp_password = (os.getenv("SMTP_PASSWORD") or "").strip()
    email_from = (os.getenv("EMAIL_FROM") or "").strip()

    missing = []
    if not smtp_server:
        missing.append("SMTP_SERVER")
    if not smtp_username:
        missing.append("SMTP_USERNAME")
    if not smtp_password:
        missing.append("SMTP_PASSWORD")
    if not email_from:
        missing.append("EMAIL_FROM")
    if missing:
        raise EnvironmentError(f"Variáveis SMTP ausentes: {', '.join(missing)}")

    try:
        smtp_port = int(smtp_port_raw) if smtp_port_raw else 587
    except ValueError as e:
        raise ValueError("SMTP_PORT inválida, use número inteiro.") from e

    return smtp_server, smtp_port, smtp_username, smtp_password, email_from

def send_email_quote(recipient_email: str, subject: str, body: str):
    try:
        smtp_server, smtp_port, smtp_username, smtp_password, email_from = _smtp_config()
    except Exception as e:
        print(f"Config SMTP inválida: {e}")
        return

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = email_from
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(email_from, recipient_email, msg.as_string())
        print(f"E-mail enviado para {recipient_email}")
    except Exception as e:
        print(f"Erro ao enviar e-mail: {e}")
