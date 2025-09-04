import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

# Function to guarantee good values
def get_env_str(var_name: str, default: str = "") -> str:
    value = os.getenv(var_name, default)
    if value is None or value.strip() == "":
        raise EnvironmentError(f"Variável de ambiente obrigatória ausente: {var_name}")
    return value

def get_env_int(var_name: str, default: int) -> int:
    value = os.getenv(var_name)
    try:
        return int(value) if value is not None else default
    except ValueError:
        raise ValueError(f"Valor inválido para {var_name}, deve ser um número inteiro.")

# Load variables validating securely
SMTP_SERVER: str = get_env_str("SMTP_SERVER")
SMTP_PORT: int = get_env_int("SMTP_PORT", 587)
SMTP_USERNAME: str = get_env_str("SMTP_USERNAME")
SMTP_PASSWORD: str = get_env_str("SMTP_PASSWORD")
EMAIL_FROM: str = get_env_str("EMAIL_FROM")

def send_email_quote(recipient_email: str, subject: str, body: str):
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, recipient_email, msg.as_string())
        print(f"E-mail enviado para {recipient_email}")
    except Exception as e:
        print(f"Erro ao enviar e-mail: {e}")
