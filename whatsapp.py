import os
import re
import json
import requests
from typing import Optional, List
from difflib import get_close_matches

WHATSAPP_API_URL = "https://graph.facebook.com/v18.0"
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")

# Número padrão do admin (pode sobrescrever no .env)
ADMIN_WHATSAPP = os.getenv("ADMIN_WHATSAPP", "31985570920")


# --------------------------
# Helpers
# --------------------------
def _format_phone(msisdn: str) -> str:
    """
    Normaliza número para o formato internacional esperado pelo WhatsApp Cloud API.
    - Remove caracteres não numéricos.
    - Se for um celular do Brasil sem DDI (11 dígitos), prefixa 55.
    - Se já começa com DDI (ex.: 55...), mantém.
    """
    if not msisdn:
        return msisdn
    digits = re.sub(r"\D", "", msisdn)

    # já vem com DDI (ex.: 55XXXXXXXXXXX)
    if digits.startswith("55") and len(digits) in (12, 13):  # 12/13 por conta do 9º dígito
        return digits

    # número BR sem DDI (11 dígitos; ex.: 31985570920)
    if len(digits) == 11 and not digits.startswith("55"):
        return f"55{digits}"

    # se já vier com +, tira o + e mantém
    if msisdn.startswith("+"):
        return digits

    return digits


def _headers():
    return {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }


def _endpoint():
    if not WHATSAPP_PHONE_NUMBER_ID:
        raise RuntimeError("WHATSAPP_PHONE_NUMBER_ID não configurado")
    return f"{WHATSAPP_API_URL}/{WHATSAPP_PHONE_NUMBER_ID}/messages"


def _post_whatsapp(payload: dict) -> Optional[str]:
    """
    Envia o payload para o WhatsApp Cloud API.
    Retorna None em caso de sucesso, ou a string do erro em caso de falha.
    """
    if not WHATSAPP_TOKEN:
        return "WHATSAPP_TOKEN não configurado"
    if not WHATSAPP_PHONE_NUMBER_ID:
        return "WHATSAPP_PHONE_NUMBER_ID não configurado"

    try:
        resp = requests.post(_endpoint(), headers=_headers(), json=payload, timeout=30)
        if resp.status_code in (200, 201):
            return None
        return f"Erro WhatsApp ({resp.status_code}): {resp.text}"
    except Exception as e:
        return f"Erro de requisição WhatsApp: {e}"


# --------------------------
# Envio do relatório (já existente)
# --------------------------
def send_pdf_whatsapp(doctor_name, patient_name, analyzed_pdf_link, original_pdf_link):
    """
    Envia mensagem via template com os links do PDF analisado e original para o telefone do médico.
    Requer o template 'relatorio_BioO3' aprovado no WhatsApp Business.
    """
    # Carrega médicos
    try:
        with open("json/doctors.json", "r", encoding="utf-8") as file:
            doctors = json.load(file)
    except Exception as e:
        return f"Erro ao ler json/doctors.json: {e}"

    doctor_names = [d["name"] for d in doctors]
    matches = get_close_matches(doctor_name, doctor_names, n=1, cutoff=0.6)
    if not matches:
        return f"Doctor '{doctor_name}' not found in the system."

    doctor = next((d for d in doctors if d["name"] == matches[0]), None)
    if not doctor or not doctor.get("phone"):
        return f"Doctor '{matches[0]}' not found or phone not registered."

    phone_number = _format_phone(doctor["phone"])

    payload = {
        "messaging_product": "whatsapp",
        "to": phone_number,
        "type": "template",
        "template": {
            "name": "relatorio_BioO3",
            "language": {"code": "pt_BR"},
            "components": [
                {
                    "type": "body",
                    "parameters": [
                        {"type": "text", "text": doctor_name},
                        {"type": "text", "text": patient_name},
                        {"type": "text", "text": analyzed_pdf_link or "-"},
                        {"type": "text", "text": original_pdf_link or "-"},
                    ],
                }
            ],
        },
    }

    return _post_whatsapp(payload)


# --------------------------
# Envio de cotação a fornecedores (já existente)
# --------------------------
def send_quote_whatsapp(supplier_name, phone, quote_title, quote_items: List[str], response_url):
    """
    Envia mensagem via template com detalhes da cotação e link para responder.
    Requer o template 'cotacao_rafahmed' aprovado no WhatsApp Business.
    """
    if not phone:
        print("[ERRO] Telefone do fornecedor não informado.")
        return

    phone_fmt = _format_phone(phone)
    items_text = " | ".join([str(item).strip().replace("\n", " ").replace("\t", " ") for item in quote_items or []])

    payload = {
        "messaging_product": "whatsapp",
        "to": phone_fmt,
        "type": "template",
        "template": {
            "name": "cotacao_rafahmed",
            "language": {"code": "pt_BR"},
            "components": [
                {
                    "type": "body",
                    "parameters": [
                        {"type": "text", "text": supplier_name},
                        {"type": "text", "text": quote_title},
                        {"type": "text", "text": items_text or "-"},
                        {"type": "text", "text": response_url or "-"},
                    ],
                }
            ],
        },
    }

    err = _post_whatsapp(payload)
    if err:
        print(f"[Erro WhatsApp - {supplier_name}] {err}")
    else:
        print(f"[WhatsApp enviado] para {supplier_name} ({phone_fmt})")


# --------------------------
# Envio de comprovante PIX ao admin (NOVO)
# --------------------------
def send_pix_receipt_admin(
    admin_phone: Optional[str],
    user_name: str,
    user_id: int,
    user_email: str,
    plan: str,
    amount: float,
    txid: str,
    receipt_url: Optional[str] = None,
    payload_text: Optional[str] = None,
) -> Optional[str]:
    """
    Envia ao administrador (WhatsApp) os dados do pagamento PIX (texto) e,
    se houver, anexa o comprovante como documento (link).
    - admin_phone: número do admin (ex.: 31985570920). Se None, usa ADMIN_WHATSAPP do .env
    - receipt_url: link público do comprovante salvo em /static/pix_receipts/...
    - payload_text: payload/copia-e-cola do PIX (opcional, para facilitar conferência)
    Retorna None em sucesso, ou string de erro.
    """
    phone = _format_phone(admin_phone or ADMIN_WHATSAPP)
    if not phone:
        return "Número do admin não definido."

    # 1) Mensagem de texto com resumo
    lines = [
        "📎 *Novo comprovante PIX recebido*",
        f"👤 Usuário: {user_name} (ID: {user_id})",
        f"✉️ E-mail: {user_email or '-'}",
        f"📦 Plano: {plan.upper() if plan else '-'}",
        f"💵 Valor: R$ {amount:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."),
        f"🧾 TXID: {txid or '-'}",
    ]
    if payload_text:
        lines.append("\n🔑 *Payload (copia e cola)*:")
        # evitar mensagem gigante, mas ainda útil; corte se passar muito
        payload_preview = payload_text.strip()
        if len(payload_preview) > 1500:
            payload_preview = payload_preview[:1500] + "…"
        lines.append(payload_preview)

    text_body = "\n".join(lines)

    text_payload = {
        "messaging_product": "whatsapp",
        "to": phone,
        "type": "text",
        "text": {"preview_url": True, "body": text_body},
    }

    err = _post_whatsapp(text_payload)
    if err:
        return err

    # 2) Se houver link do comprovante, envia como documento
    if receipt_url:
        doc_payload = {
            "messaging_product": "whatsapp",
            "to": phone,
            "type": "document",
            "document": {
                "link": receipt_url,
                "caption": f"Comprovante PIX • {user_name} • Plano {plan.upper()}",
                # "filename": "comprovante.pdf"  # opcional: se for PDF
            },
        }
        err2 = _post_whatsapp(doc_payload)
        if err2:
            # não falha geral; apenas reporta log/erro de anexo
            return f"Resumo enviado, mas falhou enviar o documento: {err2}"

    return None
