import os
import mercadopago
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

access_token = os.getenv("MERCADO_PAGO_ACCESS_TOKEN")
sdk = mercadopago.SDK(access_token)


def generate_payment_link(package, amount):
    """
    Generates a Mercado Pago payment link for the given package and amount.
    """
    preference_data = {
        "items": [
            {
                "title": f"Pacote de {package} análises - Ponza Lab",
                "quantity": 1,
                "currency_id": "BRL",
                "unit_price": float(amount)
            }
        ],
        "back_urls": {
            "success": "https://RafahMed.com/payments/success",
            "failure": "https://RafahMed.com/payments/failure",
            "pending": "https://RafahMed.com/payments/pending"
        },
        "auto_return": "approved"
    }

    preference_response = sdk.preference().create(preference_data)
    print("=== MERCADO PAGO RESPONSE ===")
    print(preference_response)
    print("================================")

    if preference_response['status'] == 201:
        return preference_response['response'].get('init_point', '')
    else:
        return ''
