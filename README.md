<p align="center">
  <img src="https://github.com/user-attachments/assets/b469ab49-3469-446a-88bb-ef08bb297837" alt="RafahMed logo" width="300">
</p>

<h1 align="center">RafahMed</h1>

<p align="center">

RafahMed is a mental healthcare platform for conducting health assessments, analyzing patient results, and supporting clinical follow-up.

The application helps healthcare professionals share mental health screening questionnaires, review the submitted results, maintain patient records, and organize follow-up consultations. The current interface is written in Brazilian Portuguese.

> **Important:** RafahMed's questionnaires are screening tools, not diagnostic instruments. Their results should be interpreted by a qualified healthcare professional.

## How RafahMed works

1. A healthcare professional creates an account and signs in.
2. From the assessment area, the professional generates a questionnaire link for a patient or employee.
3. The participant reviews the consent notice and completes the assessment.
4. RafahMed scores the answers and securely associates the result with the professional's account.
5. The professional reviews individual or aggregate results, downloads PDF reports, and plans any necessary follow-up.

## Assessments

RafahMed currently supports two assessment experiences:

- **Emotional health self-assessment:** evaluates indicators related to anxiety, depression, stress, quality of life, and overall risk.
- **SRQ-20:** the World Health Organization's 20-question Self-Reporting Questionnaire, used to screen for common mental disorders. It includes consent handling, automatic scoring, and an immediate safety message when the self-harm item is answered positively.

Assessment responses can be viewed individually or as an overview, linked to patient records, and exported as PDF reports.

## Supporting features

- Patient profiles and consultation history
- Appointment scheduling and professional availability
- Dashboard summaries and assessment trends
- Individual and aggregate PDF reports
- Secure file storage with encrypted contents and signed links
- Company accounts and access codes
- Subscription plans and PIX or Mercado Pago payment flows
- Optional Google Calendar, email, and WhatsApp integrations
- Inventory, supplier, and quotation management
- Training materials and videos

## Technology

- Python and Flask
- SQLAlchemy and Flask-Migrate
- SQLite by default, with PostgreSQL support through `DATABASE_URL`
- Jinja templates, HTML, CSS, and JavaScript
- WeasyPrint for PDF generation
- Fernet encryption for protected files

## Project structure

```text
RafahMed/
├── Logos/                 # Brand assets
├── Web/
│   ├── app.py             # Flask application and routes
│   ├── models.py          # Database models
│   ├── records.py         # Data-access helpers
│   ├── prescription.py    # PDF and prescription helpers
│   ├── email_utils.py     # Email integration
│   ├── whatsapp.py        # WhatsApp integration
│   ├── mercado_pago.py    # Payment integration
│   ├── migrations/        # Database migrations
│   ├── static/            # CSS, JavaScript, images, and uploads
│   └── templates/         # Jinja HTML templates
└── README.md
```

## Running locally

### Requirements

- Python 3.10 or newer
- `pip` and a Python virtual environment
- Native WeasyPrint dependencies if you need PDF generation

### 1. Create a virtual environment

```bash
cd Web
python3 -m venv .venv
source .venv/bin/activate
```

On Windows, activate it with:

```powershell
.venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure the environment

Create a `Web/.env` file. At minimum, RafahMed requires a Fernet encryption key:

```env
FILE_ENC_KEY=replace-with-a-fernet-key
APP_SECRET_KEY=replace-with-a-long-random-secret
FLASK_DEBUG=1
```

Generate suitable values with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
python -c "import secrets; print(secrets.token_hex(32))"
```

Use the first output for `FILE_ENC_KEY` and the second for `APP_SECRET_KEY`. Keep both values private and stable; changing the Fernet key prevents previously encrypted files from being read, while changing the application secret invalidates existing sessions and signed links.

### 4. Start the application

```bash
python app.py
```

Then open `http://127.0.0.1:5000`. When no `DATABASE_URL` is provided, the app uses a local SQLite database and creates missing tables automatically.

## Configuration

The main environment variables are:

| Variable | Purpose | Required |
| --- | --- | --- |
| `FILE_ENC_KEY` | Encrypts protected files | Yes |
| `APP_SECRET_KEY` | Signs sessions and temporary file links | Recommended |
| `DATABASE_URL` | Overrides the default SQLite database | No |
| `FLASK_DEBUG` | Enables Flask debug mode when set to `1` | No |
| `GOOGLE_CLIENT_SECRET_JSON` | Enables Google Calendar OAuth | No |
| `MERCADO_PAGO_ACCESS_TOKEN` | Enables Mercado Pago checkout | No |
| `SMTP_SERVER`, `SMTP_PORT` | Configure the email server | No |
| `SMTP_USERNAME`, `SMTP_PASSWORD`, `EMAIL_FROM` | Authenticate and send email | No |
| `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_TOKEN` | Enable WhatsApp messages | No |
| `AUTO_WHATSAPP_ENABLED` | Enables automatic WhatsApp sending | No |
| `PIX_KEY`, `PIX_NAME`, `PIX_CITY`, `PIX_DESC` | Customize PIX payments | No |
| `ADMIN_WHATSAPP` | Sets the destination for payment receipts | No |
| `QUOTES_SECTION_ENABLED` | Enables the supplier quotation section | No |

Only enable integrations after their credentials have been configured. Never commit `.env`, database files, access tokens, patient data, or uploaded documents to source control.

Because RafahMed handles sensitive health information, any production deployment should also use HTTPS, strict access controls, encrypted backups, audit logging, and privacy practices appropriate to the applicable regulations, including Brazil's LGPD where relevant.
