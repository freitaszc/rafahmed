import os
import re
import json
import logging
from datetime import datetime
from PyPDF2 import PdfReader

logger = logging.getLogger(__name__)


# ---------------------------
# I/O helpers
# ---------------------------
def read_pdf(file_path: str) -> list[str]:
    try:
        reader = PdfReader(file_path)
        text = "".join(page.extract_text() or "" for page in reader.pages)
        return [line.strip() for line in text.splitlines() if line.strip()]
    except Exception as e:
        logger.error(f"Error reading PDF: {e}")
        return []


def read_references(references_path: str) -> dict | None:
    try:
        with open(references_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception as e:
        logger.error(f"Error reading references: {e}")
        return None


# ---------------------------
# Parsing helpers
# ---------------------------
def parse_min_max(ideal_text: str) -> tuple[float | None, float | None]:
    """
    Accepts strings like:
      - ">= 40", "> 40"
      - "<= 120", "< 120"
      - "40 - 60" or "40–60"
      - "50" (single fixed value)
    Returns (min_val, max_val) using None when unparseable.
    """
    try:
        ideal_text = ideal_text.strip().split("\n")[0]

        # ≥ or >
        if match := re.match(r"(≥|>=|>)\s*([\d.,]+)", ideal_text):
            return float(match.group(2).replace(",", ".")), float("inf")

        # ≤ or <
        if match := re.match(r"(≤|<=|<)\s*([\d.,]+)", ideal_text):
            return float("-inf"), float(match.group(2).replace(",", "."))

        # range
        if match := re.search(r"([\d.,]+)\s*[-–]\s*([\d.,]+)", ideal_text):
            return float(match.group(1).replace(",", ".")), float(match.group(2).replace(",", "."))

        # single number
        if match := re.search(r"([\d.,]+)", ideal_text):
            v = float(match.group(1).replace(",", "."))
            return v, v

        return None, None
    except Exception:
        return None, None


def detect_gender(lines: list[str], fallback_name: str = "") -> str:
    """
    Try to read 'Sexo: M/F' from the document; otherwise fallback based on name heuristic.
    """
    for line in lines:
        if m := re.search(r"Sexo[:\s]+([MF])", line, re.IGNORECASE):
            return m.group(1).upper()
    # crude name-based fallback
    return "M" if any(x in fallback_name.upper() for x in [" JOÃO ", " PAULO ", " NICOLAS ", " LUCAS ", " GABRIEL "]) else "F"


def extract_patient_info(lines: list[str]) -> tuple[str, str, int, str, str, str]:
    """
    Tries to extract: name, gender, age, cpf, phone (if present—kept blank), doctor
    """
    name, birth_date, age, cpf, phone, doctor = "", "", 0, "", "", ""

    for line in lines:
        # Name + birthdate + (age anos)
        if m := re.match(r"^([A-Z\s]+)\s+(\d{2}/\d{2}/\d{4})\s+\((\d+)\s+anos\)", line):
            name, birth_date = m.group(1).strip().title(), m.group(2)
            try:
                bd = datetime.strptime(birth_date, "%d/%m/%Y")
                today = datetime.today()
                age = today.year - bd.year - ((today.month, today.day) < (bd.month, bd.day))
            except Exception:
                age = 0

        # CPF
        if m := re.search(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", line):
            cpf = m.group()

        # Doctor
        if "CRM-" in line and (m := re.search(r"([A-Z\s\.]+)\s*-\s*CRM", line)):
            doctor = m.group(1).strip().title()

    gender = detect_gender(lines, name)
    return name, gender, age, cpf, phone, doctor


def normalize_number(s: str) -> float | None:
    try:
        return float(s.replace(",", ".").replace(">", "").replace("<", "").strip())
    except ValueError:
        return None


def scan_results(lines: list[str], references: dict, gender: str) -> dict:
    """
    For each referenced test, search across a sliding window of 3 lines for
    synonyms and a numeric value, then compare to the ideal range.
    """
    results: dict = {}
    normalized_lines = [line.lower() for line in lines]

    for test_name, info in references.items():
        synonyms = [s.lower() for s in info.get("synonyms", [])] + [test_name.lower()]
        found = False

        for i in range(len(normalized_lines)):
            window = " ".join(normalized_lines[i:i + 3])  # bigger context window
            for synonym in synonyms:
                if synonym in window:
                    # capture value + optional unit (mg/dL, %, etc.)
                    m = re.search(r"([<>]?\s*\d+(?:[.,]\d+)?)(?:\s*[a-zA-Z/%]+)?", window)
                    value = normalize_number(m.group(1)) if m else None

                    # gender-aware ideal (dict) or single ideal (str)
                    ideal = info.get("ideal", {}).get(gender) if isinstance(info.get("ideal"), dict) else info.get("ideal")
                    min_val, max_val = parse_min_max(str(ideal)) if ideal is not None else (None, None)

                    meds = []
                    if value is not None and min_val is not None:
                        if value < min_val:
                            meds = info.get("medications", {}).get("low", [])
                        elif max_val is not None and value > max_val:
                            meds = info.get("medications", {}).get("high", [])

                    results[test_name] = {
                        "value": value,
                        "line": " ".join(lines[i:i + 3]).strip(),
                        "ideal": ideal,
                        "medications": meds,
                    }
                    found = True
                    break
            if found:
                break

        if not found:
            results[test_name] = {"value": None, "line": None, "ideal": None, "medications": []}

    return results


# ---------------------------
# High level builders
# ---------------------------
def build_diagnosis_and_prescriptions(results: dict) -> tuple[str, str]:
    diagnosis_text = ""
    prescriptions: list[dict] = []

    for test, info in results.items():
        value, ideal, meds = info["value"], info["ideal"], info["medications"]
        if value is None or ideal is None:
            continue

        min_val, max_val = parse_min_max(str(ideal))
        if min_val is None or max_val is None:
            continue

        if value < min_val:
            diagnosis_text += f"{test}: valor {value} ABAIXO do valor ideal ({ideal}).\n"
            prescriptions.extend([{"test": test, **med} for med in meds])
        elif value > max_val:
            diagnosis_text += f"{test}: valor {value} ACIMA do valor ideal ({ideal}).\n"
            prescriptions.extend([{"test": test, **med} for med in meds])
        else:
            diagnosis_text += f"{test}: valor {value} está dentro do valor ideal ({ideal}).\n"

    # Dedup by med name (case-insensitive)
    seen: set[str] = set()
    prescription_lines: list[str] = []
    for med in prescriptions:
        key = med["nome"].strip().lower()
        if key not in seen:
            seen.add(key)
            prescription_lines.append(
                f"- {med['nome']}\nPreparo: {med['preparo']}\nAplicação: {med['aplicacao']}\n"
            )

    return diagnosis_text.strip(), "\n".join(prescription_lines).strip()


# ---------------------------
# Orchestrators
# ---------------------------
def analyze_pdf(source: str, references_path: str = "json/references.json", manual: bool = False):
    """
    Always returns 8-tuple:
      diagnosis, prescriptions, name, gender, age, cpf, phone, doctor
    """
    references = read_references(references_path)
    if not references:
        return "Error: could not load references.", "", "", "", 0, "", "", ""

    if manual:
        # `source` is raw text pasted by the user
        lines = [l.strip() for l in source.splitlines() if l.strip()]
        gender = "F"  # consider taking this from UI
        results = scan_results(lines, references, gender)
        diagnosis, prescriptions = build_diagnosis_and_prescriptions(results)
        return diagnosis, prescriptions, "", gender, 0, "", "", ""

    # `source` is a file path
    lines = read_pdf(source)
    if not lines:
        return "Error reading PDF.", "", "", "", 0, "", "", ""

    text = "\n".join(lines)

    # Special-case for Biocell / Diagnósticos do Brasil
    if "Diagnósticos do Brasil" in text or "Drª. Christiany" in text:
        return analyze_pdf_biocell(text, references_path)

    name, gender, age, cpf, phone, doctor = extract_patient_info(lines)
    results = scan_results(lines, references, gender)
    diagnosis, prescriptions = build_diagnosis_and_prescriptions(results)

    return diagnosis, prescriptions, name, gender, age, cpf, phone, doctor


def analyze_pdf_biocell(text: str, references_path: str = "json/references.json"):
    """
    Variant parser for certain providers. Returns the same 8-tuple.
    """
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    name = re.sub(r"\bCAD\d*\b$", "", lines[0], flags=re.IGNORECASE).strip().title() if lines else "Unknown"

    cpf_match = re.search(r"C\.?P\.?F\.?\s+(\d{3}\.\d{3}\.\d{3}-\d{2})", text)
    cpf = cpf_match.group(1) if cpf_match else ""

    birth_date_match = re.search(r"D\.?N\.?\s+(\d{2}/\d{2}/\d{4})", text)
    birth_date = birth_date_match.group(1) if birth_date_match else ""
    try:
        birth_date_dt = datetime.strptime(birth_date, "%d/%m/%Y")
        today = datetime.today()
        age = today.year - birth_date_dt.year - ((today.month, today.day) < (birth_date_dt.month, birth_date_dt.day))
    except Exception:
        age = 0

    doctor_match = re.search(r"Dr[ªa\.]*\s+([A-ZÁÉÍÓÚÇ][^\n]+?)(?:CRF|CPF)", text, re.IGNORECASE)
    doctor = doctor_match.group(1).strip() if doctor_match else ""

    references = read_references(references_path)
    if not references:
        return "Error: could not load references.", "", name, "", age, cpf, "", doctor

    results = scan_results(lines, references, gender="")
    diagnosis, prescriptions = build_diagnosis_and_prescriptions(results)

    return diagnosis, prescriptions, name, "", age, cpf, "", doctor
