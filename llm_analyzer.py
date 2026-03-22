import ollama
import json
import hashlib


MODEL = "llama3:latest"


# --------------------------------------------------
# SYSTEM PROMPT (forces strict structured detection)
# --------------------------------------------------

SYSTEM_PROMPT = """
You are a cybersecurity credential exposure detection engine.

Return ONLY valid JSON.
No markdown.
No explanation.
Start with { and end with }.

Detect:

STRUCTURED CREDENTIALS:
- password
- pin
- otp
- email
- username
- api key
- token
- credit card
- bank account
- pan
- aadhaar

PHISHING SIGNALS:
- urgency language
- suspension threats
- impersonation
- credential verification requests

Return ONLY this JSON format:

{
  "credential_findings": [
    {
      "type": "password",
      "description": "Password exposed",
      "risk_tier": "High",
      "evidence": "Password: Passw0rd123",
      "confidence": 0.95
    }
  ],
  "phishing_signals": [
    "urgency language detected"
  ]
}
"""


# --------------------------------------------------
# HASH FUNCTION
# --------------------------------------------------

def hash_value(value: str):
    return hashlib.sha256(value.encode()).hexdigest()


# --------------------------------------------------
# NORMALIZE TYPES FOR PIPELINE COMPATIBILITY
# --------------------------------------------------

def normalize_credential_type(label):

    label = label.lower().strip()

    mapping = {

        "password": "password_plain",
        "pin": "pin_number",
        "otp": "otp_code",
        "credit card": "credit_card",
        "card": "credit_card",
        "account number": "bank_account",
        "bank account": "bank_account",
        "iban": "bank_account",
        "pan": "india_pan",
        "aadhaar": "india_aadhaar",
        "api key": "api_key",
        "token": "auth_token",
        "email": "email_address",
        "username": "username_field"
    }

    return mapping.get(label, label.replace(" ", "_"))


# --------------------------------------------------
# MAIN ENTRY FUNCTION
# --------------------------------------------------

def run_llm_scan(text: str) -> list:

    trimmed = text[:1200]

    try:

        response = ollama.chat(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": f"""
Extract ALL credentials and phishing signals from this email.

STRICT RULES:
- Always return JSON
- Never skip credentials
- Include urgency/suspension warnings

EMAIL:
{trimmed}
"""
                }
            ],
            options={
                "temperature": 0.0,
                "num_predict": 700,
                "num_ctx": 2048,
            }
        )

        raw = response["message"]["content"].strip()

        print("\n====== LLM RESPONSE ======\n", raw, "\n==========================\n")

        return parse_llm_response(raw)

    except Exception as e:

        print("LLM scan error:", e)

        return []


# --------------------------------------------------
# PARSER (SAFE + RELIABLE)
# --------------------------------------------------

def parse_llm_response(raw: str) -> list:

    try:

        start = raw.find("{")
        end = raw.rfind("}") + 1

        if start == -1 or end <= start:
            print("LLM returned non-JSON output")
            return []

        data = json.loads(raw[start:end])

    except Exception as e:

        print("LLM JSON parse failed:", e)
        return []

    findings = []

    # ---------------------------
    # credential findings
    # ---------------------------

    for item in data.get("credential_findings", []):

        evidence = str(item.get("evidence", "")).strip()

        if not evidence:
            continue

        cred_type = normalize_credential_type(
            str(item.get("type", "llm_detected"))
        )

        findings.append({

            "layer": "llm",

            "credential_type": cred_type,

            "description": item.get(
                "description",
                f"LLM detected {cred_type}"
            ),

            "risk_tier": item.get("risk_tier", "High"),

            "category": "llm_detected",

            "redacted_value": evidence[:4] + "****",

            "value_hash": hash_value(evidence),

            "context_snippet": evidence,

            "char_position": 0,

            "confidence": float(item.get("confidence", 0.9)),

            "llm_detected": True
        })


    # ---------------------------
    # phishing signals
    # ---------------------------

    signals = data.get("phishing_signals", [])

    if signals:

        combined = "; ".join(signals[:3])

        findings.append({

            "layer": "llm",

            "credential_type": "phishing_intent",

            "description": combined,

            "risk_tier": "High",

            "category": "phishing",

            "redacted_value": "N/A",

            "value_hash": hash_value(combined),

            "context_snippet": combined,

            "char_position": 0,

            "confidence": 0.9,

            "llm_detected": True
        })

    return findings


# --------------------------------------------------
# OPTIONAL: CHECK OLLAMA STATUS
# --------------------------------------------------

def check_ollama_running() -> bool:

    try:
        ollama.list()
        return True
    except Exception:
        return False