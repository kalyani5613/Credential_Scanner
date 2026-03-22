from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
import hashlib


# -----------------------------
# MODEL CONFIGURATION
# -----------------------------

MODEL_NAME = "SoelMgd/bert-pii-detection"

print("[NER] Loading transformer PII model...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForTokenClassification.from_pretrained(MODEL_NAME)

ner_pipeline = pipeline(
    "ner",
    model=model,
    tokenizer=tokenizer,
    aggregation_strategy="simple"
)

print("[NER] Model loaded successfully")


# -----------------------------
# HASH FUNCTION
# -----------------------------

def hash_value(value: str):
    return hashlib.sha256(value.encode()).hexdigest()


# -----------------------------
# LABEL MAPPING
# -----------------------------

LABEL_MAP = {

    "EMAIL": "email_address",

    "PHONE": "phone_number",

    "PERSON": "person_name",

    "ID": "national_id",

    "USERNAME": "username_field"
}


# -----------------------------
# TEXT CHUNKING (for long emails)
# -----------------------------

def chunk_text(text, size=400):

    return [
        text[i:i + size]
        for i in range(0, len(text), size)
    ]


# -----------------------------
# MAIN NER SCAN FUNCTION
# -----------------------------

def run_ner_scan(text: str):

    findings = []

    text_lower = text.lower()

    chunks = chunk_text(text)

    for chunk in chunks:

        results = ner_pipeline(chunk)

        for entity in results:

            label = entity["entity_group"]

            confidence = float(entity["score"])

            value = entity["word"].strip()


            # -----------------------------
            # FILTER LOW CONFIDENCE
            # -----------------------------

            if confidence < 0.60:
                continue


            # -----------------------------
            # FILTER SHORT TOKENS
            # -----------------------------

            if len(value) < 4:
                continue


            # -----------------------------
            # REMOVE FALSE SSN DETECTIONS
            # -----------------------------

            if label == "SSN":
                continue


            # -----------------------------
            # REMOVE PURE NUMERIC STRINGS
            # (prevents PIN / random number noise)
            # -----------------------------

            if value.replace(" ", "").isdigit():
                continue


            # -----------------------------
            # MAP LABEL → PIPELINE TYPE
            # -----------------------------

            credential_type = LABEL_MAP.get(
                label,
                label.lower()
            )


            # -----------------------------
            # CONTEXT BOOSTING
            # (helps email detection reliability)
            # -----------------------------

            if "email" in text_lower and "@" in value:
                credential_type = "email_address"

            if "phone" in text_lower:
                credential_type = "phone_number"

            if "name" in text_lower:
                credential_type = "person_name"


            # -----------------------------
            # ADD FINDING
            # -----------------------------

            findings.append({

                "credential_type": credential_type,

                "value": value,

                "value_hash": hash_value(value),

                "confidence": confidence,

                "layer": "ner",

                "risk_tier": "Medium",

                "description": f"Detected {label} using transformer NER",

                "context_snippet": value,

                "redacted_value": "[REDACTED]"
            })


    return findings