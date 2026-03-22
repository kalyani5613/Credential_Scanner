import math
import hashlib
import re


# -----------------------------
# CONFIGURATION
# -----------------------------

MIN_LENGTH = 8
ENTROPY_THRESHOLD = 3.0


# -----------------------------
# HASH FUNCTION
# -----------------------------

def hash_value(value: str):

    return hashlib.sha256(value.encode()).hexdigest()


# -----------------------------
# ENTROPY CALCULATION
# -----------------------------

def shannon_entropy(data: str) -> float:

    if not data:
        return 0.0

    probabilities = [
        float(data.count(char)) / len(data)
        for char in set(data)
    ]

    return -sum(p * math.log2(p) for p in probabilities)


# -----------------------------
# TOKEN CLEANING
# -----------------------------

def clean_token(token: str):

    return token.strip(
        " \n\t\r,.:;()[]{}<>\"'"
    )


# -----------------------------
# SECRET-LIKE TOKEN FILTER
# -----------------------------

def looks_like_secret(token: str):

    # must contain at least one number
    if not re.search(r"[0-9]", token):
        return False

    # must contain uppercase OR symbol
    if not (
        re.search(r"[A-Z]", token)
        or re.search(r"[_\\-!@#$%^&*]", token)
    ):
        return False

    return True


# -----------------------------
# IGNORE STRUCTURED CREDENTIALS
# (handled by regex layer)
# -----------------------------

def is_structured_credential(token: str):

    if token.isdigit() and len(token) <= 6:
        return True

    if re.search(r"(?i)(password|pin|otp|cvv|code)", token):
        return True

    return False


# -----------------------------
# MAIN ENTROPY SCAN FUNCTION
# -----------------------------

def run_entropy_scan(text: str):

    findings = []

    tokens = re.split(r"\s+", text)

    for token in tokens:

        token = clean_token(token)

        if len(token) < MIN_LENGTH:
            continue

        if is_structured_credential(token):
            continue

        if not looks_like_secret(token):
            continue

        entropy = shannon_entropy(token)

        if entropy >= ENTROPY_THRESHOLD:

            findings.append({

                "credential_type": "high_entropy_secret",

                "value": token,

                "value_hash": hash_value(token),

                "confidence": round(entropy / 5, 2),

                "layer": "entropy",

                "risk_tier": "Medium",

                "description": "High-entropy string detected (possible secret)",

                "context_snippet": token,

                "redacted_value": token[:4] + "****"
            })

    return findings