from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings
from detect_secrets.core.scan import scan_line
import hashlib


def hash_value(value: str):
    return hashlib.sha256(value.encode()).hexdigest()


def run_detect_secrets_scan(text: str):

    findings = []

    with transient_settings({}):

        for line_number, line in enumerate(text.splitlines(), start=1):

            results = scan_line(line)

            for secret in results:

                findings.append({

                    "credential_type": secret.type.lower().replace(" ", "_"),

                    "value": "[REDACTED]",

                    "value_hash": hash_value(secret.type),

                    "confidence": 0.95,

                    "layer": "detect_secrets",

                    "risk_tier": "High",

                    "description": f"Detected {secret.type}",

                    "context_snippet": line[:120],

                    "redacted_value": "[REDACTED]"
                })

    return findings