# Stage 4 — ML Feature Scorer
# Extracts PE header features and produces ML-style risk score
# In production: trained sklearn RandomForest classifier
# Here: weighted feature scoring on known malware indicators

import math


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return round(
        -sum((c / length) * math.log2(c / length)
             for c in freq.values()), 3
    )


# Feature weights based on malware research
# Higher weight = stronger malware indicator
FEATURE_WEIGHTS = {
    "is_pe_file":             0,   # neutral — just classification
    "has_upx_packer":         15,
    "has_aspack_packer":      15,
    "has_themida":            20,
    "has_process_injection":  25,
    "has_keylogger_api":      30,
    "has_network_api":        20,
    "has_anti_debug":         20,
    "has_registry_write":     15,
    "has_service_creation":   20,
    "has_high_entropy":       15,
    "has_suspicious_section": 10,
    "filesize_very_small":    10,  # tiny PE = suspicious
    "filesize_very_large":     5,  # large PE = possible dropper
}


def extract_features(file_bytes: bytes) -> dict:
    """
    Extract binary features from PE file.
    Returns feature dict with boolean values.
    """
    if file_bytes[:2] != b"\x4d\x5a":
        return {"is_pe_file": False}

    content = file_bytes.decode("latin-1", errors="ignore")
    size    = len(file_bytes)

    return {
        "is_pe_file":             True,
        "has_upx_packer":         b"UPX" in file_bytes,
        "has_aspack_packer":      b"ASPack" in file_bytes,
        "has_themida":            b"Themida" in file_bytes,
        "has_process_injection":  any(
            api in content for api in
            ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
        ),
        "has_keylogger_api":      any(
            api in content for api in
            ["GetAsyncKeyState", "SetWindowsHookEx", "keybd_event"]
        ),
        "has_network_api":        any(
            api in content for api in
            ["InternetOpen", "InternetConnect", "HttpSendRequest"]
        ),
        "has_anti_debug":         any(
            api in content for api in
            ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
        ),
        "has_registry_write":     "RegSetValueEx" in content,
        "has_service_creation":   "CreateService" in content,
        "has_high_entropy":       calculate_entropy(
            file_bytes[:4096]
        ) > 7.0,
        "has_suspicious_section": calculate_entropy(
            file_bytes[-4096:]
        ) > 7.2,
        "filesize_very_small":    size < 1024,
        "filesize_very_large":    size > 10 * 1024 * 1024,
    }


def score(file_bytes: bytes) -> dict:
    """
    Calculate ML-style risk score from PE features.
    Returns score, label, and active features.
    """
    features = extract_features(file_bytes)

    if not features.get("is_pe_file"):
        return {
            "applicable": False,
            "score":      0,
            "label":      "Not a PE file — ML scoring not applicable",
            "features":   {},
        }

    total = sum(
        FEATURE_WEIGHTS.get(k, 0)
        for k, v in features.items()
        if v and k != "is_pe_file"
    )
    total = min(total, 100)

    if total >= 70:   label = "Likely malicious"
    elif total >= 40: label = "Suspicious"
    elif total > 0:   label = "Low-risk indicators present"
    else:             label = "Clean"

    active = {
        k: v for k, v in features.items()
        if v and k not in ("is_pe_file",)
    }

    return {
        "applicable": True,
        "score":      total,
        "label":      label,
        "features":   active,
    }