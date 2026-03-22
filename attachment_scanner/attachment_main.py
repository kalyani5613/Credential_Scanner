# Attachment Scanner — Main Entry Point
# Orchestrates all 5 stages

import re

from .magic_detector  import detect
from .pdf_analyzer    import analyze as analyze_pdf
from .office_analyzer import analyze as analyze_office
from .pe_analyzer     import analyze as analyze_pe
from .zip_analyzer    import analyze as analyze_zip
from .pattern_engine  import scan    as scan_patterns
from .hash_checker    import check   as check_hash
from .ml_scorer       import score   as ml_score


def extract_urls(file_bytes: bytes) -> list:
    try:
        text = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        text = file_bytes.decode("latin-1", errors="ignore")

    url_re   = re.compile(r"https?://[^\s\"\'<>,;()\[\]{}]{4,200}")
    all_urls = url_re.findall(text)

    safe = [
        "microsoft.com", "adobe.com", "w3.org",
        "schema.org", "openxmlformats.org", "xmlsoap.org",
    ]

    suspicious = [
        u for u in all_urls
        if not any(s in u.lower() for s in safe)
    ]
    return list(set(suspicious))[:10]


def calculate_final_risk(
    all_findings: list,
    file_type:    dict,
    hash_result:  dict,
    ml_result:    dict,
    urls:         list,
    filename:     str,
) -> dict:
    from .magic_detector import HIGH_RISK_EXTENSIONS, MEDIUM_RISK_EXTENSIONS

    ext   = file_type.get("declared_extension", "")
    score = 0

    if hash_result.get("known_malware"):
        score += 100

    if ext in HIGH_RISK_EXTENSIONS:
        score += 50

    if ext in MEDIUM_RISK_EXTENSIONS:
        score += 20

    if file_type.get("extension_mismatch"):
        score += 40

    tier_pts = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3}
    for f in all_findings:
        score += tier_pts.get(f.get("risk_tier", "Low"), 3)

    if ml_result.get("applicable"):
        score += ml_result.get("score", 0) // 5

    score += len(urls) * 8
    score  = min(score, 100)

    if score >= 80:   label = "Critical"
    elif score >= 60: label = "High"
    elif score >= 40: label = "Medium"
    elif score > 0:   label = "Low"
    else:             label = "Clean"

    return {"score": score, "label": label}


def build_summary(
    findings:    list,
    file_type:   dict,
    hash_result: dict,
    ml_result:   dict,
    urls:        list,
) -> str:
    parts = []

    if hash_result.get("known_malware"):
        parts.append(
            f"KNOWN MALWARE: {hash_result['known_malware']}"
        )

    if file_type.get("extension_mismatch"):
        parts.append(
            f"Extension mismatch — "
            f"{file_type['mismatch_desc']}"
        )

    if findings:
        cats = list(set(f.get("category", "") for f in findings))
        parts.append(
            f"{len(findings)} suspicious pattern(s): "
            f"{', '.join(cats)}"
        )

    if ml_result.get("applicable") and ml_result.get("score", 0) > 40:
        parts.append(
            f"ML classifier: {ml_result['label']} "
            f"(score {ml_result['score']})"
        )

    if urls:
        parts.append(f"{len(urls)} suspicious embedded URL(s)")

    if not parts:
        parts.append("No threats detected — file appears clean")

    return ". ".join(parts) + "."


def analyze_attachment(file_bytes: bytes, filename: str) -> dict:
    """
    Run complete 5-stage static analysis pipeline.
    Safe — file is never executed at any point.
    """
    ext = ("." + filename.lower().rsplit(".", 1)[-1]
           if "." in filename else "")

    # Stage 1 — file type detection
    file_type = detect(file_bytes, filename)

    # Stage 2 — sub-analyzers based on file type
    all_findings = []

      # Start findings — include mismatch as first finding if detected
    if file_type.get("extension_mismatch"):
        all_findings = [{
            "stage":       "File Type Detection",
            "rule":        "extension_mismatch",
            "description": file_type["mismatch_desc"],
            "risk_tier":   "Critical",
            "category":    "evasion",
        }]
    else:
        all_findings = []

    if (ext == ".pdf" or
            file_bytes[:4] == b"\x25\x50\x44\x46"):
        all_findings += analyze_pdf(file_bytes)

    if ext in (".doc", ".xls", ".ppt", ".docx", ".xlsx",
               ".pptx", ".docm", ".xlsm", ".pptm"):
        all_findings += analyze_office(file_bytes, filename)

    if file_bytes[:2] == b"\x4d\x5a":
        all_findings += analyze_pe(file_bytes)

    if file_bytes[:4] == b"\x50\x4b\x03\x04":
        all_findings += analyze_zip(file_bytes)

    # Always run generic pattern scan
    all_findings += scan_patterns(file_bytes)

    # Stage 3 — hash check
    hash_result = check_hash(file_bytes)

    # Stage 4 — ML scoring
    ml_result = ml_score(file_bytes)

    # Stage 5 — URL extraction
    urls = extract_urls(file_bytes)

    # Final risk
    risk = calculate_final_risk(
        all_findings, file_type, hash_result, ml_result, urls, filename
    )

    def count(tier):
        return sum(1 for f in all_findings if f.get("risk_tier") == tier)

    return {
        "module":           "Malicious Attachment Analyzer",
        "filename":         filename,
        "file_size_kb":     file_type["file_size_kb"],
        "stages": {
            "stage_1_file_type":    file_type,
            "stage_2_findings":     all_findings,
            "stage_3_hash":         hash_result,
            "stage_4_ml":           ml_result,
            "stage_5_urls":         urls,
        },
        "total_findings":   len(all_findings),
        "critical_count":   count("Critical"),
        "high_count":       count("High"),
        "medium_count":     count("Medium"),
        "low_count":        count("Low"),
        "risk_score":       risk["score"],
        "risk_label":       risk["label"],
        "human_summary":    build_summary(
            all_findings, file_type, hash_result, ml_result, urls
        ),
    }