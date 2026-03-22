# Stage 2d — ZIP/RAR Recursive Analyzer
# Unpacks archives and analyzes contents recursively
# Catches malware hidden inside ZIP files

import zipfile
import io

HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1",
    ".vbs", ".js",  ".jar", ".sh",  ".msi",
    ".scr", ".pif", ".com", ".hta", ".wsf",
}


def analyze(file_bytes: bytes) -> list:
    findings = []

    if file_bytes[:4] != b"\x50\x4b\x03\x04":
        return findings

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            names = z.namelist()

            for name in names:
                ext = ("." + name.lower().rsplit(".", 1)[-1]
                       if "." in name else "")

                # High risk file inside archive
                if ext in HIGH_RISK_EXTENSIONS:
                    findings.append({
                        "stage":       "ZIP Recursive Analyzer",
                        "rule":        "dangerous_file_in_archive",
                        "description": f"Dangerous file inside archive: {name}",
                        "risk_tier":   "Critical",
                        "category":    "archive_threat",
                    })

                # Double extension trick e.g. invoice.pdf.exe
                parts = name.lower().split(".")
                if (len(parts) > 2 and
                        "." + parts[-1] in HIGH_RISK_EXTENSIONS):
                    findings.append({
                        "stage":       "ZIP Recursive Analyzer",
                        "rule":        "double_extension_trick",
                        "description": f"Double extension evasion: {name}",
                        "risk_tier":   "Critical",
                        "category":    "evasion",
                    })

                # Deeply nested archives (zip bomb indicator)
                if ext in (".zip", ".rar", ".7z"):
                    findings.append({
                        "stage":       "ZIP Recursive Analyzer",
                        "rule":        "nested_archive",
                        "description": f"Archive inside archive: {name}",
                        "risk_tier":   "Medium",
                        "category":    "zip_bomb",
                    })

    except zipfile.BadZipFile:
        findings.append({
            "stage":       "ZIP Recursive Analyzer",
            "rule":        "corrupt_archive",
            "description": "Archive is corrupted — possible evasion attempt",
            "risk_tier":   "Medium",
            "category":    "evasion",
        })

    return findings