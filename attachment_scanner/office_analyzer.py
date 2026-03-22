# Stage 2b — Office Macro Extractor
# Detects VBA macros, DDE commands, and malicious scripts
# in Word, Excel, PowerPoint files

import zipfile
import io

MACRO_SIGNATURES = [
    {
        "pattern":     b"AutoOpen",
        "risk":        "Critical",
        "description": "Auto-run macro executes when document opens",
        "category":    "auto_execute"
    },
    {
        "pattern":     b"Document_Open",
        "risk":        "Critical",
        "description": "Document open event macro — auto-executes",
        "category":    "auto_execute"
    },
    {
        "pattern":     b"Workbook_Open",
        "risk":        "Critical",
        "description": "Workbook open macro — executes in Excel",
        "category":    "auto_execute"
    },
    {
        "pattern":     b"Auto_Open",
        "risk":        "Critical",
        "description": "XLM auto-open macro in Excel",
        "category":    "auto_execute"
    },
    {
        "pattern":     b"DDEAUTO",
        "risk":        "Critical",
        "description": "DDE auto-execute — runs commands via Office DDE",
        "category":    "dde"
    },
    {
        "pattern":     b"WScript.Shell",
        "risk":        "Critical",
        "description": "WScript.Shell object — executes system commands",
        "category":    "shell_exec"
    },
    {
        "pattern":     b"Shell(",
        "risk":        "High",
        "description": "VBA Shell function — runs external programs",
        "category":    "shell_exec"
    },
    {
        "pattern":     b"powershell",
        "risk":        "High",
        "description": "PowerShell invocation found in macro",
        "category":    "powershell"
    },
    {
        "pattern":     b"powershell -enc",
        "risk":        "Critical",
        "description": "Encoded PowerShell — obfuscated command execution",
        "category":    "powershell"
    },
    {
        "pattern":     b"-windowstyle hidden",
        "risk":        "Critical",
        "description": "Hidden PowerShell window — stealth execution",
        "category":    "powershell"
    },
    {
        "pattern":     b"cmd.exe",
        "risk":        "Critical",
        "description": "CMD execution found in macro",
        "category":    "shell_exec"
    },
    {
        "pattern":     b"URLDownloadToFile",
        "risk":        "Critical",
        "description": "Downloads file from internet — dropper behaviour",
        "category":    "downloader"
    },
    {
        "pattern":     b"CreateObject",
        "risk":        "High",
        "description": "Creates COM object — used to access system resources",
        "category":    "com_object"
    },
    {
        "pattern":     b"HKEY_",
        "risk":        "High",
        "description": "Registry access in macro — persistence mechanism",
        "category":    "persistence"
    },
    {
        "pattern":     b"regsvr32",
        "risk":        "Critical",
        "description": "Regsvr32 abuse — LOLBin used to bypass defences",
        "category":    "lolbin"
    },
    {
        "pattern":     b"mshta",
        "risk":        "Critical",
        "description": "MSHTA execution — runs HTA files, bypasses controls",
        "category":    "lolbin"
    },
    {
        "pattern":     b"certutil",
        "risk":        "High",
        "description": "CertUtil — can decode base64 and download files",
        "category":    "lolbin"
    },
    {
        "pattern":     b"bitsadmin",
        "risk":        "High",
        "description": "BITSAdmin — Windows download utility abuse",
        "category":    "lolbin"
    },
    {
        "pattern":     b"VBA",
        "risk":        "Medium",
        "description": "VBA macro code present in document",
        "category":    "macro_present"
    },
    {
        "pattern":     b"Environ(",
        "risk":        "Low",
        "description": "Reads environment variables — reconnaissance",
        "category":    "recon"
    },
]


def analyze(file_bytes: bytes, filename: str) -> list:
    """
    Extract and analyze Office macros and dangerous commands.
    Handles both legacy .doc/.xls and modern .docx/.xlsx formats.
    """
    findings      = []
    ext           = ("." + filename.lower().rsplit(".", 1)[-1]
                     if "." in filename else "")
    content       = file_bytes
    seen          = set()

    # Modern Office files are ZIP archives
    # Unpack and scan all internal XML/binary content
    if ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
        try:
            all_content = b""
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                for name in z.namelist():
                    try:
                        all_content += z.read(name)
                    except Exception:
                        pass
            content = all_content
        except Exception:
            pass

    content_lower = content.lower()

    for sig in MACRO_SIGNATURES:
        pattern = sig["pattern"].lower()
        if pattern in content_lower:
            if pattern in seen:
                continue
            seen.add(pattern)

            pos     = content_lower.find(pattern)
            start   = max(0, pos - 30)
            end     = min(len(content), pos + 80)
            context = content[start:end].decode(
                "latin-1", errors="ignore"
            ).replace("\x00", " ").strip()

            findings.append({
                "stage":       "Office Macro Extractor",
                "rule":        sig["pattern"].decode("utf-8", errors="ignore"),
                "description": sig["description"],
                "risk_tier":   sig["risk"],
                "category":    sig["category"],
                "context":     context[:80],
            })

    return findings