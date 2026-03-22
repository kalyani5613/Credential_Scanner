# Stage 2a — PDF Stream Analyzer
# Scans PDF binary structure for dangerous objects
# WITHOUT opening or rendering the PDF

PDF_DANGEROUS_OBJECTS = [
    {
        "pattern":     b"/JavaScript",
        "risk":        "Critical",
        "description": "JavaScript code embedded in PDF — executes on open",
        "detail":      "Attackers embed JS to exploit PDF readers or download malware"
    },
    {
        "pattern":     b"/JS",
        "risk":        "Critical",
        "description": "JavaScript shorthand tag in PDF",
        "detail":      "Shorthand for /JavaScript — same risk level"
    },
    {
        "pattern":     b"/Launch",
        "risk":        "Critical",
        "description": "PDF Launch action — can execute any file on system",
        "detail":      "Can run cmd.exe, PowerShell or any executable silently"
    },
    {
        "pattern":     b"/OpenAction",
        "risk":        "High",
        "description": "PDF auto-execute action — triggers when document opens",
        "detail":      "Combined with /Launch or /JS creates drive-by execution"
    },
    {
        "pattern":     b"/AA",
        "risk":        "High",
        "description": "PDF additional actions — triggers on various user actions",
        "detail":      "Can trigger on page open, close, keystroke etc."
    },
    {
        "pattern":     b"/EmbeddedFile",
        "risk":        "High",
        "description": "File embedded inside PDF — hidden payload",
        "detail":      "Malware can be hidden inside PDFs as embedded files"
    },
    {
        "pattern":     b"/RichMedia",
        "risk":        "Medium",
        "description": "Rich media embedding — can contain Flash/video exploits",
        "detail":      "Historical attack vector via Flash vulnerabilities"
    },
    {
        "pattern":     b"/XFA",
        "risk":        "Medium",
        "description": "XFA form — XML-based forms that can contain scripts",
        "detail":      "XFA forms can execute JavaScript and make network requests"
    },
    {
        "pattern":     b"eval(",
        "risk":        "High",
        "description": "JavaScript eval() in PDF — executes dynamic code",
        "detail":      "Used to obfuscate malicious JavaScript payloads"
    },
    {
        "pattern":     b"unescape(",
        "risk":        "High",
        "description": "String unescaping in PDF JavaScript",
        "detail":      "Common obfuscation technique in malicious PDFs"
    },
    {
        "pattern":     b"/URI",
        "risk":        "Low",
        "description": "External URI reference in PDF",
        "detail":      "PDF links to external resource — may be phishing"
    },
    {
        "pattern":     b"/SubmitForm",
        "risk":        "Medium",
        "description": "Form submission action — can exfiltrate data",
        "detail":      "PDF can silently submit form data to attacker server"
    },
]


def analyze(file_bytes: bytes) -> list:
    """
    Scan PDF binary content for dangerous stream objects.
    Returns list of findings.
    """
    findings   = []
    file_lower = file_bytes.lower()
    seen       = set()

    for obj in PDF_DANGEROUS_OBJECTS:
        pattern = obj["pattern"].lower()
        if pattern in file_lower:
            if pattern in seen:
                continue
            seen.add(pattern)

            # Find position in file
            pos = file_lower.find(pattern)

            # Get surrounding context (100 bytes)
            start   = max(0, pos - 50)
            end     = min(len(file_bytes), pos + 100)
            context = file_bytes[start:end].decode(
                "latin-1", errors="ignore"
            ).replace("\x00", "")

            findings.append({
                "stage":       "PDF Stream Analyzer",
                "rule":        obj["pattern"].decode("utf-8", errors="ignore"),
                "description": obj["description"],
                "detail":      obj["detail"],
                "risk_tier":   obj["risk"],
                "category":    "pdf_threat",
                "position":    pos,
                "context":     context[:100],
            })

    return findings