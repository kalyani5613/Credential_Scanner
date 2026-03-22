# Stage 2e — Generic YARA-style Pattern Engine
# Matches suspicious strings across all file types
# 40+ patterns covering malware families

import re

YARA_RULES = [
    # Ransomware
    (b"your files have been encrypted", "Critical", "ransomware",
     "Ransomware note detected in file"),
    (b"pay the ransom",                 "Critical", "ransomware",
     "Ransom payment demand found"),
    (b"bitcoin",                        "High",     "ransomware",
     "Bitcoin payment reference — possible ransomware"),
    (b"decrypt your files",             "Critical", "ransomware",
     "File decryption offer — ransomware indicator"),

    # PowerShell obfuscation
    (b"invoke-expression",              "Critical", "powershell",
     "PowerShell Invoke-Expression — executes dynamic code"),
    (b"iex(",                           "Critical", "powershell",
     "IEX shorthand — obfuscated PowerShell execution"),
    (b"-noprofile",                     "High",     "powershell",
     "PowerShell no-profile flag — evasion technique"),
    (b"-executionpolicy bypass",        "Critical", "powershell",
     "Bypasses PowerShell execution policy"),
    (b"frombase64string",               "High",     "obfuscation",
     "Base64 decoding — common payload obfuscation"),

    # Persistence
    (b"net user /add",                  "Critical", "persistence",
     "Creates hidden user account"),
    (b"net localgroup administrators",  "Critical", "persistence",
     "Adds user to admin group — privilege escalation"),
    (b"schtasks /create",               "High",     "persistence",
     "Creates scheduled task — persistence mechanism"),
    (b"reg add",                        "High",     "persistence",
     "Adds registry entry — persistence mechanism"),

    # Evasion
    (b"netsh firewall",                 "High",     "evasion",
     "Modifies firewall rules — defence evasion"),
    (b"netsh advfirewall",              "High",     "evasion",
     "Advanced firewall modification"),
    (b"taskkill",                       "Medium",   "evasion",
     "Kills process — may target security tools"),
    (b"vssadmin delete shadows",        "Critical", "evasion",
     "Deletes volume shadow copies — ransomware technique"),
    (b"bcdedit",                        "High",     "evasion",
     "Modifies boot configuration — disables recovery"),

    # Network
    (b"wget ",                          "Medium",   "downloader",
     "File download command — possible dropper"),
    (b"curl ",                          "Medium",   "downloader",
     "File download command — possible dropper"),
    (b"ftp ",                           "Medium",   "exfiltration",
     "FTP command — possible data exfiltration"),

    # Script obfuscation
    (b"document.write",                 "Medium",   "script",
     "JS document write — injection technique"),
    (b"eval(",                          "High",     "obfuscation",
     "Eval execution — obfuscated script"),
    (b"unescape(",                      "High",     "obfuscation",
     "String unescaping — obfuscation technique"),
    (b"string.fromcharcode",            "High",     "obfuscation",
     "Char code obfuscation — hides malicious strings"),

    # Phishing
    (b"<iframe",                        "Medium",   "phishing",
     "Hidden iframe — common in phishing pages"),
    (b"password",                       "Low",      "credential",
     "Password reference found in file"),
    (b"enter your",                     "Low",      "phishing",
     "User input prompt — possible phishing form"),
      # Office macro patterns
    (b"autoopen",                       "Critical", "macro",
     "AutoOpen macro — executes when document opens"),
    (b"wscript.shell",                  "Critical", "macro",
     "WScript.Shell — executes system commands"),
    (b"urldownloadtofile",              "Critical", "downloader",
     "Downloads file from internet — dropper behaviour"),
    (b"document_open",                  "Critical", "macro",
     "Document_Open macro — auto-executes on open"),
    (b"workbook_open",                  "Critical", "macro",
     "Workbook_Open macro — auto-executes in Excel"),
    (b"cmd.exe",                        "Critical", "shell_exec",
     "CMD execution detected"),
    (b"powershell -enc",                "Critical", "powershell",
     "Encoded PowerShell — obfuscated command"),
    (b"powershell",                     "High",     "powershell",
     "PowerShell command detected"),
    (b"shell(",                         "High",     "shell_exec",
     "Shell execution function"),
    (b"createobject",                   "High",     "com_object",
     "COM object creation — system resource access"),
    (b"ddeauto",                        "Critical", "dde",
     "DDE auto-execute command"),
    (b"mshta",                          "Critical", "lolbin",
     "MSHTA execution — bypasses controls"),
    (b"regsvr32",                       "Critical", "lolbin",
     "Regsvr32 abuse — LOLBin technique"),
    (b"certutil",                       "High",     "lolbin",
     "CertUtil — can decode and download files"),
    (b"bitsadmin",                      "High",     "lolbin",
     "BITSAdmin — download utility abuse"),
]



def scan(file_bytes: bytes) -> list:
    findings   = []
    file_lower = file_bytes.lower()
    seen       = set()

    for (pattern, risk, category, desc) in YARA_RULES:
        pattern_lower = pattern.lower()
        if pattern_lower in file_lower:
            if pattern_lower in seen:
                continue
            seen.add(pattern_lower)

            pos   = file_lower.find(pattern_lower)
            start = max(0, pos - 30)
            end   = min(len(file_bytes), pos + 80)
            ctx   = file_bytes[start:end].decode(
                "latin-1", errors="ignore"
            ).replace("\x00", " ").strip()

            findings.append({
                "stage":       "YARA-style Pattern Engine",
                "rule":        pattern.decode("utf-8", errors="ignore"),
                "description": desc,
                "risk_tier":   risk,
                "category":    category,
                "context":     ctx[:80],
            })

    return findings