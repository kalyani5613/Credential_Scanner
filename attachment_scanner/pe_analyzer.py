# Stage 2c — PE Header Analyzer
# Analyzes Windows executable structure for malicious indicators
# Checks imports, sections, entropy, packers

import math


SUSPICIOUS_IMPORTS = [
    ("VirtualAlloc",              "Critical", "process_injection",
     "Allocates executable memory — core process injection technique"),
    ("VirtualProtect",            "High",     "process_injection",
     "Changes memory permissions — used in shellcode injection"),
    ("WriteProcessMemory",        "Critical", "process_injection",
     "Writes into another process memory — classic RAT/trojan technique"),
    ("CreateRemoteThread",        "Critical", "process_injection",
     "Spawns thread in another process — process injection"),
    ("OpenProcess",               "High",     "process_access",
     "Opens handle to another process — surveillance/injection"),
    ("ReadProcessMemory",         "High",     "process_access",
     "Reads another process memory — credential theft"),
    ("SetWindowsHookEx",          "Critical", "keylogger",
     "Installs system-wide hook — keylogger technique"),
    ("GetAsyncKeyState",          "Critical", "keylogger",
     "Reads keyboard state — keylogger API"),
    ("keybd_event",               "High",     "keylogger",
     "Simulates keystrokes — input injection"),
    ("InternetOpen",              "High",     "network",
     "Opens internet connection — malware C2 communication"),
    ("InternetConnect",           "High",     "network",
     "Connects to remote server — data exfiltration"),
    ("HttpSendRequest",           "High",     "network",
     "Sends HTTP request — data exfiltration or C2"),
    ("RegSetValueEx",             "High",     "persistence",
     "Writes registry value — persistence mechanism"),
    ("RegCreateKey",              "High",     "persistence",
     "Creates registry key — persistence mechanism"),
    ("CreateService",             "Critical", "persistence",
     "Creates Windows service — persistent backdoor"),
    ("IsDebuggerPresent",         "High",     "anti_analysis",
     "Checks for debugger — anti-analysis evasion"),
    ("CheckRemoteDebuggerPresent","High",      "anti_analysis",
     "Checks for remote debugger — sandbox evasion"),
    ("GetTickCount",              "Medium",   "anti_analysis",
     "Timing check — used to detect sandbox slowdown"),
    ("NtQueryInformationProcess", "High",     "anti_analysis",
     "Low-level process query — rootkit/evasion technique"),
]

KNOWN_PACKERS = [
    (b"UPX",      "UPX packer — commonly used to compress and hide malware"),
    (b"ASPack",   "ASPack packer — executable compression"),
    (b"Themida",  "Themida protector — strong anti-analysis protection"),
    (b"PECompact","PECompact packer"),
    (b"MPRESS",   "MPRESS packer"),
]


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


def analyze(file_bytes: bytes) -> list:
    """
    Analyze PE (Windows executable) header and imports.
    Returns findings list.
    """
    findings = []

    # Only analyze PE files
    if file_bytes[:2] != b"\x4d\x5a":
        return findings

    content = file_bytes.decode("latin-1", errors="ignore")
    seen    = set()

    # Check suspicious imports
    for (api, risk, category, desc) in SUSPICIOUS_IMPORTS:
        if api in content:
            if api in seen:
                continue
            seen.add(api)
            findings.append({
                "stage":       "PE Header Analyzer",
                "rule":        api,
                "description": desc,
                "risk_tier":   risk,
                "category":    category,
            })

    # Check for packers
    for packer_bytes, packer_desc in KNOWN_PACKERS:
        if packer_bytes in file_bytes:
            findings.append({
                "stage":       "PE Header Analyzer",
                "rule":        packer_bytes.decode(),
                "description": packer_desc,
                "risk_tier":   "High",
                "category":    "packer",
            })

    # Check section entropy — high entropy = packed/encrypted
    if len(file_bytes) > 4096:
        sections = [
            file_bytes[i:i+512]
            for i in range(0, min(len(file_bytes), 8192), 512)
        ]
        for i, section in enumerate(sections):
            entropy = calculate_entropy(section)
            if entropy > 7.2:
                findings.append({
                    "stage":       "PE Header Analyzer",
                    "rule":        f"high_entropy_section_{i}",
                    "description": f"Section entropy {entropy} — likely packed or encrypted",
                    "risk_tier":   "High",
                    "category":    "packer",
                })
                break

    return findings