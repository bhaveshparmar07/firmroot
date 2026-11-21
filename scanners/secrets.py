"""
Firmroot - High-signal Deterministic Secrets & Credential Scanner
"""
import re
import os
from typing import List, Dict, Any

SECRET_RULES = [
    {
        "id": "SEC-001",
        "name": "Hardcoded RSA/DSA/EC Private Key",
        "pattern": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "confidence": "HIGH"
    },
    {
        "id": "SEC-002",
        "name": "Hardcoded Unix Password Hash in Shadow/Passwd",
        "pattern": re.compile(r"(?:root|admin|user):(\$[156]\$[a-zA-Z0-9./]{8,64})"),
        "confidence": "HIGH"
    },
    {
        "id": "SEC-003",
        "name": "Hardcoded Default Password Assignment in Script",
        "pattern": re.compile(r"(?i)(?:password|passwd|pwd)\s*=\s*['\"]([a-zA-Z0-9@#$%^&*-_!]{4,32})['\"]"),
        "confidence": "MEDIUM"
    },
    {
        "id": "SEC-004",
        "name": "Cloud / API Token (AWS / Generic Access Key)",
        "pattern": re.compile(r"(?:AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z\\-_]{35})"),
        "confidence": "HIGH"
    },
    {
        "id": "SEC-005",
        "name": "Embedded Telnet/SSH Hardcoded Credentials in NVRAM or Config",
        "pattern": re.compile(r"(?i)(?:admin_password|http_passwd|telnet_pwd)\s*[:=]\s*([^\s\r\n]+)"),
        "confidence": "HIGH"
    }
]

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf",
    ".bin", ".rom", ".img", ".o", ".so", ".a", ".ko", ".gz", ".tar", ".xz"
}

def scan_secrets(root_dir: str) -> List[Dict[str, Any]]:
    findings = []
    
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in BINARY_EXTENSIONS:
                continue
                
            file_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(file_path, root_dir)
            
            try:
                # Read with fallback for decoding
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    
                for rule in SECRET_RULES:
                    for match in rule["pattern"].finditer(content):
                        # Calculate line number
                        start_pos = match.start()
                        line_number = content.count('\n', 0, start_pos) + 1
                        
                        # Extract a safe snippet
                        matched_snippet = match.group(0)
                        if len(matched_snippet) > 120:
                            matched_snippet = matched_snippet[:120] + "...[truncated]"
                            
                        findings.append({
                            "check_type": "SECRET",
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "file_path": rel_path.replace("\\", "/"),
                            "line_number": line_number,
                            "evidence_snippet": matched_snippet,
                            "confidence": rule["confidence"]
                        })
            except Exception:
                continue
                
    return findings
