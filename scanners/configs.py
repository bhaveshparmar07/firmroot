"""
Firmroot - Insecure Configuration & Service Check
"""
import os
import re
from typing import List, Dict, Any

INSECURE_DAEMONS = [
    {
        "daemon": "telnetd",
        "pattern": re.compile(r"(?:^|\s|/)(telnetd)(?:\s|$)", re.IGNORECASE),
        "risk": "Unencrypted Telnet daemon spawned in startup script",
        "severity": "HIGH"
    },
    {
        "daemon": "ftpd",
        "pattern": re.compile(r"(?:^|\s|/)(?:bftpd|vsftpd|proftpd|pure-ftpd|ftpd)(?:\s|$)", re.IGNORECASE),
        "risk": "Cleartext FTP daemon enabled without TLS requirement",
        "severity": "MEDIUM"
    },
    {
        "daemon": "gdbserver",
        "pattern": re.compile(r"(?:^|\s|/)(gdbserver)(?:\s|$)", re.IGNORECASE),
        "risk": "Debug server (gdbserver) exposed in production startup sequence",
        "severity": "CRITICAL"
    }
]

def scan_configs(root_dir: str) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. Startup scripts (etc/init.d, etc/rc.d, etc/inittab, etc/init.sh)
    startup_paths = ["etc/init.d", "etc/rc.d", "etc/rc.local", "etc/inittab", "etc/init.sh"]
    
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(file_path, root_dir).replace("\\", "/")
            
            is_init = any(init_token in rel_path.lower() for init_token in ["init", "rc", "boot", "startup"])
            
            if is_init:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        
                    for line_idx, line in enumerate(lines):
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                            
                        for daemon_rule in INSECURE_DAEMONS:
                            if daemon_rule["pattern"].search(stripped):
                                findings.append({
                                    "check_type": "INSECURE_SERVICE",
                                    "daemon": daemon_rule["daemon"],
                                    "severity": daemon_rule["severity"],
                                    "file_path": rel_path,
                                    "line_number": line_idx + 1,
                                    "evidence_snippet": stripped[:120],
                                    "description": daemon_rule["risk"]
                                })
                except Exception:
                    pass

            # Check for shadow / passwd without password requirement
            if rel_path in ["etc/passwd", "etc/shadow"]:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for l_no, line in enumerate(f):
                            parts = line.strip().split(":")
                            if len(parts) > 1 and parts[0] in ["root", "admin"]:
                                if parts[1] == "" or parts[1] == "!":
                                    findings.append({
                                        "check_type": "EMPTY_ROOT_PASSWORD",
                                        "severity": "CRITICAL",
                                        "file_path": rel_path,
                                        "line_number": l_no + 1,
                                        "evidence_snippet": f"{parts[0]} account has no password set or is unconfigured",
                                        "description": "Root/admin account allows unauthenticated console/shell access"
                                    })
                except Exception:
                    pass

    return findings
