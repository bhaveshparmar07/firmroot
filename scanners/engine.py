"""
Firmroot - High-signal Deterministic Scanners
Extracts real, verbatim evidence from actual firmware rootfs trees.
"""
import os
import re
from typing import List, Dict, Any

SECRET_RULES = [
    {
        "id": "SEC-KEY",
        "name": "Hardcoded Private Key",
        "pattern": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "severity": "CRITICAL",
        "category": "HARDCODED_SECRET"
    },
    {
        "id": "SEC-HASH",
        "name": "Unix Password Hash in Shadow/Passwd",
        "pattern": re.compile(r"(?:root|admin|service|guest):(\$[156]\$[a-zA-Z0-9./]{8,64})"),
        "severity": "CRITICAL",
        "category": "HARDCODED_SECRET"
    },
    {
        "id": "SEC-NVRAM",
        "name": "Hardcoded NVRAM / Embedded Credential",
        "pattern": re.compile(r"(?i)(?:http_passwd|admin_password|telnet_pwd|mydlink_token)\s*[:=]\s*([^\s\r\n]+)"),
        "severity": "HIGH",
        "category": "HARDCODED_SECRET"
    }
]

VULNERABLE_COMPONENTS = [
    {
        "name": "busybox",
        "pattern": re.compile(r"BusyBox\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        "vulnerabilities": [
            {"max_ver": "1.33.2", "cve": "CVE-2021-42378", "severity": "HIGH", "summary": "Use-after-free in hush applet allowing remote command execution"}
        ]
    },
    {
        "name": "dnsmasq",
        "pattern": re.compile(r"Dnsmasq\s+version\s+([0-9]+\.[0-9]+)", re.IGNORECASE),
        "vulnerabilities": [
            {"max_ver": "2.82", "cve": "CVE-2020-25684", "severity": "CRITICAL", "summary": "DNSpooq: Cache poisoning & remote code execution in DHCP/DNS daemon"}
        ]
    },
    {
        "name": "openssl",
        "pattern": re.compile(r"OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)", re.IGNORECASE),
        "vulnerabilities": [
            {"max_ver": "1.0.2u", "cve": "CVE-2021-3712", "severity": "HIGH", "summary": "Buffer overrun in ASN.1 string parsing"}
        ]
    }
]

INSECURE_DAEMONS = [
    {"daemon": "telnetd", "pattern": re.compile(r"(?:^|\s|/)(telnetd)(?:\s|$)", re.IGNORECASE), "risk": "Unencrypted Telnet daemon spawned in init sequence", "severity": "HIGH"},
    {"daemon": "gdbserver", "pattern": re.compile(r"(?:^|\s|/)(gdbserver)(?:\s|$)", re.IGNORECASE), "risk": "Unauthenticated GDB debug server running on open network socket", "severity": "CRITICAL"},
    {"daemon": "bftpd", "pattern": re.compile(r"(?:^|\s|/)(bftpd|vsftpd|pure-ftpd)(?:\s|$)", re.IGNORECASE), "risk": "Cleartext FTP daemon active without TLS enforcement", "severity": "MEDIUM"},
    {"daemon": "rtspd", "pattern": re.compile(r"(?:^|\s|/)(rtspd|onvif_srv)(?:\s|$)", re.IGNORECASE), "risk": "Legacy surveillance media daemon running unauthenticated", "severity": "MEDIUM"}
]

def parse_version(ver_str: str):
    clean = re.sub(r"[^0-9.]", "", ver_str)
    parts = clean.split(".")
    res = []
    for p in parts:
        try:
            res.append(int(p))
        except ValueError:
            res.append(0)
    return res

def is_vulnerable(detected_ver: str, max_ver: str) -> bool:
    d = parse_version(detected_ver)
    m = parse_version(max_ver)
    max_len = max(len(d), len(m))
    d += [0] * (max_len - len(d))
    m += [0] * (max_len - len(m))
    return d <= m

def scan_real_filesystem(root_dir: str) -> List[Dict[str, Any]]:
    evidence = []
    evid_counter = 1

    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(file_path, root_dir).replace("\\", "/")

            # 1. Text checks (secrets + configs)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Secrets check
                for rule in SECRET_RULES:
                    for match in rule["pattern"].finditer(content):
                        line_no = content.count("\n", 0, match.start()) + 1
                        snippet = match.group(0).strip()
                        if len(snippet) > 100:
                            snippet = snippet[:100] + "... [redacted]"
                        evidence.append({
                            "id": f"EVID-{evid_counter:03d}",
                            "category": rule["category"],
                            "severity": rule["severity"],
                            "title": rule["name"],
                            "file_path": rel_path,
                            "line_number": line_no,
                            "snippet": snippet
                        })
                        evid_counter += 1

                # Insecure daemons in init scripts
                if any(x in rel_path.lower() for x in ["init.d", "rc", "boot", "startup"]):
                    for daemon_rule in INSECURE_DAEMONS:
                        for match in daemon_rule["pattern"].finditer(content):
                            line_no = content.count("\n", 0, match.start()) + 1
                            lines = content.splitlines()
                            matched_line = lines[line_no - 1].strip() if line_no - 1 < len(lines) else match.group(0)
                            evidence.append({
                                "id": f"EVID-{evid_counter:03d}",
                                "category": "INSECURE_CONFIGURATION",
                                "severity": daemon_rule["severity"],
                                "title": daemon_rule["risk"],
                                "file_path": rel_path,
                                "line_number": line_no,
                                "snippet": matched_line
                            })
                            evid_counter += 1
            except Exception:
                pass

            # 2. Binary version checks
            if any(b in rel_path.lower() for b in ["bin", "sbin", "lib", "usr"]):
                try:
                    with open(file_path, "rb") as f:
                        chunk = f.read(256 * 1024).decode("latin1", errors="ignore")
                    for comp in VULNERABLE_COMPONENTS:
                        for match in comp["pattern"].finditer(chunk):
                            detected_ver = match.group(1)
                            for vuln in comp["vulnerabilities"]:
                                if is_vulnerable(detected_ver, vuln["max_ver"]):
                                    evidence.append({
                                        "id": f"EVID-{evid_counter:03d}",
                                        "category": "VULNERABLE_COMPONENT",
                                        "severity": vuln["severity"],
                                        "title": f"Vulnerable {comp['name']} ({vuln['cve']})",
                                        "file_path": rel_path,
                                        "line_number": None,
                                        "snippet": f"{comp['name']} version {detected_ver} matches known critical advisory {vuln['cve']}: {vuln['summary']}"
                                    })
                                    evid_counter += 1
                except Exception:
                    pass

    return evidence
