"""
Firmroot - Outdated & Vulnerable Component Matcher
"""
import os
import re
from typing import List, Dict, Any

# Targeted known vulnerable components prevalent in embedded firmware
VULNERABLE_COMPONENTS = [
    {
        "name": "busybox",
        "pattern": re.compile(r"BusyBox\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        "known_vulnerabilities": [
            {"max_version": "1.33.2", "cve": "CVE-2021-42378", "severity": "HIGH", "summary": "Use-after-free in hush applet allowing remote code execution"}
        ]
    },
    {
        "name": "dropbear",
        "pattern": re.compile(r"dropbear[_\- ]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        "known_vulnerabilities": [
            {"max_version": "2019.78", "cve": "CVE-2020-36254", "severity": "HIGH", "summary": "Information disclosure / authentication bypass in legacy Dropbear SSH"}
        ]
    },
    {
        "name": "dnsmasq",
        "pattern": re.compile(r"Dnsmasq\s+version\s+([0-9]+\.[0-9]+)", re.IGNORECASE),
        "known_vulnerabilities": [
            {"max_version": "2.82", "cve": "CVE-2020-25684", "severity": "CRITICAL", "summary": "DNSpooq: Cache poisoning & remote code execution in DHCP/DNS daemon"}
        ]
    },
    {
        "name": "openssl",
        "pattern": re.compile(r"OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)", re.IGNORECASE),
        "known_vulnerabilities": [
            {"max_version": "1.0.2u", "cve": "CVE-2021-3712", "severity": "HIGH", "summary": "Read buffer overruns in ASN.1 string parsing"}
        ]
    },
    {
        "name": "lighttpd",
        "pattern": re.compile(r"lighttpd/([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE),
        "known_vulnerabilities": [
            {"max_version": "1.4.53", "cve": "CVE-2022-22707", "severity": "HIGH", "summary": "Out-of-bounds read and HTTP header parsing denial of service"}
        ]
    }
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
    # Pad to equal length
    max_len = max(len(d), len(m))
    d += [0] * (max_len - len(d))
    m += [0] * (max_len - len(m))
    return d <= m

def scan_components(root_dir: str) -> List[Dict[str, Any]]:
    findings = []
    scanned_binaries = set()
    
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(file_path, root_dir).replace("\\", "/")
            
            # Focus on bin, sbin, usr/bin, lib, etc. or files with no extension
            if not any(token in rel_path.lower() for token in ["bin", "sbin", "lib", "etc", "usr"]):
                continue
                
            try:
                # Read chunks to find banner signatures
                with open(file_path, "rb") as f:
                    chunk = f.read(512 * 1024) # Scan first 512KB for version banner
                    
                text = chunk.decode("latin1", errors="ignore")
                
                for comp in VULNERABLE_COMPONENTS:
                    for match in comp["pattern"].finditer(text):
                        detected_ver = match.group(1)
                        for vuln in comp["known_vulnerabilities"]:
                            if is_vulnerable(detected_ver, vuln["max_version"]):
                                key = (comp["name"], detected_ver, vuln["cve"])
                                if key not in scanned_binaries:
                                    scanned_binaries.add(key)
                                    findings.append({
                                        "check_type": "OUTDATED_COMPONENT",
                                        "component_name": comp["name"],
                                        "detected_version": detected_ver,
                                        "cve": vuln["cve"],
                                        "severity": vuln["severity"],
                                        "file_path": rel_path,
                                        "summary": vuln["summary"],
                                        "evidence_snippet": f"Identified {comp['name']} version {detected_ver} in binary banner"
                                    })
            except Exception:
                continue
                
    return findings
