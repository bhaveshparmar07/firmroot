"""
Phase 1: Binary Structural Vulnerability Analysis Engine
Implements Step 2 (Service Enumeration) and Step 3 (Import/Symbol Mapping)
Analyzes ELF dynamic imports into network, file-write, auth, and priv-drop buckets.
"""
import os
import re
import subprocess
from typing import List, Dict, Any, Set, Tuple

# Step 3 Buckets
NETWORK_INPUT_FUNCTIONS = {
    "socket", "bind", "listen", "accept", "recv", "recvfrom", "recvmsg",
    "read", "select", "poll", "epoll_wait"
}

FILE_WRITE_FUNCTIONS = {
    "fopen", "open", "creat", "open64", "fwrite", "write", "fputs",
    "fprintf", "fputc", "pwrite", "vfprintf"
}

AUTH_FUNCTIONS = {
    "crypt", "crypt_r", "getpwnam", "getpwuid", "getspnam", "pam_authenticate",
    "pam_acct_mgmt", "pam_open_session", "checkpassword", "auth_user"
}

PRIV_DROP_FUNCTIONS = {
    "setuid", "seteuid", "setreuid", "setresuid", "setgid", "setegid",
    "setregid", "setresgid", "initgroups", "setgroups", "capset"
}

COMMAND_EXEC_FUNCTIONS = {
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execvpe"
}

def extract_symbols_from_elf(binary_path: str) -> Set[str]:
    """
    Extracts dynamic symbol imports using readelf or nm inside WSL or directly.
    """
    symbols = set()
    
    # Try readelf first
    try:
        # Check if binary is ELF
        with open(binary_path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return symbols
    except Exception:
        return symbols

    # Run readelf -s or nm -D via wsl
    # Map windows path to wsl
    win_path = os.path.abspath(binary_path).replace("\\", "/")
    match = re.match(r"^([a-zA-Z]):/(.*)", win_path)
    wsl_path = f"/mnt/{match.group(1).lower()}/{match.group(2)}" if match else win_path

    cmd = ["wsl", "bash", "-c", f"readelf -s --wide '{wsl_path}' 2>/dev/null || nm -D '{wsl_path}' 2>/dev/null"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines():
            # Format in readelf: ... UND symbol@GLIBC...
            # Format in nm: U symbol
            parts = line.strip().split()
            if not parts:
                continue
            for part in parts:
                # Clean version tags like func@GLIBC_2.4
                clean_sym = part.split("@")[0].strip()
                if clean_sym:
                    symbols.add(clean_sym)
    except Exception as e:
        pass

    return symbols

def enumerate_services(rootfs_path: str) -> List[Dict[str, Any]]:
    """
    Step 2: Parse init scripts (/etc/init.d/*, /etc/rc.d/*, inittab, rc.local)
    to discover binaries actually executed at boot, their arguments, and execution context.
    """
    services = []
    seen_binaries = set()

    init_dirs = [
        os.path.join(rootfs_path, "etc", "init.d"),
        os.path.join(rootfs_path, "etc", "rc.d"),
        os.path.join(rootfs_path, "etc", "rc.local"),
        os.path.join(rootfs_path, "etc", "inittab")
    ]

    for init_path in init_dirs:
        if not os.path.exists(init_path):
            continue
            
        files_to_read = []
        if os.path.isfile(init_path):
            files_to_read.append(init_path)
        else:
            for root, _, files in os.walk(init_path):
                for f in files:
                    files_to_read.append(os.path.join(root, f))

        for file_path in files_to_read:
            rel_script = os.path.relpath(file_path, rootfs_path).replace("\\", "/")
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, 1):
                        stripped = line.strip()
                        if not stripped or stripped.startswith("#"):
                            continue
                            
                        # Look for binary executions e.g. /usr/bin/service, /bin/foo, /sbin/bar
                        tokens = re.findall(r"(?:/usr/bin/|/usr/sbin/|/bin/|/sbin/|/etc/)([a-zA-Z0-9_\-\.]+)", stripped)
                        for bin_name in tokens:
                            if bin_name in ["sh", "echo", "sleep", "mkdir", "rm", "mount", "cat"]:
                                continue
                                
                            # Search for binary on filesystem
                            for search_dir in ["bin", "sbin", "usr/bin", "usr/sbin", "etc"]:
                                candidate = os.path.join(rootfs_path, search_dir, bin_name)
                                if os.path.exists(candidate) and candidate not in seen_binaries:
                                    seen_binaries.add(candidate)
                                    services.append({
                                        "binary_name": bin_name,
                                        "binary_path": candidate,
                                        "rel_path": os.path.relpath(candidate, rootfs_path).replace("\\", "/"),
                                        "spawned_by": f"{rel_script}:{line_no}",
                                        "init_command": stripped,
                                        "runs_as_root": True  # Embedded Linux init scripts execute with root UID (0)
                                    })
            except Exception:
                continue

    return services

def analyze_structural_vulnerabilities(rootfs_path: str) -> List[Dict[str, Any]]:
    """
    Step 3: Analyze each service binary against structural vulnerability heuristics:
    Pattern: (Network Input + File Write) + (Root Privilege) - (Auth Functions + Privilege Drop)
    """
    services = enumerate_services(rootfs_path)
    structural_findings = []
    finding_id = 1

    print(f"[*] Enumerated {len(services)} active boot services from init scripts.")

    for s in services:
        bin_path = s["binary_path"]
        symbols = extract_symbols_from_elf(bin_path)

        net_imports = symbols.intersection(NETWORK_INPUT_FUNCTIONS)
        file_write_imports = symbols.intersection(FILE_WRITE_FUNCTIONS)
        auth_imports = symbols.intersection(AUTH_FUNCTIONS)
        priv_drop_imports = symbols.intersection(PRIV_DROP_FUNCTIONS)
        exec_imports = symbols.intersection(COMMAND_EXEC_FUNCTIONS)

        # Apply Generalizable Structural Heuristic
        # Rule 1: Unauthenticated Privileged File-Write/Overwrite
        if net_imports and file_write_imports and s["runs_as_root"]:
            if not auth_imports and not priv_drop_imports:
                structural_findings.append({
                    "id": f"STRUCT-{finding_id:03d}",
                    "vulnerability_class": "Unauthenticated Privileged File-Write / Overwrite",
                    "cwe_id": "CWE-73: External Control of File Name or Path",
                    "severity": "CRITICAL",
                    "binary_name": s["binary_name"],
                    "binary_path": s["rel_path"],
                    "spawned_by": s["spawned_by"],
                    "init_command": s["init_command"],
                    "heuristic_match": {
                        "runs_as_root": True,
                        "network_input_symbols": sorted(list(net_imports)),
                        "file_write_symbols": sorted(list(file_write_imports)),
                        "missing_auth_symbols": True,
                        "missing_priv_drop_symbols": True
                    },
                    "reasoning": (
                        f"Binary '{s['binary_name']}' is invoked at boot as root by {s['spawned_by']}. "
                        f"It accepts untrusted network input ({', '.join(sorted(net_imports))}) and performs "
                        f"file write operations ({', '.join(sorted(file_write_imports))}) without importing any "
                        f"authentication checks (PAM, crypt) or privilege de-escalation routines (setuid, seteuid)."
                    )
                })
                finding_id += 1

        # Rule 2: Unauthenticated Privileged Command Injection Sink
        if net_imports and exec_imports and s["runs_as_root"]:
            if not auth_imports and not priv_drop_imports:
                structural_findings.append({
                    "id": f"STRUCT-{finding_id:03d}",
                    "vulnerability_class": "Unauthenticated Remote Command Execution via Subprocess Sink",
                    "cwe_id": "CWE-78: OS Command Injection",
                    "severity": "CRITICAL",
                    "binary_name": s["binary_name"],
                    "binary_path": s["rel_path"],
                    "spawned_by": s["spawned_by"],
                    "init_command": s["init_command"],
                    "heuristic_match": {
                        "runs_as_root": True,
                        "network_input_symbols": sorted(list(net_imports)),
                        "command_exec_symbols": sorted(list(exec_imports)),
                        "missing_auth_symbols": True,
                        "missing_priv_drop_symbols": True
                    },
                    "reasoning": (
                        f"Binary '{s['binary_name']}' runs as root and links network input "
                        f"({', '.join(sorted(net_imports))}) directly with command execution primitives "
                        f"({', '.join(sorted(exec_imports))}) without credential validation."
                    )
                })
                finding_id += 1

    return structural_findings
