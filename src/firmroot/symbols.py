"""ELF dynamic-symbol extraction and security-bucket classification.

Uses `readelf --dyn-syms -W` (binutils, present on any Linux box) to list
imported (UND) symbols, then classifies them into buckets:

  network_input   - socket/bind/listen/accept/recv family
  file_write      - fopen/fwrite/open-family file-writing calls
  auth            - crypt/PAM/password-DB calls
  priv_drop       - set*id/initgroups/setgroups privilege dropping

The main heuristic (generalizable, no binary-name hardcoding):
  service runs as root AND imports network_input AND file_write
  AND imports nothing from auth or priv_drop
  => candidate unauthenticated privileged file-write/overwrite.
"""

import re
import subprocess
from pathlib import Path

NETWORK_INPUT = {
    "socket", "bind", "listen", "accept", "accept4",
    "recv", "recvfrom", "recvmsg", "recvmmsg",
    "socketpair", "getpeername", "getsockname",
    "SSL_read", "gnutls_record_recv", "mbedtls_ssl_read",
}
FILE_WRITE = {
    "fopen", "fopen64", "freopen", "freopen64",
    "fwrite", "fwrite_unlocked", "fputs", "fputc", "putc",
    "fprintf", "vfprintf", "dprintf",
    "open", "open64", "openat", "openat64", "creat", "creat64",
    "mkdir", "mkdirat", "rename", "renameat", "link", "symlink",
    "chmod", "fchmod", "chown", "fchown", "truncate", "ftruncate",
}
AUTH = {
    "crypt", "crypt_r", "getpwnam", "getpwuid", "getspnam", "getspent",
    "getpwent", "pam_start", "pam_authenticate", "pam_acct_mgmt",
    "pam_setcred", "pam_open_session", "pam_chauthtok",
    "auth_getval", "auth_setval",
}
PRIV_DROP = {
    "setuid", "seteuid", "setgid", "setegid",
    "setreuid", "setregid", "setresuid", "setresgid",
    "setfsuid", "setfsgid", "initgroups", "setgroups",
    "capset", "capsetx",
}

# symbols that merely *mention* file writes but are ubiquitous noise
IGNORE = {"__fprintf_chk", "__printf_chk", "__sprintf_chk", "__snprintf_chk",
          "__open_2", "__open64_2", "__openat_2", "__openat64_2",
          "__isoc99_fscanf", "sscanf", "fscanf", "scanf"}


def is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except OSError:
        return False


def _elf_arch(path: Path) -> str:
    try:
        out = subprocess.run(["readelf", "-h", str(path)],
                             capture_output=True, text=True, timeout=30)
        for line in out.stdout.splitlines():
            if "Class:" in line or "Machine:" in line or "Type:" in line:
                pass
        m = re.search(r"Class:\s+(\w+).*Machine:\s+(.+)", out.stdout, re.S)
        # simpler: grab lines
        cls = re.search(r"Class:\s+(\S+)", out.stdout)
        mach = re.search(r"Machine:\s+(.+)", out.stdout)
        typ = re.search(r"Type:\s+(.+)", out.stdout)
        return " ".join(x.group(1).strip() for x in (cls, mach, typ) if x)
    except Exception:
        return "unknown"


def dynamic_symbols(path: Path):
    """Return (imports:set[str], exports:set[str], static:bool)."""
    path = Path(path)
    if not is_elf(path):
        return set(), set(), False
    try:
        out = subprocess.run(
            ["readelf", "--dyn-syms", "-W", str(path)],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return set(), set(), False
    if out.returncode != 0 or "no symbols" in out.stdout.lower():
        return set(), set(), True
    imports, exports = set(), set()
    for line in out.stdout.splitlines():
        # format: Num: Value Size Type Bind Vis Ndx Name
        m = re.match(r"\s*\d+:\s+[0-9a-f]+\s+\d+\s+(\w+)\s+\w+\s+\w+\s+(\S+)\s+(\S+)", line)
        if not m:
            continue
        ndx, name = m.group(2), m.group(3)
        if not name or name.startswith("$"):
            continue
        base = name.split("@")[0].split(".")[0] if "." not in name else name
        sym = name.split("@")[0]
        if sym in IGNORE:
            continue
        if ndx == "UND":
            imports.add(sym)
        else:
            exports.add(sym)
    # also try nm -D as fallback if readelf gave nothing
    if not imports and not exports:
        try:
            out2 = subprocess.run(["nm", "-D", "--undefined-only", str(path)],
                                  capture_output=True, text=True, timeout=60)
            for line in out2.stdout.splitlines():
                parts = line.split()
                if parts:
                    imports.add(parts[-1].split("@")[0])
        except (OSError, subprocess.TimeoutExpired):
            pass
    return imports, exports, False


def classify_symbols(imports):
    """Bucket the import set. Returns dict bucket -> sorted matched symbols."""
    buckets = {"network_input": [], "file_write": [], "auth": [], "priv_drop": []}
    for sym in sorted(imports):
        if sym in NETWORK_INPUT:
            buckets["network_input"].append(sym)
        if sym in FILE_WRITE:
            buckets["file_write"].append(sym)
        if sym in AUTH:
            buckets["auth"].append(sym)
        if sym in PRIV_DROP:
            buckets["priv_drop"].append(sym)
    return buckets


def analyze_binary(binary_path, rootfs=None):
    """Full per-binary analysis. Returns evidence dict."""
    p = Path(binary_path)
    result = {
        "binary": str(p),
        "is_elf": is_elf(p),
        "arch": _elf_arch(p) if is_elf(p) else None,
        "static_or_no_dynsyms": False,
        "imports": [],
        "buckets": {"network_input": [], "file_write": [], "auth": [], "priv_drop": []},
        "import_count": 0,
    }
    imports, exports, static = dynamic_symbols(p)
    result["static_or_no_dynsyms"] = static
    result["imports"] = sorted(imports)
    result["import_count"] = len(imports)
    result["buckets"] = classify_symbols(imports)
    return result


def check_unauth_priv_write(service, analysis):
    """Apply the main heuristic. Returns finding dict or None."""
    if not analysis["is_elf"]:
        return None
    b = analysis["buckets"]
    runs_as_root = service.get("user", "root") == "root" or service.get("setuid_bit")
    has_net = bool(b["network_input"])
    has_write = bool(b["file_write"])
    has_auth = bool(b["auth"])
    has_drop = bool(b["priv_drop"]) or service.get("drops_privileges")
    if runs_as_root and has_net and has_write and not has_auth and not has_drop:
        return {
            "type": "unauthenticated_privileged_file_write",
            "service": service["name"],
            "binary": service["binary"],
            "user": service.get("user", "root"),
            "matched_network_symbols": b["network_input"],
            "matched_file_write_symbols": b["file_write"],
            "auth_symbols_absent": True,
            "priv_drop_absent": True,
            "setuid_bit": service.get("setuid_bit", False),
            "sources": service.get("sources", []),
            "notes": service.get("notes", []),
            "import_count": analysis["import_count"],
            "static_or_no_dynsyms": analysis["static_or_no_dynsyms"],
        }
    return None


def supplementary_checks(rootfs, service, analysis):
    """Light corroborating checks: hardcoded credential strings, versions."""
    notes = {}
    p = Path(service.get("resolved") or "")
    root = Path(rootfs)
    # strings scan for credential-looking literals in the binary
    creds = []
    interesting = []
    if analysis["is_elf"]:
        cred_pat = re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)"
                              r"\s*[=:]\s*['\"]?[^\s'\"]{4,}")
        int_pat = re.compile(
            r"(/(?:etc|var|tmp|rom|mnt|data|config|www|overlay)/[^\s'\"]{2,80})"
            r"|(?:port|listen|bind)\s*[:=]?\s*\d{2,5}"
            r"|\b\d{4,5}\b.*(?:port|listen)", re.I)
        try:
            out = subprocess.run(
                ["strings", "-n", "5", str(p)],
                capture_output=True, text=True, timeout=60)
            seen = set()
            for line in out.stdout.splitlines():
                s = line.strip()
                if len(s) < 4 or s in seen:
                    continue
                seen.add(s)
                if cred_pat.search(s) and not s.startswith("$"):
                    creds.append(s[:160])
                elif int_pat.search(s):
                    interesting.append(s[:160])
                if len(creds) >= 10 and len(interesting) >= 40:
                    break
        except (OSError, subprocess.TimeoutExpired):
            pass
    if creds:
        notes["possible_hardcoded_credentials"] = creds
    if interesting:
        notes["interesting_strings"] = interesting
    # version fingerprint: nearby opkg/apk control or release files
    ver = {}
    for rel in ("etc/openwrt_release", "etc/openwrt_version"):
        f = root / rel
        if f.is_file():
            try:
                ver[rel] = f.read_text(errors="replace").strip()[:500]
            except OSError:
                pass
    # package db version for this binary's package
    pkgname = None
    for db in ("lib/opkg/status", "lib/apk/db/installed", "var/lib/opkg/status"):
        f = root / db
        if f.is_file():
            try:
                txt = f.read_text(errors="replace")
                # find stanza mentioning this binary path
                binname = Path(service["binary"]).name
                for stanza in txt.split("\n\n"):
                    if binname in stanza:
                        for kv in stanza.splitlines():
                            if kv.startswith(("Version:", "pkgver=")):
                                ver[f"pkg:{db}"] = kv.strip()
                                break
                        break
            except OSError:
                pass
    if ver:
        notes["versions"] = ver
    return notes
