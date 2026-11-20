"""Service enumeration: parse init scripts to find which binaries run at
boot and with what privileges.

Covers OpenWrt/procd (/etc/init.d/* with START= sections), SysV
(/etc/init.d/*, /etc/rc.d/S??*, /etc/inittab), and rc.local style hooks.
Privilege model: services default to root; we downgrade only when the
script/config explicitly drops privileges (su/suid/setuid calls, user=
directives, or setuid bits on the binary itself).
"""

import os
import posixpath
import re
import stat
from pathlib import Path

EXEC_DIRS = ("bin", "sbin", "usr/bin", "usr/sbin", "usr/libexec",
             "usr/local/bin", "usr/local/sbin", "libexec")
ABS_PATH_RE = re.compile(r"/(?:usr/|sbin/|bin/|libexec/|opt/|rom/)?[\w.\-]+(?:/[\w.\-]+)+")

DROP_PATTERNS = re.compile(
    r"\b(su|sudo|setuid|seteuid|setgid|setgroups|initgroups|chroot|"
    r"start-stop-daemon\s+.*--user|--chuid|runuser)\b")
USER_DIRECTIVE_RE = re.compile(r"\b(?:user|username|account)\s*[=:]\s*([\w.-]+)", re.I)
PROG_RE = re.compile(
    r"(?:exec|command|prog|program|path|start|daemon|server|agent|daemon_bin)"
    r"[\s]*[=:][\s]*['\"]?(/[\w./+\-]+)", re.I)


def _is_executable(path: Path) -> bool:
    try:
        st = path.stat()
        return stat.S_ISREG(st.st_mode) and (st.st_mode & 0o111) != 0
    except OSError:
        return False


def _resolve(root: Path, token: str):
    """Resolve a script token to a path inside rootfs, following
    rootfs-relative symlinks (never escaping to the host fs)."""
    token = token.strip("'\"`").rstrip(";&|)")
    if not token.startswith("/"):
        return None
    p = root / token.lstrip("/")
    for _ in range(8):
        try:
            if p.is_symlink():
                target = os.readlink(p)
                if target.startswith("/"):
                    p = root / target.lstrip("/")
                else:
                    p = (p.parent / target)
                continue
            if p.exists():
                return p
            return None
        except OSError:
            return None
    return p if p.exists() else None


VAR_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=[\"']?(/[^\s\"';|&]+)", re.M)
CMD_HINT_RE = re.compile(
    r"(?:^|[;&|]\s*|\b(?:exec|command|procd_set_param|procd_append_param|"
    r"start-stop-daemon|daemon|respawn|nohup)\b)")
GENERIC_SCRIPT_NAMES = {"sysinit", "boot", "done", "sysctl", "urandom_seed",
                        "system", "rcS", "rc.common"}


def _parse_varmap(text):
    # Map shell VAR=/abs/path assignments for later variable expansion.
    varmap = {}
    for m in VAR_ASSIGN_RE.finditer(text):
        varmap[m.group(1)] = m.group(2)
    return varmap


def _expand_vars(line, varmap):
    def rep(m):
        name = m.group(1) or m.group(2)
        return varmap.get(name, m.group(0))
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", rep, line)


def _command_position_paths(line):
    """Absolute paths appearing in command position on a shell line."""
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    # strip leading env assignments (FOO=bar) and wrappers
    toks = line.split()
    i = 0
    while i < len(toks) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[i]):
        i += 1
    if i < len(toks) and toks[i] in ("sudo", "nice", "ionice", "chrt", "taskset"):
        i += 1
        while i < len(toks) and toks[i].startswith("-"):
            i += 1
    if i >= len(toks):
        return []
    first = toks[i].strip("'\"`")
    cands = [first] if first.startswith("/") else []
    # 'command /path ...' or 'exec /path ...' forms
    if first in ("command", "exec") and i + 1 < len(toks):
        t = toks[i + 1].strip("'\"`")
        if t.startswith("/"):
            cands.append(t)
    # procd_set_param command /path  /  procd_append_param command /path
    for j, t in enumerate(toks):
        if t == "command" and j + 1 < len(toks):
            nxt = toks[j + 1].strip("'\"`")
            if nxt.startswith("/"):
                cands.append(nxt)
    return cands


def _candidate_binaries(root: Path, script_path: Path):
    """Extract plausible service binaries: command-position paths first,
    falling back to any executable absolute path in the script."""
    try:
        text = script_path.read_text(errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    varmap = _parse_varmap(text)
    skip_prefix = ("/etc/", "/lib/", "/usr/lib/", "/usr/share/", "/var/",
                   "/tmp/", "/dev/", "/proc/", "/sys/", "/rom/etc/",
                   "/overlay/", "/mnt/", "/media/", "/boot/")
    skip_suffix = (".so", ".sh", ".lua", ".pl", ".py", ".conf", ".json")

    root_abs = root.resolve()

    def acceptable(p: Path):
        try:
            rel = posixpath.normpath(
                "/" + os.path.relpath(str(p), str(root_abs)).replace("\\", "/"))
        except (ValueError, OSError):
            return False
        if rel.startswith("/../") or rel == "/..":
            return False
        if rel.startswith(skip_prefix):
            return False
        if p.suffix.lower() in skip_suffix:
            return False
        return _is_executable(p)

    primary, secondary = [], []
    for raw_line in text.splitlines():
        line = _expand_vars(raw_line, varmap)
        for tok in _command_position_paths(line):
            p = _resolve(root, tok)
            if p and acceptable(p):
                primary.append(p)
        # secondary: any absolute path that is an executable (dedup later)
        for m in ABS_PATH_RE.finditer(line):
            p = _resolve(root, m.group(0))
            if p and acceptable(p):
                secondary.append(p)

    # dedup preserving order
    def dedup(seq):
        seen, out = set(), []
        for p in seq:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    primary, secondary = dedup(primary), dedup(secondary)
    # if the script names its service binary via a variable used in
    # command position, primary wins; else fall back to secondary
    chosen = primary if primary else secondary
    # drop libs entirely even in fallback
    return [p for p in chosen if p.suffix != ".so"]


def _script_privileges(root: Path, script_path: Path):
    """Return (user, drops_privileges, notes)."""
    try:
        text = script_path.read_text(errors="replace")
    except OSError:
        return "root", False, []
    notes = []
    user = "root"
    m = USER_DIRECTIVE_RE.search(text)
    if m and m.group(1).lower() not in ("root",):
        user = m.group(1)
        notes.append(f"user directive '{user}'")
    drops = bool(DROP_PATTERNS.search(text))
    if drops:
        notes.append("privilege-drop call found in script")
    return user, drops, notes


def enumerate_services(rootfs):
    """Enumerate boot-time services. Returns list of service dicts."""
    root = Path(rootfs)
    services = {}  # key: binary path str -> service dict

    def add(binary, script, source, user="root", drops=False, notes=None):
        try:
            rel = posixpath.normpath(
                "/" + str(binary.relative_to(root)).replace("\\", "/"))
        except ValueError:
            rel = posixpath.normpath(str(binary))
        key = rel
        if key in services:
            services[key]["sources"].append(source)
            if user != "root":
                services[key]["user"] = user
            if drops:
                services[key]["drops_privileges"] = True
            return
        # setuid bit on the binary itself = privilege-relevant
        setuid = False
        try:
            setuid = bool(binary.stat().st_mode & stat.S_ISUID)
        except OSError:
            pass
        sname = script.stem if script else binary.name
        if sname in GENERIC_SCRIPT_NAMES:
            sname = binary.name
        services[key] = {
            "name": sname,
            "binary": rel,
            "resolved": str(binary),
            "user": user,
            "drops_privileges": drops,
            "setuid_bit": setuid,
            "sources": [source],
            "notes": notes or [],
        }

    # 1. /etc/init.d/* and /etc/rc.d/* scripts (SysV + OpenWrt procd)
    for d in ("etc/init.d", "etc/rc.d", "etc/rc.d/init.d"):
        base = root / d
        if not base.is_dir():
            continue
        for script in sorted(base.iterdir()):
            if not script.is_file() or script.suffix in (".so", ".md"):
                continue
            if d.endswith("rc.d") and script.name[:1] in ("K", "k"):
                continue  # kill/stop scripts don't start services
            # rc.d/S??* are usually symlinks to init.d
            real = script
            try:
                if script.is_symlink():
                    real = script.resolve()
            except OSError:
                pass
            if not real.exists():
                continue
            user, drops, notes = _script_privileges(root, real)
            for b in _candidate_binaries(root, real):
                add(b, real, f"{d}/{script.name}", user=user,
                    drops=drops, notes=notes)

    # 2. /etc/inittab: sysinit/respawn lines may name binaries directly
    inittab = root / "etc/inittab"
    if inittab.is_file():
        try:
            for line in inittab.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 5:
                    action, process = parts[3].strip(), parts[4].strip()
                    if action in ("sysinit", "respawn", "askfirst") and process.startswith("/"):
                        p = _resolve(root, process.split()[0])
                        if p and _is_executable(p):
                            add(p, inittab, "inittab", notes=[f"action={action}"])
        except OSError:
            pass

    # 3. /etc/rc.local
    rclocal = root / "etc/rc.local"
    if rclocal.is_file():
        for b in _candidate_binaries(root, rclocal):
            add(b, rclocal, "rc.local")

    # 4. /etc/config/* procd service definitions (command/path fields)
    cfgdir = root / "etc/config"
    if cfgdir.is_dir():
        for cfg in sorted(cfgdir.iterdir()):
            if not cfg.is_file():
                continue
            try:
                text = cfg.read_text(errors="replace")
            except OSError:
                continue
            user = "root"
            m = USER_DIRECTIVE_RE.search(text)
            if m and m.group(1).lower() != "root":
                user = m.group(1)
            drops = bool(re.search(r"\bsetuid\b|\bseteuid\b|\binitgroups\b", text))
            for m in PROG_RE.finditer(text):
                p = _resolve(root, m.group(1))
                if p and _is_executable(p):
                    add(p, cfg, f"config/{cfg.name}", user=user, drops=drops)
            # also catch 'command' style UCI lists: command=/path args
            for m in re.finditer(r"command\s*=\s*'(/[^\s']+)'", text):
                p = _resolve(root, m.group(1))
                if p and _is_executable(p):
                    add(p, cfg, f"config/{cfg.name}", user=user, drops=drops)

    return list(services.values())


def _is_wrapper(script: Path) -> bool:
    """Heuristic: small scripts that just source another init script."""
    try:
        if script.stat().st_size > 20000:
            return False
        text = script.read_text(errors="replace")
        return bool(re.search(r"\.\s+/etc/init\.d/|source\s+/etc/init\.d/", text))
    except OSError:
        return False
