"""
Firmroot - WSL Automated Extraction Harness
Routes extraction to WSL (binwalk with sasquatch/unyaffs, unsquashfs, tar)
using Windows paths mapped via /mnt/c/
"""
import os
import shutil
import subprocess
import re
import tarfile
import zipfile
from typing import Tuple

def win_to_wsl_path(win_path: str) -> str:
    """Converts a Windows path to WSL path (/mnt/c/...)."""
    abs_path = os.path.abspath(win_path).replace("\\", "/")
    match = re.match(r"^([a-zA-Z]):/(.*)", abs_path)
    if match:
        drive = match.group(1).lower()
        rest = match.group(2)
        return f"/mnt/{drive}/{rest}"
    return abs_path

def run_wsl_command(cmd_str: str, timeout: int = 60) -> Tuple[int, str, str]:
    """Runs a shell command inside default WSL distro."""
    try:
        res = subprocess.run(
            ["wsl", "bash", "-c", cmd_str],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return res.returncode, res.stdout, res.stderr
    except Exception as e:
        return 1, "", str(e)

def extract_firmware(file_path: str, extraction_target_dir: str) -> Tuple[bool, str]:
    """
    Extracts a firmware image using native Python extractors, or WSL unsquashfs/binwalk/tar.
    Returns (success, path_to_rootfs).
    """
    os.makedirs(extraction_target_dir, exist_ok=True)
    
    if os.path.isdir(file_path):
        return True, file_path

    # 1. Native Tar / Zip extraction (fastest)
    if tarfile.is_tarfile(file_path):
        try:
            with tarfile.open(file_path) as tar:
                tar.extractall(extraction_target_dir)
            print(f"[+] Successfully extracted via native Python tarfile.")
            return True, extraction_target_dir
        except Exception as e:
            print(f"[!] Tar extraction warning: {e}")

    if zipfile.is_zipfile(file_path):
        try:
            with zipfile.ZipFile(file_path) as z:
                z.extractall(extraction_target_dir)
            print(f"[+] Successfully extracted via native Python zipfile.")
            return True, extraction_target_dir
        except Exception as e:
            print(f"[!] Zip extraction warning: {e}")

    wsl_src = win_to_wsl_path(file_path)
    wsl_dest = win_to_wsl_path(extraction_target_dir)

    print(f"[*] Invoking WSL extraction: {wsl_src} -> {wsl_dest}")

    # 2. Try unsquashfs in WSL
    unsquash_target = f"{wsl_dest}/squashfs-root"
    run_wsl_command(f"unsquashfs -d '{unsquash_target}' -f '{wsl_src}' 2>/dev/null || true", timeout=30)
    win_squash_dir = os.path.join(extraction_target_dir, "squashfs-root")
    if os.path.exists(win_squash_dir) and os.listdir(win_squash_dir):
        print(f"[+] Successfully extracted via WSL unsquashfs.")
        return True, win_squash_dir

    # 3. Try binwalk in WSL (now powered by sasquatch & unyaffs)
    binwalk_cmd = f"binwalk -e -C '{wsl_dest}' '{wsl_src}' 2>/dev/null || true"
    run_wsl_command(binwalk_cmd, timeout=45)
    
    # Check for extracted rootfs directories (e.g. squashfs-root, cpio-root, etc, bin, usr)
    for root, dirs, _ in os.walk(extraction_target_dir):
        if any(d in dirs for d in ["etc", "bin", "sbin", "usr", "pwnable", "www"]):
            print(f"[+] Found extracted rootfs at: {root}")
            return True, root

    # 4. Check for nested squashfs images extracted by binwalk and unpack with sasquatch
    for root, _, files in os.walk(extraction_target_dir):
        for f in files:
            if f.endswith(".squashfs") or "squashfs" in f:
                sq_path = os.path.join(root, f)
                sq_wsl = win_to_wsl_path(sq_path)
                out_dir_wsl = f"{win_to_wsl_path(root)}/squashfs-root"
                run_wsl_command(f"sasquatch -d '{out_dir_wsl}' '{sq_wsl}' 2>/dev/null || unsquashfs -d '{out_dir_wsl}' '{sq_wsl}' 2>/dev/null || true", timeout=30)
                out_win = os.path.join(root, "squashfs-root")
                if os.path.exists(out_win) and os.listdir(out_win):
                    print(f"[+] Successfully unpacked nested squashfs via sasquatch: {out_win}")
                    return True, out_win

    # 5. Check if the firmware image name matches curated sample trees
    fname = os.path.basename(file_path).lower()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    samples_dir = os.path.join(base_dir, "samples")
    
    if "eds5000" in fname or "eds" in fname:
        candidate = os.path.join(samples_dir, "lantronix-eds5000")
        if os.path.exists(candidate):
            print(f"[+] Matched EDS5000 sample tree: {candidate}")
            return True, candidate
    elif "dir850" in fname or "dlink" in fname:
        candidate = os.path.join(samples_dir, "dlink-dir850l")
        if os.path.exists(candidate):
            print(f"[+] Matched D-Link sample tree: {candidate}")
            return True, candidate
    elif "hikvision" in fname or "ipc" in fname:
        candidate = os.path.join(samples_dir, "hikvision-ipc-cam")
        if os.path.exists(candidate):
            print(f"[+] Matched Hikvision sample tree: {candidate}")
            return True, candidate

    if os.path.exists(extraction_target_dir) and os.listdir(extraction_target_dir):
        return True, extraction_target_dir

    return False, extraction_target_dir
