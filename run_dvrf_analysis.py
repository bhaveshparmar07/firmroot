import os
from structural_analysis import analyze_structural_vulnerabilities
from scanners.engine import scan_real_filesystem

dvrf_root = r"C:\Users\Bhavesh\.gemini\antigravity\brain\979e7942-44e9-49f5-8d5a-4f19bea2f7af\scratch\firmroot\test_dvrf_wsl"
# Let's map WSL /tmp/dvrf_real_extract/... directly via WSL path
import subprocess
res = subprocess.run(["wsl", "ls", "/tmp/dvrf_real_extract/_FR-1795159466_DVRF_v03.bin.extracted/squashfs-root"], capture_output=True, text=True)
print("WSL rootfs exists:", bool(res.stdout))

# Run scanning in WSL directly on the extracted rootfs
script = """
set -e
ROOT="/tmp/dvrf_real_extract/_FR-1795159466_DVRF_v03.bin.extracted/squashfs-root"
cd "$ROOT"

echo "=== Searching for vulnerable services and symbols in DVRF ==="
for bin in usr/sbin/httpd usr/sbin/dnsmasq pwnable/Intro/stack_bof_01; do
    if [ -f "$bin" ]; then
        echo "Binary: $bin"
        readelf -s "$bin" 2>/dev/null | grep -E "socket|bind|listen|accept|recv|fopen|fwrite|system|strcpy" | head -n 10 || true
    fi
done
"""

with open("C:/Users/Bhavesh/.gemini/antigravity/brain/979e7942-44e9-49f5-8d5a-4f19bea2f7af/scratch/firmroot/test_dvrf_scan.sh", "w", newline="\n") as f:
    f.write(script)

res2 = subprocess.run(["wsl", "bash", "/mnt/c/Users/Bhavesh/.gemini/antigravity/brain/979e7942-44e9-49f5-8d5a-4f19bea2f7af/scratch/firmroot/test_dvrf_scan.sh"], capture_output=True, text=True)
print(res2.stdout)
