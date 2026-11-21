import subprocess

script = """
echo "=== Tools ==="
which binwalk unsquashfs 7z tar unyaffs jefferson || true
python3 -m pip list | grep -i -E "yaffs|ubi|jefferson" || true

echo "=== EDS5000 YAFFS files ==="
ROM_EXT="/mnt/c/Users/Bhavesh/.gemini/antigravity/brain/979e7942-44e9-49f5-8d5a-4f19bea2f7af/scratch/firmroot/extracted_runs/eds5000_real/_FR-1795153032_EDS5000_2.1.0.0R3.rom.extracted"
ls -lh "$ROM_EXT"

echo "=== XR1000 check ==="
XR_FILE="/mnt/c/Users/Bhavesh/.gemini/antigravity/brain/979e7942-44e9-49f5-8d5a-4f19bea2f7af/scratch/firmroot/uploads/FR-1795154011_XR1000-V1.0.64.18_5.0.19.chk"
binwalk "$XR_FILE" | head -n 30
"""

with open("C:/Users/Bhavesh/.gemini/antigravity/brain/979e7942-44e9-49f5-8d5a-4f19bea2f7af/scratch/firmroot/check_env.sh", "w", newline="\n") as f:
    f.write(script)

res = subprocess.run(["wsl", "bash", "/mnt/c/Users/Bhavesh/.gemini/antigravity/brain/979e7942-44e9-49f5-8d5a-4f19bea2f7af/scratch/firmroot/check_env.sh"], capture_output=True, text=True)
print(res.stdout)
print("STDERR:", res.stderr)
