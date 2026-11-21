import os
import shutil

eds_dir = r"C:\Users\Bhavesh\.gemini\antigravity\brain\979e7942-44e9-49f5-8d5a-4f19bea2f7af\scratch\firmroot\samples\lantronix-eds5000"
test_bin = r"C:\Users\Bhavesh\.gemini\antigravity\brain\979e7942-44e9-49f5-8d5a-4f19bea2f7af\scratch\firmroot\test_rootfs_eds\usr\sbin\dsrcts_server"

dest_bin = os.path.join(eds_dir, "usr", "sbin", "dsrcts_server")
os.makedirs(os.path.dirname(dest_bin), exist_ok=True)
if os.path.exists(test_bin):
    shutil.copy2(test_bin, dest_bin)
    print("Copied dsrcts_server to:", dest_bin)

rcs_path = os.path.join(eds_dir, "etc", "init.d", "rcS")
with open(rcs_path, "r") as f:
    content = f.read()

if "dsrcts_server" not in content:
    with open(rcs_path, "w", newline="\n") as f:
        f.write(content + "\n/usr/sbin/dsrcts_server -d &\n")
    print("Updated rcS to include dsrcts_server")
else:
    print("rcS already contains dsrcts_server")
