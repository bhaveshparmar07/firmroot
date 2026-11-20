# Firmware scan: JWNR2000v3_JWNR2010v3_JWNR2000Tv3-v1.0.0.32.img

- SHA256: `17afced959a4ee06f996b3fb3a4495d0c54dc58f55ae70f772515184b69e36db`
- Rootfs: `work/scans/jwnr/extracted/rootfs/carved-direct-e8000`
- Services enumerated: 3
- Binaries analyzed: 3
- Candidate findings: 1

**Summary:** The structural analysis of the JWNR2000v3 firmware image (v1.0.0.32) identified a high-risk service, /usr/bin/pc, which executes as root and exhibits network-listening behavior alongside file-writing capabilities without evidence of authentication or privilege separation mechanisms.

## F001: Unauthenticated Root-Privileged Network Service with File-Write Capabilities
- **Priority:** High  |  **Service:** daemon  |  **Binary:** `/usr/bin/pc`
- Runs as: `root`
- Network symbols: bind, recvmsg, socket
- File-write symbols: fopen, fputs, fwrite
- **Explanation:** The binary /usr/bin/pc runs as a root-level daemon and imports symbols for network socket management (bind, recvmsg) and file system modification (fwrite, fputs). The absence of authentication-related symbols and privilege-dropping calls indicates that any user capable of reaching the service over the network may be able to influence file writes on the system. Given that the service runs as root, this could allow an attacker to overwrite sensitive configuration files or system binaries.
- **Attack scenario:** An unauthenticated attacker sends crafted network packets to the listening port of the /usr/bin/pc service to trigger its file-writing logic, overwriting critical system files like /etc/pc.ini or startup scripts to gain persistent root access to the device.
- **Permanent fix:** Engineer the /usr/bin/pc binary to include a robust authentication layer, implement strict path and content validation for all file operations, and ensure the process drops root privileges to a non-privileged user immediately after binding to its network port.
- **Immediate mitigation:** Configure the device's firewall to block access to the service's listening port(s) from the WAN and untrusted LAN segments, or disable the service by commenting out its entry in /etc/init.d/daemon.rc if the functionality is not required.
- **Compromise indicators:** Audit the integrity and timestamps of /etc/pc.ini and /var/mon.conf for unauthorized changes, and inspect the /var/ directory for unexpected files or modified initialization flags like /var/allmoduleinitok.
- Supplementary: `{"interesting_strings": ["/var/pid/0x04", "/etc/pc.ini", "/var/mon.conf", "/var/allmoduleinitok"]}`
