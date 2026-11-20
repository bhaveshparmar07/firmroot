# Firmware scan: EDS5000_2.3.0.0R7.rom

- SHA256: `a380bd86800456b45014b5069e3d140def0d5193e5bd1a1c89af06184e374ff1`
- Rootfs: `work/scans/eds5000/extracted/rootfs/carved-ubi-de0100-3e000`
- Services enumerated: 28
- Binaries analyzed: 28
- Candidate findings: 5

**Summary:** The structural analysis of the Lantronix EDS5000 firmware (v2.3.0.0R7) reveals a high-risk attack surface characterized by several custom vendor binaries (diresponder, ltrx_cli, dsrcts_server) running as root with active network listeners and file-write capabilities. Most notably, the 'nuevo80' service utilizes a CLI binary containing strings that suggest the use of unsanitized shell commands (e.g., openssl, grep /etc/shadow), indicating a high probability of both arbitrary file write and command injection. Standard OpenWrt components (netifd, odhcpd) are also present and privileged, though they represent a lower risk relative to the custom vendor-developed services.

## F001: Unauthenticated Privileged File Write in Discovery Service
- **Priority:** High  |  **Service:** discovery  |  **Binary:** `/bin/diresponder`
- Runs as: `root`
- Network symbols: bind, recvmsg, socket
- File-write symbols: fopen, fprintf, fputs, open
- **Explanation:** The discovery responder binary 'diresponder' runs as the root user and listens for network traffic (bind/recvmsg). It lacks symbols for authentication and privilege dropping, while importing functions that write to the filesystem. The presence of strings related to PID files and IPC sockets in /tmp suggests it manages state files that could be targeted for symlink attacks or arbitrary content injection if network-provided data is not sanitized.
- **Attack scenario:** An attacker sends a crafted UDP discovery packet to the service's listening port to trigger the creation or overwrite of files in /tmp or /var/run, potentially leading to a Denial of Service or hijacking of IPC mechanisms.
- **Permanent fix:** Modify the diresponder service to run as a non-privileged user and implement strict validation/sanitization of all network-received data before using it in file operations.
- **Immediate mitigation:** Disable the discovery service if not required for deployment, or use a firewall to restrict access to the discovery ports to trusted management subnets only.
- **Compromise indicators:** Unexpected file ownership or modified timestamps for files in /tmp/ipc/ or /tmp/diresponder.info, or the presence of non-standard files in /var/run/.
- Supplementary: `{"interesting_strings": ["/var/run/diresponder.pid", "/tmp/diresponder.info", "/tmp/ipc/cfg.ipc", "/tmp/ipc/as.ipc"], "versions": {"etc/openwrt_release": "DISTRIB_ID='Lantronix EDS5000'\nDISTRIB_RELEASE='2.3.0.0R7'\nDISTRIB_REVISION='r19685-512e76967f'\nDISTRIB_TARGET='ma35d1/som'\nDISTRIB_ARCH='aarch64_generic'\nDISTRIB_DESCRIPTION='Lantronix EDS5000 2.3.0.0R7'\nDISTRIB_TAINTS='no-all busybox'\nD`

## F002: Privileged Network Configuration Service Risk
- **Priority:** Medium  |  **Service:** network  |  **Binary:** `/sbin/netifd`
- Runs as: `root`
- Network symbols: socket
- File-write symbols: fopen, fprintf, fputs, mkdir, open, openat, rename, vfprintf
- **Explanation:** The netifd daemon is a core OpenWrt component running as root that manages network interfaces and writes configuration files like resolv.conf. While it is a standard component, its privileged status and interaction with network-derived data (e.g., via DHCP) mean that any vulnerability in its path handling or file renaming logic could allow for unauthorized system configuration changes.
- **Attack scenario:** An attacker on the local network provides a malicious DHCP response containing crafted hostnames or options designed to cause netifd to perform directory traversal when writing its temporary resolution files.
- **Permanent fix:** Ensure the service uses a restricted filesystem namespace or AppArmor/Selinux profile to limit file writes to a specific set of configuration directories.
- **Immediate mitigation:** Enable DHCP snooping on the local network switch to prevent unauthorized DHCP servers from providing malicious configuration data to the device.
- **Compromise indicators:** Modification of /etc/board.json or unexpected entries in /tmp/resolv.conf.d/ that do not match the expected network environment.
- Supplementary: `{"interesting_strings": ["/tmp/resolv.conf-%s.d/resolv.conf.auto", "/etc/board.json", "/tmp/resolv.conf.d/resolv.conf.auto", "/etc/iproute2/rt_protos", "/etc/iproute2/rt_tables"], "versions": {"etc/openwrt_release": "DISTRIB_ID='Lantronix EDS5000'\nDISTRIB_RELEASE='2.3.0.0R7'\nDISTRIB_REVISION='r19685-512e76967f'\nDISTRIB_TARGET='ma35d1/som'\nDISTRIB_ARCH='aarch64_generic'\nDISTRIB_DESCRIPTION='La`

## F003: High-Risk Privileged CLI Backend with Command Injection Potential
- **Priority:** High  |  **Service:** nuevo80  |  **Binary:** `/bin/ltrx_cli`
- Runs as: `root`
- Network symbols: socket
- File-write symbols: chmod, fopen, fprintf, fputc, fputs, fwrite, open, vfprintf
- **Explanation:** The ltrx_cli binary, associated with the nuevo80 service, imports numerous file-writing and socket functions and runs as root. The binary contains strings suggesting it constructs shell commands for OpenSSL, shadow file parsing, and certificate management. The lack of authentication symbols combined with 'chmod' and 'fwrite' imports suggests an attacker who can reach the service's port might manipulate system-critical files or execute arbitrary commands.
- **Attack scenario:** An attacker interacts with the CLI service and provides malicious input that is concatenated into an internal 'openssl' or 'cat /etc/shadow' command string, resulting in root-level command execution.
- **Permanent fix:** Refactor the binary to use direct library APIs (such as OpenSSL's C API) instead of constructing shell commands via system() or popen(), and implement a robust authentication layer.
- **Immediate mitigation:** Immediately firewall the service's listening port to allow access only from authorized administrative IP addresses.
- **Compromise indicators:** Unusual files in /tmp/ssl_work/, modified timestamps on /etc/shadow, or the presence of files matching the pattern /tmp/ssh_client_user_*.
- Supplementary: `{"interesting_strings": ["/tmp/ipc/cfg.ipc", "/tmp/ipc/as.ipc", "/tmp/ssh_%lu_%lu", "openssl dsaparam -out /tmp/dsaparam.pem %u", "openssl gendsa -out %s /tmp/dsaparam.pem", "openssl dsa -in %s -pubout > /tmp/publickey.pem", "ssh-keygen -f /tmp/publickey.pem -i -m pkcs8 > %s", "/http/config/en_US/varid_help.mtxt", "/var/run/mach10.pid", "/tmp/mach10.errors", "/tmp/last_fw_update", "/http/config/em`

## F004: Privileged DHCP/RA Daemon File Write Surface
- **Priority:** Medium  |  **Service:** odhcpd  |  **Binary:** `/usr/sbin/odhcpd`
- Runs as: `root`
- Network symbols: bind, getsockname, recvmsg, socket
- File-write symbols: fopen, fprintf, fputs, ftruncate, fwrite, open, rename
- **Explanation:** The odhcpd daemon manages DHCPv6 and Router Advertisements. It runs as root and writes state information (leases) to the filesystem. Although it is a standard OpenWrt daemon, its position as an unauthenticated network listener with root-level file write access (fopen, rename) makes it a critical target for local network attackers.
- **Attack scenario:** An attacker sends a flood of crafted DHCPv6 lease requests designed to exhaust filesystem space or exploit path traversal logic in how leases are recorded to disk.
- **Permanent fix:** Configure odhcpd to run within a chroot jail or use a dedicated unprivileged user for lease management tasks.
- **Immediate mitigation:** Isolate the device's management interface on a dedicated VLAN and disable IPv6 if it is not required for the specific deployment.
- **Compromise indicators:** Large numbers of lease files or corrupted lease databases in the service's designated storage directory.
- Supplementary: `{"versions": {"etc/openwrt_release": "DISTRIB_ID='Lantronix EDS5000'\nDISTRIB_RELEASE='2.3.0.0R7'\nDISTRIB_REVISION='r19685-512e76967f'\nDISTRIB_TARGET='ma35d1/som'\nDISTRIB_ARCH='aarch64_generic'\nDISTRIB_DESCRIPTION='Lantronix EDS5000 2.3.0.0R7'\nDISTRIB_TAINTS='no-all busybox'\nDISTRIB_SUPRT_URL='https://cdn.lantronix.com/wp-content/uploads/pdf/PMD-00226_A-EDS5000-Series-Device-Server-User-Guid`

## F005: Unauthenticated Privileged Network Listener (dsrcts_server)
- **Priority:** High  |  **Service:** dsrcts_server  |  **Binary:** `/usr/bin/dsrcts_server`
- Runs as: `root`
- Network symbols: accept, bind, listen, socket
- File-write symbols: fopen, fwrite
- **Explanation:** The dsrcts_server binary is a custom service that listens for incoming TCP connections (accept, listen) and performs file writes (fopen, fwrite) as the root user. The extremely low import count (25) suggests a simple, potentially custom-built network server that may lack the robust input validation and security controls found in more mature network services.
- **Attack scenario:** An attacker connects to the dsrcts_server port and sends a payload that is written directly to a root-owned file, such as a PID file or log, without proper path validation.
- **Permanent fix:** Implement a mandatory authentication handshake before any data processing and use O_NOFOLLOW when opening files to prevent symlink-based attacks.
- **Immediate mitigation:** Restrict network access to the service's port using the device's internal firewall (iptables) to prevent external connections.
- **Compromise indicators:** Unexpected modifications to files matching the pattern /var/run/slave_dsrcts_* or log entries indicating failed or malformed connections to this service.
- Supplementary: `{"interesting_strings": ["/var/run/slave_dsrcts_%u"], "versions": {"etc/openwrt_release": "DISTRIB_ID='Lantronix EDS5000'\nDISTRIB_RELEASE='2.3.0.0R7'\nDISTRIB_REVISION='r19685-512e76967f'\nDISTRIB_TARGET='ma35d1/som'\nDISTRIB_ARCH='aarch64_generic'\nDISTRIB_DESCRIPTION='Lantronix EDS5000 2.3.0.0R7'\nDISTRIB_TAINTS='no-all busybox'\nDISTRIB_SUPRT_URL='https://cdn.lantronix.com/wp-content/uploads/p`
