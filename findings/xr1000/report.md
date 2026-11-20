# Firmware scan: XR1000-V1.0.64.18_5.0.19.chk

- SHA256: `9ddf9e3aa4be29c4c9b12f4639fb465b0fff52d316898ea30b90fe12d2de5396`
- Rootfs: `work/scans/xr1000/extracted/rootfs/carved-ubi-3a-383000`
- Services enumerated: 23
- Binaries analyzed: 23
- Candidate findings: 8

**Summary:** The structural analysis of XR1000 firmware version V1.0.64.18_5.0.19 identifies several high-risk services (UPAgent, XAgent, utelnetd) running as root with network listeners and file-write capabilities but lacking authentication or privilege separation symbols. Specifically, XAgent and remGenie demonstrate the ability to modify critical configuration files in /etc/ while exposed to network inputs. Several monitoring services (arpwatch, ctwatch) appear to have limited risk, likely restricted to internal logging.

## F001: Unauthenticated Root File Write in UPAgent
- **Priority:** High  |  **Service:** UPAgent  |  **Binary:** `/usr/bin/upagent`
- Runs as: `root`
- Network symbols: accept, bind, listen, socket, socketpair
- File-write symbols: fopen, fprintf, fputs, open, vfprintf
- **Explanation:** The UPAgent service listens on the network and runs with full root privileges without any detected authentication or privilege-dropping logic. It imports functions that allow it to create and write to files, creating a risk where a remote user could potentially overwrite system files.
- **Attack scenario:** A remote attacker sends a crafted network packet to the UPAgent service's listening port, exploiting the lack of authentication to overwrite arbitrary system files via the vfprintf or open functions.
- **Permanent fix:** Implement robust challenge-response authentication for all network commands and transition the service to run as a dedicated non-privileged user instead of root.
- **Immediate mitigation:** Use the device's internal firewall to block network access to the UPAgent service's port from the WAN and untrusted LAN segments.
- **Compromise indicators:** Check for the existence of unexpected files in /tmp/upagent or modification timestamps on /tmp/libXhdlr.log that do not align with legitimate device activity.
- Supplementary: `{"interesting_strings": ["/tmp/libXhdlr.log", "/tmp/upagent"]}`

## F002: Privileged Configuration Overwrite in XAgent
- **Priority:** High  |  **Service:** XAgent  |  **Binary:** `/opt/xagent/xagent`
- Runs as: `root`
- Network symbols: SSL_read, accept, bind, listen, socket
- File-write symbols: fopen, fprintf, fwrite, open, rename, vfprintf
- **Explanation:** XAgent is a root-level service that uses SSL for communication but lacks internal authentication symbols, and it possesses the capability to write and rename files in sensitive locations like /etc/. This could allow an attacker to redirect device traffic by modifying system configuration files.
- **Attack scenario:** An attacker leverages an unauthenticated SSL connection to XAgent to trigger a file write that replaces /etc/resolv.conf, thereby hijacking the device's DNS resolution.
- **Permanent fix:** Adopt a least-privilege model by using a non-root account for XAgent and implement strict path validation to prevent writing outside of designated temporary directories.
- **Immediate mitigation:** Disable remote management features that rely on XAgent if not required and restrict access to the service's port to known administrative IP addresses.
- **Compromise indicators:** Inspect /etc/xagent.conf and /etc/resolv.conf for unauthorized changes or entries, and check /tmp/xagent.log for unusual error messages or connection attempts.
- Supplementary: `{"interesting_strings": ["/etc/xagent.conf", "/etc/resolv.conf", "/tmp/xagent.log", "/tmp/xagent.pid", "/tmp/xagent_watchdog.pid"]}`

## F003: Restricted File Writing in arpwatch
- **Priority:** Low  |  **Service:** arpwatch  |  **Binary:** `/usr/bin/arpwatch`
- Runs as: `root`
- Network symbols: bind, recv, recvmsg, socket
- File-write symbols: fprintf, fputc, fwrite
- **Explanation:** While arpwatch runs as root and receives network data, its file-writing capabilities are limited to basic logging functions (fprintf, fputc). The risk is lower as it primarily interacts with internal sockets and lacks the 'open' symbol for creating new files.
- **Attack scenario:** An attacker on the local network sends a flood of ARP packets to exhaust disk space by forcing arpwatch to write excessive log data through its ubus connection.
- **Permanent fix:** Configure arpwatch to drop privileges to a 'nobody' or 'arpwatch' user after the initial socket binding.
- **Immediate mitigation:** Ensure the device is not reachable from untrusted local network segments where ARP spoofing or flooding could occur.
- **Compromise indicators:** Monitor for unusually large log files or high CPU usage associated with the /usr/bin/arpwatch process.
- Supplementary: `{"interesting_strings": ["/var/run/ubus.sock"]}`

## F004: Unauthenticated Root Telnet Access
- **Priority:** High  |  **Service:** bcm-wlan-drivers  |  **Binary:** `/usr/sbin/utelnetd`
- Runs as: `root`
- Network symbols: accept, bind, listen, socket
- File-write symbols: fopen, fprintf, fputc, fputs, open
- **Explanation:** The utelnetd binary provides a remote terminal interface running as root. The absence of authentication symbols within the binary itself suggests it relies on external mechanisms or may be completely unauthenticated, posing a critical risk of remote shell access.
- **Attack scenario:** An attacker connects to the device's Telnet port and gains immediate root shell access due to the service running with root privileges without enforced authentication.
- **Permanent fix:** Disable the utelnetd service entirely in production firmware and replace it with an encrypted, authenticated SSH daemon like Dropbear.
- **Immediate mitigation:** Disable the Telnet service through the web management interface or block the Telnet port (typically 23) at the network perimeter.
- **Compromise indicators:** Check the process list for active 'utelnetd' instances and examine /etc/issue.net for any modifications indicating a persistent banner change.
- Supplementary: `{"interesting_strings": ["/etc/issue.net"]}`

## F005: Privileged State Management in conntrackd
- **Priority:** Medium  |  **Service:** conntrackd  |  **Binary:** `/usr/sbin/conntrackd`
- Runs as: `root`
- Network symbols: accept, bind, listen, recv, recvfrom, socket
- File-write symbols: fopen, fprintf, fputc, fputs, fwrite, open, vfprintf
- **Explanation:** The conntrackd service manages network connection state and runs as root. It possesses extensive file-writing capabilities and listens for network data to synchronize state, but it lacks evidence of built-in authentication for these synchronization packets.
- **Attack scenario:** An attacker sends malicious state-synchronization packets to conntrackd's listening port to corrupt the kernel's connection tracking table or overwrite the /var/log/conntrackd.log file.
- **Permanent fix:** Enable cryptographically signed state synchronization and ensure the daemon drops privileges after initializing its netlink sockets.
- **Immediate mitigation:** Isolate the conntrackd synchronization traffic to a dedicated, private VLAN or use an internal firewall to restrict traffic to the synchronization port.
- **Compromise indicators:** Check /var/log/conntrackd.log and /var/log/conntrackd-stats.log for entries originating from unauthorized IP addresses.
- Supplementary: `{"interesting_strings": ["/etc/conntrackd/conntrackd.conf", "/var/log/conntrackd.log", "getprotobyname() cannot find protocol `%s' in /etc/protocols", "getprotobyname() cannot find protocol `tcp' in /etc/protocols", "getprotobyname() cannot find protocol `udp' in /etc/protocols", "/var/log/conntrackd-stats.log", "/var/lock/conntrackd.lock", "../../../libgcc/config/arm/lib1funcs.S", "../../../libgc`

## F006: Internal Monitoring Service Write Risk (ctwatch)
- **Priority:** Low  |  **Service:** ctwatch  |  **Binary:** `/usr/bin/ctwatch`
- Runs as: `root`
- Network symbols: bind, recv, socket
- File-write symbols: fprintf, fputc, fwrite
- **Explanation:** ctwatch appears to be an internal connection tracking monitor. It imports limited file-write symbols and interacts primarily with the internal ubus system, suggesting its external attack surface is minimal.
- **Attack scenario:** An attacker who has already gained limited access to the system uses the ubus socket to send messages that cause ctwatch to write data into its log streams.
- **Permanent fix:** Ensure the service runs under a restricted user account and that ubus access policies prevent unauthorized interaction with ctwatch.
- **Immediate mitigation:** Restrict access to the physical and logical management interfaces of the device.
- **Compromise indicators:** Check for existence or unusual growth of files related to connection tracking in /var/run/ or /var/log/.
- Supplementary: `{"interesting_strings": ["/var/run/ubus.sock"]}`

## F007: Unauthenticated System Management Messaging (smd)
- **Priority:** Medium  |  **Service:** hndmfg  |  **Binary:** `/bin/smd`
- Runs as: `root`
- Network symbols: accept, bind, listen, socket
- File-write symbols: fopen
- **Explanation:** The smd (System Management Daemon) service handles internal messaging and runs as root. It listens on the network and can create files like /tmp/smd_shutdown_in_progress, which could be abused to disrupt device operations.
- **Attack scenario:** An attacker sends a specific management command to the smd network listener to force a system shutdown or create a denial-of-service condition.
- **Permanent fix:** Implement a local-only socket for smd messaging or add a shared-secret authentication layer for network-based management commands.
- **Immediate mitigation:** Firewall the smd service port (identified by /var/smd_messaging_server_addr) to prevent any external interaction.
- **Compromise indicators:** Look for the file /tmp/smd_shutdown_in_progress which may indicate an attempt to use the daemon to reboot or shut down the device.
- Supplementary: `{"interesting_strings": ["/tmp/smd_shutdown_in_progress", "/var/smd_messaging_server_addr"]}`

## F008: Remote Configuration Manipulation in remGenie
- **Priority:** Medium  |  **Service:** remGenie  |  **Binary:** `/opt/xagent/genie_handler`
- Runs as: `root`
- Network symbols: socket
- File-write symbols: fopen, fprintf, fputs, rename, vfprintf
- **Explanation:** The remGenie service (genie_handler) runs as root and can rename and write files, specifically targeting the XAgent configuration. While it has fewer network symbols than others, its ability to modify /opt/xagent/etc/xagent.conf is a significant risk if its socket is reachable.
- **Attack scenario:** An attacker exploits a vulnerability in the genie_handler process to rename a malicious configuration file into /opt/xagent/etc/xagent.conf, changing the behavior of the XAgent management service.
- **Permanent fix:** Enforce strict file permissions on the /opt/xagent/etc/ directory and use O_NOFOLLOW to prevent symlink-based file write attacks.
- **Immediate mitigation:** Monitor the /tmp directory for unauthorized files starting with 'genie' and restrict the genie_handler process if it is not required for daily operations.
- **Compromise indicators:** Compare the current /opt/xagent/etc/xagent.conf with a known good backup and check /tmp/genie_handler.log for unexpected execution traces.
- Supplementary: `{"interesting_strings": ["/tmp/genie_handler.log", "/opt/xagent/etc/xagent.conf"]}`
