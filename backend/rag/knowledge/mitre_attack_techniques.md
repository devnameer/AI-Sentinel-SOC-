# MITRE ATT&CK techniques covered by the platform

MITRE ATT&CK is a public knowledge base of adversary tactics and techniques. Each technique has an ID (for example T1052.001). The descriptions below are short summaries written for analysts using this platform.

## T1052.001 — Exfiltration over Physical Medium: USB

Adversaries (or malicious insiders) copy data to a removable USB device to move it out of the organisation, bypassing network monitoring. Detection: removable device connections, especially a user's first-ever USB use, combined with file activity above baseline or after-hours timing. Response: confirm with the user's manager, review files written to removable media, consider blocking removable storage for the account via device-control policy.

## T1567 — Exfiltration over Web Service

Data is uploaded to a legitimate web service (file sharing, paste sites, leak sites) to blend in with normal HTTPS traffic. Detection: visits to file-sharing or leak domains such as wikileaks.org, mega.nz or pastebin.com, particularly from accounts with no history of using them. Response: review proxy logs for upload volume, block the destination for the account, preserve evidence.

## T1056.001 — Input Capture: Keylogging

A keylogger records keystrokes to capture credentials. In CERT scenario 3 an administrator plants a keylogger on a supervisor's workstation via USB. Detection: removable media on a machine that is not the user's own, unexpected software, subsequent logons by the victim account from unusual devices. Response: isolate the affected workstation, reset the victim's credentials, image the machine for forensics.

## T1078 — Valid Accounts

Adversaries use legitimate credentials (stolen or misused) to log in, which makes activity look normal. Detection: logons from unknown devices, at unusual hours, or impossible combinations for the account; actions inconsistent with the account owner's role. Response: force a password reset and MFA re-enrolment, review recent activity for the account, verify with the owner out of band.

## T1005 — Data from Local System

Collection of files from local disks before exfiltration. Detection: file access volume far above the user's baseline and access to high-sensitivity files outside the user's normal ceiling. Response: review which files were accessed, check whether they left the system.

## T1498.002 — Network Denial of Service: Reflection Amplification

Attackers send small spoofed requests to reflectors (DNS, NTP, SSDP, SNMP, LDAP, memcached…) that send much larger responses to the victim. Detection: UDP traffic on amplification ports with a response-to-request byte ratio far above normal (often >10× and up to >50×). Response: rate-limit or filter the reflector traffic upstream, contact the ISP / DDoS protection provider, ensure internal services are not open reflectors.

## T1498.001 — Network Denial of Service: Direct Network Flood

Floods such as SYN floods exhaust the target's resources. Detection: many TCP connection attempts that never receive a response from one source, very high connection rates. Response: enable SYN cookies, rate-limit at the edge, block the offending sources.

## T1046 — Network Service Discovery

Scanning a host or network for open ports and services — usually reconnaissance before an attack. Detection: one source contacting many distinct destination ports on the same target in a short window. Response: identify the scanning host; if internal, investigate it for compromise; block if external.
