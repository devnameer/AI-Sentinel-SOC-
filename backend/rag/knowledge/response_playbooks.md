# Response playbooks

The Response Agent recommends one of four actions. In this platform actions are recorded and shown to the analyst; nothing is pushed to real firewalls or identity systems (integration points are documented in the README).

## ALLOW

Use for low-risk events that match the user's normal behaviour. Log the event for the audit trail. No user impact.

## MONITOR

Use for medium-risk events with weak or single signals. Increase logging for the user or host for 24–72 hours, add the user to a watch list, and re-evaluate if further signals appear. Repeated medium-risk events within 24 hours escalate automatically (repeat-offender rule).

## ESCALATE

Use when several independent signals agree or the asset is sensitive. Open an incident for a human analyst, attach the evidence (triggered rules, baseline comparison, model scores), notify the team lead, and decide on containment within the response SLA.

## BLOCK

Use for high-risk, high-confidence events such as confirmed exfiltration or impersonation. Containment options: disable the account or force re-authentication with MFA, revoke sessions, block removable storage, isolate the host from the network. BLOCK always requires analyst approval unless auto-execution is explicitly enabled in config.yaml.

## Playbook — suspected USB / web exfiltration (T1052.001, T1567)

1. Confirm the device and destination (USB serial, upload domain).
2. Determine what was accessed: file count and sensitivity compared with the baseline.
3. Contact the user's manager; do not alert the user before evidence is preserved.
4. Contain: block removable storage and the upload destination for the account.
5. Preserve evidence: proxy logs, device logs, file access logs.

## Playbook — suspected account misuse / impersonation (T1078, T1056.001)

1. Verify with the account owner out of band (phone, in person).
2. Force password reset and MFA re-enrolment; revoke active sessions.
3. Isolate the workstation where the misuse started and scan it for keyloggers.
4. Review mass e-mails or messages sent from the account and warn recipients.

## Playbook — network flood or amplification (T1498)

1. Identify the target service and the traffic pattern (ports, byte ratio).
2. Rate-limit or filter at the network edge; involve the ISP or DDoS provider for volumetric attacks.
3. Check whether internal hosts act as open reflectors and close them.

## Playbook — port scanning (T1046)

1. Identify the scanning source. If it is internal, treat the host as possibly compromised and investigate it.
2. Block external scanners at the firewall if scanning persists.
3. Review exposed services on the target and close what is not needed.
