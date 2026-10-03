# CERT r4.2 insider threat dataset

The CERT Insider Threat Test Dataset (Carnegie Mellon University, Software Engineering Institute) is a synthetic but realistic corporate log dataset: logons, removable-device use, file access, e-mail and web browsing for 1,000 employees over roughly 17 months. Release r4.2 contains a small number of malicious insiders, each acting out one of the scenarios below. The answer key lists the user and the time window of the malicious activity.

## Scenario 1 — after-hours USB exfiltration to WikiLeaks

A user who previously did not use removable drives or work after hours begins logging in after hours, using a removable drive, and uploading data to wikileaks.org. The user leaves the organisation shortly afterwards. Strong indicators: first-time USB use, logons far outside the user's normal hours, visits to wikileaks.org. Relevant ATT&CK techniques: T1052.001 (Exfiltration over USB), T1567 (Exfiltration over Web Service).

## Scenario 2 — job hunting followed by data theft

A user begins browsing job-search websites and soliciting employment from a competitor. Before leaving the company, they use a thumb drive at markedly higher rates than their previous activity to steal data. Strong indicators: job-search domains (LinkedIn, Monster, Indeed…), increased USB use compared with the user's own history, external e-mail. Relevant technique: T1052.001.

## Scenario 3 — disgruntled administrator, keylogger and impersonation

A system administrator becomes disgruntled, downloads a keylogger and uses a thumb drive to transfer it to the supervisor's machine. The next day the administrator uses the collected keystrokes to log in as the supervisor and sends an alarming mass e-mail, then leaves the organisation. Strong indicators: logon on a workstation that is not one of the user's known devices, first-time USB use, after-hours activity, mass e-mail. Relevant techniques: T1056.001 (Keylogging), T1078 (Valid Accounts).

## How this platform uses the dataset

- Behaviour baselines for 1,001 users were learned from the CERT training period.
- The Live Events replay streams real labelled CERT sessions; the label is the insider time window from the answer key.
- The Attacker Agent builds controlled simulations of the three scenarios against the real baseline of a CERT insider user, so the detection models are tested against realistic deviations instead of hard-coded scores.
