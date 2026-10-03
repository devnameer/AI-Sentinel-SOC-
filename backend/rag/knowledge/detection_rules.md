# Detection rules and model signals

The Behavior Agent combines an Isolation Forest anomaly score with explainable rule signals. Every flagged session lists the rules that fired. This page explains each rule.

## login_outside_normal_hours

The session started far from the user's usual login hour. The distance is measured on a 24-hour circle (23:00 and 01:00 are two hours apart) and divided by the user's own variability, so a night-shift worker is not flagged for working at night.

## unknown_device

The workstation is not in the user's list of known devices. Common benign causes: hot-desking, a new laptop. Malicious causes: using a colleague's machine, impersonation (CERT scenario 3).

## file_download_volume_extreme

The number of files accessed is more than four standard deviations above the user's baseline mean. Bulk file access often precedes exfiltration.

## high_sensitivity_file_access

Files above the user's typical sensitivity or role ceiling were accessed. Sensitivity is derived from file type and path (for example .key, .pem, finance, hr, confidential).

## usb_device_connected and usb_first_time

A removable USB device was connected. A first-ever USB connection for a user is a much stronger signal than routine USB use by someone who uses USB every day.

## external_email_recipient

An e-mail was sent outside the organisation's domain. On its own this is common; combined with job-search browsing or USB use it matches CERT scenario 2.

## exfil_domain_visited and jobsearch_domain_visited

A known leak or file-sharing site was visited (strong signal), or a job-search site (weak signal on its own, meaningful in combination).

## How the anomaly score is computed

- Isolation Forest score: 0 (typical) to 1 (very unusual) for the 18 session features compared with the training population.
- Rule score: weighted sum of the binary signals above (weights in config.yaml › ml.behavior.rule_weights).
- Hybrid score (default) = 0.4 × Isolation Forest + 0.6 × rule score. On the labelled CERT sessions this ranks insider sessions better than the Isolation Forest alone (see README › Machine learning).
- A session is flagged when its score is at least the anomaly threshold (default 0.4).

## Network rules

- amplification_ratio / known_attack_port: UDP traffic to an amplification port with responses more than 10× larger than requests.
- syn_no_response: many TCP attempts without any response bytes.
- port_scan_pattern: 15 or more distinct destination ports on one target host in one window.
- isolation_forest_anomaly / catboost_attack: the two machine-learning stages of the network model.
