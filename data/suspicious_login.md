# Suspicious Login and Brute-Force Triage

## Initial assessment
Review the alert timestamp, account, source IP, authentication result, device, and whether multi-factor authentication was completed. Compare the event with the account's expected working pattern and known approved access methods. A single unusual login is an indicator to investigate, not proof of compromise.

## Containment and account safety
Notify the authorised identity or security team. Follow the organisation's approved account-protection playbook before disabling accounts or revoking sessions. If the account owner confirms the activity was not theirs, escalate promptly for an authorised credential reset and session review.

## Evidence to preserve
Record relevant identity-provider events, source addresses, timestamps, user agent or device details where available, MFA outcome, and related alerts. Preserve logs according to retention policy and limit access to the investigation record.
