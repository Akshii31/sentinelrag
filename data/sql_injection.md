# Suspected SQL Injection Activity

## Initial assessment
Review web application logs for unusual query parameters, repeated database errors, unexpected input patterns, and requests to sensitive endpoints. Correlate timestamps, request identifiers, user accounts, source addresses, and application/database alerts. A suspicious string alone does not prove that injection succeeded.

## Containment and remediation
Escalate to the application security or incident response team. Preserve logs before changing systems. The development team should review affected code for unsafe query construction and prefer parameterized queries or prepared statements. Do not run exploit payloads against production systems without explicit written authorization and an approved test plan.

## Evidence to preserve
Keep relevant HTTP request metadata, application error details, database audit records where available, software version, and deployment timeline. Avoid recording unnecessary personal data or credentials in the incident report.
