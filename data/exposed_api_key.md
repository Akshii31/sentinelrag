# Exposed API Key or Credential Leak

## Immediate response
Treat a credential found in a public repository, message, log, or ticket as potentially exposed. An API key or access token published in a public repository must be treated as exposed until an authorised owner confirms containment. Notify the credential owner and security team using the approved incident channel. Do not paste the secret into additional tickets, chat rooms, or public websites.

## Containment
An authorised owner should revoke or rotate the affected credential using the relevant provider's supported controls. Update dependent applications through the approved change process, then verify that the replacement works and the old credential no longer grants access. Do not attempt to use the exposed secret to test access unless explicitly authorised.

## Evidence and follow-up
Record the type of credential, discovery time, exposure location, affected service, revocation status, and dependent systems without copying the secret into the incident record. Review repository history and logs according to the organisation's procedures. Store future credentials in an approved secrets manager or protected environment configuration.
