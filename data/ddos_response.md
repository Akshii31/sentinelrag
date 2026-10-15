# Suspected Distributed Denial of Service (DDoS)

## Initial assessment
Check service availability, request and connection rates, latency, error rates, bandwidth, geographic patterns, and provider alerts. Compare current indicators with a known baseline and confirm whether the impact is limited to one service or broader infrastructure.

## Response
Notify the on-call infrastructure or security team and the upstream network or hosting provider when the service is materially affected. Apply only approved traffic-management controls, such as provider-supported mitigation profiles or rate limits. Preserve normal business traffic where possible and avoid ad hoc blocking that could disrupt legitimate users.

## Evidence and communications
Record the incident timeline, affected endpoints, traffic graphs, top-level request patterns, mitigation changes, and service impact. Use the approved status-communication process. Continue monitoring after mitigation and document when service returns to expected levels.
