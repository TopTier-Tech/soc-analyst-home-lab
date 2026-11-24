# Incident Response

## 1. Identification

The email was identified as a suspected phishing message based on multiple indicators, including a lookalike sender domain, urgency, brand impersonation, and a suspicious account verification URL.

## 2. Containment

Recommended containment actions include:

- Quarantine the suspicious email.
- Search the environment for duplicate messages.
- Identify other recipients.
- Block confirmed malicious domains or URLs.
- Investigate affected endpoints.
- Review authentication activity for affected users.

## 3. Credential Protection

If a user entered credentials into a confirmed malicious website, the affected account should be secured immediately.

Recommended actions include:

- Reset the affected password.
- Revoke active sessions where appropriate.
- Review recent authentication activity.
- Review mailbox forwarding rules.
- Investigate suspicious account changes.

## 4. Eradication

Remove identified phishing messages from affected mailboxes.

Remove any malicious files associated with the incident.

Block confirmed malicious infrastructure.

Investigate and remediate compromised endpoints where applicable.

## 5. Recovery

After containment and eradication:

- Confirm that the phishing email has been removed.
- Confirm that affected accounts are secure.
- Confirm that endpoints show no continuing malicious activity.
- Continue monitoring relevant authentication and endpoint telemetry.

## 6. Detection Improvement

The SOC should consider improving detection rules for:

- Lookalike domains
- Suspicious account verification emails
- Suspicious URLs
- Phishing-related browser activity
- Unusual process execution following browser activity
- Suspicious PowerShell execution

## 7. Escalation

If evidence indicates credential compromise, malware execution, account takeover, or confirmed endpoint compromise, the incident should be escalated to the appropriate Tier 2 or incident response team.
