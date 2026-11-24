# IOC Analysis

## Extracted Indicators of Compromise

The following indicators were extracted from the suspicious email during the initial investigation.

| IOC Type | Indicator | Reason for Investigation |
|---|---|---|
| Email Address | security@micr0soft-example.com | Suspicious sender identity |
| Domain | micr0soft-example.com | Lookalike/typosquatting domain |
| URL | https://login-m365-verification.example | Suspicious account verification URL |

## IOC Assessment

The sender address and domain are considered suspicious because they attempt to imitate a legitimate Microsoft-related identity.

The URL is also considered suspicious because it uses a non-Microsoft domain while presenting itself as an account verification service.

No IP address or file hash was extracted from the current email sample.

Additional indicators may be identified during threat intelligence and endpoint investigation.

## Investigation Handling

The identified indicators will be used during subsequent threat intelligence, endpoint, and Splunk investigations.

The suspicious URL will not be opened directly.
