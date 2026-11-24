# Threat Intelligence Analysis

## Objective

The objective of this stage was to determine whether the indicators extracted from the phishing email have previously been associated with malicious activity.

## Indicator 1: micr0soft-example.com

**Indicator Type:** Domain

**Assessment:** Suspicious based on email analysis.

**Threat Intelligence Result:**

The domain is part of the controlled laboratory phishing scenario. No production malicious reputation is being claimed from this synthetic indicator.

**Analyst Assessment:**

The domain remains suspicious because it was deliberately designed to imitate the Microsoft brand through a lookalike spelling.

## Indicator 2: login-m365-verification.example

**Indicator Type:** URL

**Assessment:** Suspicious.

**Threat Intelligence Result:**

The URL is a synthetic laboratory indicator and is not being presented as a confirmed malicious production URL.

**Analyst Assessment:**

The URL remains suspicious because it attempts to create the appearance of a Microsoft account verification service while using a non-Microsoft domain.

## Threat Intelligence Conclusion

Threat intelligence did not provide production reputation evidence for the synthetic indicators used in this laboratory exercise.

However, the lack of reputation data does not make the email legitimate.

The phishing determination is based on multiple contextual indicators, including brand impersonation, a lookalike sender domain, urgency, account verification pressure, and a suspicious external URL.

This demonstrates the importance of combining threat intelligence with email analysis rather than relying exclusively on reputation databases.
