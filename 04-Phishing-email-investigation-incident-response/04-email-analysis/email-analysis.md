# Email Analysis

## 1. Initial Email Review

The email was reviewed as part of a simulated Tier 1 SOC phishing investigation.

The message claims to originate from Microsoft 365 Security and instructs the recipient to verify their account immediately.

The initial review identified several characteristics commonly associated with phishing activity.

## 2. Sender Analysis

**Displayed Sender:**

Microsoft 365 Security

**Sender Email:**

security@micr0soft-example.com

**Observed Domain:**

micr0soft-example.com

The sender domain is suspicious because it uses a lookalike spelling of the legitimate Microsoft brand. The use of "0" instead of "o" is a potential typosquatting or impersonation indicator.

The sender identity therefore requires further investigation.

## 3. Subject Analysis

**Subject:**

Urgent: Account Verification Required

The subject creates a sense of urgency and suggests that immediate action is required.

Urgency is commonly used in phishing emails to encourage recipients to act before carefully evaluating the message.

## 4. Message Content Analysis

The message informs the recipient that their Microsoft 365 account requires immediate verification and warns that failure to act may result in account suspension.

The message therefore uses:

- Urgency
- Fear of account suspension
- Brand impersonation
- A request for account verification

These characteristics increase the likelihood that the message is a phishing attempt.

## 5. URL Analysis

The message contains the following URL:

https://login-m365-verification.example

The URL does not use an official Microsoft domain.

The domain is therefore considered suspicious and should not be accessed directly.

The URL will be treated as an Indicator of Compromise (IOC) for further investigation.

## 6. Authentication Analysis

Because this email was created as a controlled laboratory artifact, SPF, DKIM, and DMARC results were not independently validated.

In a production SOC environment, these authentication results would be reviewed from the original email headers to determine whether the sending infrastructure was authorized and whether the message passed or failed domain authentication.

## 7. Initial Assessment

Based on the sender domain, urgency, brand impersonation, and suspicious URL, the email is considered suspicious and will be investigated as a potential phishing attempt.

Further investigation will focus on IOC extraction, threat intelligence enrichment, user interaction, endpoint telemetry, and SIEM correlation.
