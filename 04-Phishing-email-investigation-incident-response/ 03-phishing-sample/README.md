# Phishing Sample

## Description

This directory contains the synthetic phishing email artifact used in the SOC investigation.

The email was intentionally created as a controlled laboratory sample to simulate a phishing message targeting an organizational user.

## Sample Type

**Artifact Type:** Synthetic phishing email

**File:** `suspicious-email.eml`

**Investigation Type:** Phishing Email Investigation

## Purpose

The purpose of the sample is to provide an email artifact that can be analyzed for:

- Sender identity
- Sender domain
- Subject
- Social engineering indicators
- Suspicious URLs
- Email headers
- Potential Indicators of Compromise

## Simulated Scenario

The simulated email impersonates a Microsoft 365 security notification and attempts to create urgency by requesting immediate account verification.

The sender uses a lookalike domain and the message contains a suspicious account verification URL.

## Safety

This sample is designed for cybersecurity training and investigation purposes.

The domain and URL used in the sample are synthetic laboratory indicators.

No real credentials are requested or collected.

The suspicious URL should not be accessed directly.

## Evidence

The original visual evidence of the email is available in:

`../screenshots/01-phishing-email.png`

## Investigation

The detailed analysis of this email is available in:

`../04-email-analysis/email-analysis.md`
