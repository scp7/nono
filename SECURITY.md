# Security Policy

## Supported Versions

We are currently in alpha, so do not have specific versions, but we will once the first GA release is made. So security fixes are on a best efforts basis.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.** To protect our users and the integrity of the project, 
we follow a [Responsible Disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure) model. 

This means we keep details of a bug private until a fix is ready and users have had a reasonable amount of time to update.

### How to Report

If you discover a potential security flaw, please report it via one of the following channels:

* **GitHub Security Advisory (Preferred):** Navigate to the "Security" tab of this repository and select "Report a vulnerability." This allows for private collaboration between you and the maintainers.

### What to Include

To help us triage the issue quickly, please include:

1. A brief description of the vulnerability.
2. Step-by-step instructions to reproduce the issue (PoC).
3. The potential impact (e.g., "unauthenticated remote code execution").

---

## Our Process

Once a report is received, the maintainers will:

1. **Acknowledge:** Confirm receipt of the report within 48 hours.
2. **Triage:** Investigate the issue and determine the severity.
3. **Fix:** Develop a patch in a private fork/branch.
4. **Disclose:** Once the fix is merged and a new release is published, we will issue a **CVE** (Common Vulnerabilities and Exposures) and publicly credit you for the discovery (unless you prefer to remain anonymous).

> **Note:** We ask that you do not share details of the vulnerability with the public or any third party until we have released a fix. Premature disclosure puts all current users at risk.

---

## Why Responsible Disclosure Matters

When a bug is made public before a patch exists, it creates a "Zero-Day" scenario. This gives malicious actors a blueprint to attack systems before maintainers can build a defense. By keeping bugs private at first, we ensure that the "good guys" have the upper hand.

