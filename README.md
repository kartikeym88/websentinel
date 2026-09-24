# Web Application Security Assessment Platform

A defensive Web Application Security Assessment Platform for authorized/local testing.

## Overview

This tool is designed to help assess the security of web applications you are authorized to test. It provides a modular foundation for crawling, passive analysis, and integration with active scanning tools like OWASP ZAP.

**Note:** This tool is for authorized testing only. Do not scan arbitrary public websites without explicit permission.

## Requirements

- Python 3.9+
- See `requirements.txt` for dependencies.

## Installation

1. Clone the repository.
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and adjust the configuration.

## Architecture Pipeline

The application features a fully coherent scanning pipeline driven by the central `ScanManager`:

```text
CLI
 ↓
ScanManager
 ↓
Crawler (spider)
 ↓
Discovered Pages (CrawlResult)
 ↓
Analyzers (SecurityHeaderAnalyzer, CookieAnalyzer)
 ↓
FindingAggregator (Deterministic Deduplication & merging)
 ↓
Repository (Persistence Layer)
 ↓
SQLite (data/scanner.db)
```

## Passive Analysis

The platform includes a passive analysis mode that evaluates HTTP responses without sending malicious payloads:
- **Security Headers Analyzer:** Checks for missing or misconfigured headers like Content-Security-Policy (CSP), Strict-Transport-Security (HSTS, enforced on HTTPS), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Clickjacking protections (X-Frame-Options or CSP frame-ancestors).
- **Cookie Analyzer:** Inspects Set-Cookie headers for the presence of `Secure`, `HttpOnly`, and `SameSite` attributes, applying stricter severity rules for likely session cookies.

### Findings Severity and Confidence

- **Severity:** Represents the potential impact or risk of a vulnerability (e.g., `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Missing generic hardening headers are typically classified as `LOW` or `INFORMATIONAL`.
- **Confidence:** Represents the strength of the evidence (e.g., `LOW`, `MEDIUM`, `HIGH`). For passive header analysis, the confidence is usually `HIGH` because the header is verifiably present or absent.

## Usage

Basic connectivity check:

```bash
python scanner.py scan --target http://localhost:3000
```

Passive security analysis:

```bash
python scanner.py analyze --target http://localhost:3000
```

To see all available options:

```bash
python scanner.py --help
```
