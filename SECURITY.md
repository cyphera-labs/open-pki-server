# Security Policy

## Reporting Vulnerabilities

If you find a security vulnerability in this project, please report it responsibly.

**Email:** leslie.gutschow@horizondigital.dev

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

We will respond within 48 hours and provide a fix timeline.

## Scope

This policy covers:
- Cyphera Open PKI Server (`open-pki-server`)
- Certificate authority operations
- CRL and OCSP responder
- REST API
- Storage layer
- Authentication/session management

## Known Limitations (Alpha)

This project is in alpha. The following are known and tracked:

- CA private keys stored as plaintext PEM in SQLite (encryption planned)
- REST API runs over HTTP (TLS planned)
- Session tokens are not TLS-channel-bound
- No OIDC/SSO integration yet
- CLI-issued certificates are not stored in the database lifecycle

These are documented in our internal tracking and will be addressed before GA.
