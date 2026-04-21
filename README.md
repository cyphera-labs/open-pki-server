# Cyphera Open PKI Server

Internal certificate authority for developers. Create CAs, issue certificates, manage revocation, and run mTLS — without fighting OpenSSL or depending on heavyweight enterprise platforms.

Works standalone or paired with [Cyphera Open KMIP Server](https://github.com/cyphera-labs/open-kmip-server) for end-to-end key management + certificate lifecycle.

## What it does

- Create root and intermediate CAs (Ed25519, ECDSA P-256/P-384)
- Issue server and client certificates with profile-based policy
- Issue from CSRs — private key never leaves the requester
- Revoke certificates with X.509 reason codes
- Publish signed CRLs per issuing CA
- OCSP responder for real-time revocation checks
- Embed CRL Distribution Points and OCSP URLs in issued certificates
- Track certificate lifecycle with audit events
- Browse everything from an embedded dashboard
- Expose Prometheus metrics for monitoring
- Single binary. SQLite. No external dependencies.

## Install

```bash
go install github.com/cyphera-labs/open-pki-server/cmd/open-pki@latest
```

Or use Docker:

```bash
docker run -d -p 8300:8300 -v pki-data:/data ghcr.io/cyphera-labs/open-pki-server
```

## Quick Start

```bash
# Create a root CA
open-pki init-ca --name my-root --out ./certs

# Issue a server certificate
open-pki issue-server-cert \
  --profile server \
  --cn localhost \
  --san localhost --san 127.0.0.1 \
  --out ./certs

# Issue a client certificate
open-pki issue-client-cert \
  --profile client \
  --cn my-service \
  --out ./certs

# Inspect it
open-pki inspect ./certs/localhost.pem

# Verify it
open-pki verify ./certs/localhost.pem --ca ./certs/ca.pem

# Start the server with dashboard
open-pki serve --db ./open-pki.db
```

Dashboard at [http://localhost:8300](http://localhost:8300).

## KMIP mTLS in 4 commands

```bash
open-pki init-ca --name kmip-root --out ./certs

open-pki issue-server-cert \
  --profile kmip-server \
  --cn localhost --san localhost --san 127.0.0.1 \
  --out ./certs

open-pki issue-client-cert \
  --profile kmip-client \
  --cn demo-client \
  --out ./certs

open-kmip-server \
  --cert ./certs/localhost.pem \
  --key ./certs/localhost-key.pem \
  --ca ./certs/ca.pem
```

## CLI Reference

```
open-pki init-ca                Create a self-signed root CA
open-pki init-intermediate      Create an intermediate CA signed by a parent
open-pki issue-server-cert      Issue a server certificate
open-pki issue-client-cert      Issue a client certificate
open-pki issue --csr <file>     Issue a certificate from a CSR
open-pki inspect <file>         Inspect a PEM certificate
open-pki verify <file> --ca     Verify a certificate against a CA
open-pki bundle <files...>      Create a trust bundle
open-pki revoke --serial        Revoke a certificate
open-pki crl --ca-id            Generate and export a CRL
open-pki list                   List certificates
open-pki list --status revoked  Filter by status
open-pki serve                  Start the server with REST API and dashboard
```

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/health` | Health check |
| `POST` | `/v1/ca/root` | Create root CA |
| `GET` | `/v1/ca` | List CAs |
| `GET` | `/v1/ca/{id}` | CA detail |
| `GET` | `/v1/ca/bundle` | Trust bundle (PEM) |
| `GET` | `/v1/ca/{id}/crl` | CRL (PEM) |
| `POST` | `/v1/certificates/issue` | Issue certificate |
| `POST` | `/v1/certificates/issue-csr` | Issue from CSR |
| `POST` | `/v1/certificates/renew` | Renew certificate |
| `GET` | `/v1/certificates` | List certificates |
| `GET` | `/v1/certificates/expiring` | Expiring soon |
| `GET` | `/v1/certificates/{serial}` | Certificate detail |
| `POST` | `/v1/certificates/{serial}/revoke` | Revoke |
| `GET` | `/crl/{id}.crl` | CRL (DER, public) |
| `POST` | `/ocsp` | OCSP responder (public) |
| `GET` | `/v1/inventory` | Asset inventory |
| `GET` | `/v1/audit` | Lifecycle events |
| `GET` | `/v1/stats` | Stats |
| `GET` | `/metrics` | Prometheus metrics |

## Certificate Profiles

| Profile | Type | Validity | EKU |
|---------|------|----------|-----|
| `server` | Server | 397 days | serverAuth |
| `client` | Client | 397 days | clientAuth |
| `kmip-server` | Server | 397 days | serverAuth |
| `kmip-client` | Client | 397 days | clientAuth |

KMIP profiles enforce SAN and subject validation rules.

## Revocation

Issued certificates include CRL Distribution Point extensions. Revocation is published through CRL and OCSP.

```bash
# Revoke
open-pki revoke --serial ABC123 --reason key_compromise

# Download CRL
curl -o root.crl http://localhost:8300/crl/1.crl

# Check via OCSP
openssl ocsp -issuer ca.pem -cert client.pem -url http://localhost:8300/ocsp
```

Supported reasons: `unspecified`, `key_compromise`, `ca_compromise`, `affiliation_changed`, `superseded`, `cessation_of_operation`, `certificate_hold`, `remove_from_crl`, `privilege_withdrawn`, `aa_compromise`.

## CA Hierarchy

```bash
# Root CA (long-lived, signs intermediates)
open-pki init-ca --name root --validity-days 3650 --out ./certs

# Intermediate CA (medium-lived, signs end-entity certs)
open-pki init-intermediate --name issuing-ca \
  --ca-cert ./certs/ca.pem --ca-key ./certs/ca-key.pem \
  --out ./certs

# End-entity certs signed by intermediate
open-pki issue-server-cert --cn app.internal \
  --ca-cert ./certs/issuing-ca.pem --ca-key ./certs/issuing-ca-key.pem \
  --out ./certs
```

## CSR-Based Issuance

For production use, generate the private key on the requesting system and send only the CSR:

```bash
# On the requesting system
openssl req -new -newkey ed25519 -keyout app-key.pem -out app.csr \
  -nodes -subj "/CN=my-app" -addext "subjectAltName=DNS:my-app.internal"

# On the PKI server — validates CSR against profile policy before signing
open-pki issue --csr app.csr --profile server \
  --ca-cert ca.pem --ca-key ca-key.pem --out ./issued
```

The CA never sees the private key.

## License

Apache License 2.0

## Links

- [Cyphera Labs](https://github.com/cyphera-labs) — open-source cryptography infrastructure
- [Open KMIP Server](https://github.com/cyphera-labs/open-kmip-server) — KMIP key management
- [KMIP Client Libraries](https://github.com/cyphera-labs) — Go, Java, Python, Node.js, Rust, .NET, PHP, Ruby, Swift
