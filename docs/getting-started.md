# Getting Started

## Install

### Docker (recommended)

```bash
docker run -d -p 8300:8300 ghcr.io/cyphera-labs/open-pki-server
```

### From source

```bash
go install github.com/cyphera-labs/open-pki-server/cmd/open-pki@latest
```

## Quick Start

### Create a Root CA

```bash
open-pki init-ca --name my-root --out ./certs
```

Creates `ca.pem` and `ca-key.pem` in `./certs/`.

### Issue a Server Certificate

```bash
open-pki issue-server-cert \
  --profile server \
  --cn localhost \
  --san localhost --san 127.0.0.1 \
  --ca-cert ./certs/ca.pem --ca-key ./certs/ca-key.pem \
  --out ./certs
```

### Issue a Client Certificate

```bash
open-pki issue-client-cert \
  --profile client \
  --cn my-service \
  --ca-cert ./certs/ca.pem --ca-key ./certs/ca-key.pem \
  --out ./certs
```

### Issue from a CSR

```bash
# On the requesting system — private key stays here
openssl req -new -newkey ed25519 -keyout app-key.pem -out app.csr \
  -nodes -subj "/CN=my-app" -addext "subjectAltName=DNS:my-app.internal"

# On the PKI server — validates CSR against profile before signing
open-pki issue --csr app.csr --profile server \
  --ca-cert ca.pem --ca-key ca-key.pem --out ./issued
```

### Inspect a Certificate

```bash
open-pki inspect ./certs/localhost.pem
```

### Verify Against CA

```bash
open-pki verify ./certs/localhost.pem --ca ./certs/ca.pem
```

## Server Mode

Start the REST API and dashboard:

```bash
open-pki serve --db ./open-pki.db
```

Dashboard at http://localhost:8300/.

### With Authentication

```bash
open-pki serve --db ./open-pki.db --api-key my-secret
```

### Via REST API

```bash
# Create a root CA
curl -X POST http://localhost:8300/v1/ca/root \
  -d '{"name":"api-root","algorithm":"ed25519"}'

# Issue a certificate
curl -X POST http://localhost:8300/v1/certificates/issue \
  -d '{"ca_id":1,"common_name":"localhost","sans":["localhost","127.0.0.1"],"profile":"server"}'

# Revoke
curl -X POST http://localhost:8300/v1/certificates/$SERIAL/revoke \
  -d '{"reason":"key_compromise"}'

# Download CRL
curl -o root.crl http://localhost:8300/crl/1.crl
```

## CA Hierarchy

```bash
# Root CA (long-lived)
open-pki init-ca --name root --validity-days 3650 --out ./certs

# Intermediate CA (medium-lived, signed by root)
open-pki init-intermediate --name issuing-ca \
  --ca-cert ./certs/ca.pem --ca-key ./certs/ca-key.pem \
  --out ./certs

# End-entity certs signed by intermediate
open-pki issue-server-cert --cn app.internal \
  --ca-cert ./certs/issuing-ca.pem --ca-key ./certs/issuing-ca-key.pem \
  --out ./certs
```

## mTLS with Open KMIP Server

```bash
open-pki init-ca --name kmip-root --out ./certs

open-pki issue-server-cert --profile kmip-server \
  --cn localhost --san localhost --san 127.0.0.1 --out ./certs

open-pki issue-client-cert --profile kmip-client \
  --cn demo-client --out ./certs

open-kmip --cert ./certs/localhost.pem --key ./certs/localhost-key.pem \
  --ca ./certs/ca.pem --api-key my-secret
```

## Dashboard

- In dev mode (no `--api-key`): loads directly with DEV MODE banner
- In production mode: shows login screen

Pages: Overview, Certificates (with status filters), Certificate Authorities (with CRL download), Audit Log.

## Certificate Profiles

| Profile | Type | Validity | EKU |
|---------|------|----------|-----|
| `server` | Server | 397 days | serverAuth |
| `client` | Client | 397 days | clientAuth |
| `kmip-server` | Server | 397 days | serverAuth |
| `kmip-client` | Client | 397 days | clientAuth |

KMIP profiles enforce SAN and subject validation rules.
