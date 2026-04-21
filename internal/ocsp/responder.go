package ocsp

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"time"

	gocsp "golang.org/x/crypto/ocsp"

	"github.com/cyphera-labs/open-pki-server/internal/storage"
)

// Responder handles OCSP requests with proper issuer matching.
type Responder struct {
	store           *storage.Store
	validityMinutes int
}

// NewResponder creates an OCSP responder.
func NewResponder(store *storage.Store, validityMinutes int) *Responder {
	if validityMinutes <= 0 {
		validityMinutes = 60
	}
	return &Responder{store: store, validityMinutes: validityMinutes}
}

// caKeyPair holds a loaded CA cert + private key for signing OCSP responses.
type caKeyPair struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// Handler returns an HTTP handler for OCSP POST requests.
// Matches the issuer from the OCSP request against stored CAs.
func (resp *Responder) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required for OCSP", http.StatusMethodNotAllowed)
			return
		}

		reqBytes, err := io.ReadAll(io.LimitReader(r.Body, 10240))
		if err != nil {
			http.Error(w, "failed to read request", http.StatusBadRequest)
			return
		}

		ocspReq, err := gocsp.ParseRequest(reqBytes)
		if err != nil {
			http.Error(w, "invalid OCSP request", http.StatusBadRequest)
			return
		}

		// Match issuer CA from the OCSP request
		issuerCA, err := resp.matchIssuer(ocspReq)
		if err != nil {
			// Can't match issuer — return unauthorized (no CA found)
			ocspResp := gocsp.Response{
				Status:       gocsp.Unknown,
				SerialNumber: ocspReq.SerialNumber,
				ThisUpdate:   time.Now().UTC(),
				NextUpdate:   time.Now().UTC().Add(time.Duration(resp.validityMinutes) * time.Minute),
			}
			// Can't sign without a CA — return tryLater
			http.Error(w, "issuer CA not found", http.StatusNotFound)
			_ = ocspResp // avoid unused
			return
		}

		serialHex := strings.ToUpper(ocspReq.SerialNumber.Text(16))

		now := time.Now().UTC()
		template := gocsp.Response{
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   now,
			NextUpdate:   now.Add(time.Duration(resp.validityMinutes) * time.Minute),
			Certificate:  issuerCA.cert,
		}

		certRec, err := resp.store.GetCertBySerial(serialHex)
		if err != nil {
			template.Status = gocsp.Unknown
		} else {
			// Check if cert was issued by this CA
			if certRec.CAID != resp.getCAID(issuerCA.cert) {
				template.Status = gocsp.Unknown
			} else {
				switch certRec.Status {
				case "revoked":
					template.Status = gocsp.Revoked
					if certRec.RevokedAt != nil {
						template.RevokedAt = *certRec.RevokedAt
					}
					if code, ok := storage.RevocationReasonCode[certRec.RevocationReason]; ok {
						template.RevocationReason = code
					}
				case "expired":
					// Expired certs are not revoked but should not return Good
					template.Status = gocsp.Unknown
				default:
					// Check temporal validity — if NotAfter has passed, cert is expired
					if certRec.NotAfter.Before(now) {
						template.Status = gocsp.Unknown
					} else {
						template.Status = gocsp.Good
					}
				}
			}
		}

		respBytes, err := gocsp.CreateResponse(issuerCA.cert, issuerCA.cert, template, issuerCA.key)
		if err != nil {
			http.Error(w, "failed to create OCSP response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(respBytes)
	}
}

// matchIssuer finds the CA that matches the OCSP request's issuer key hash.
func (resp *Responder) matchIssuer(ocspReq *gocsp.Request) (*caKeyPair, error) {
	cas, err := resp.store.ListCAs()
	if err != nil || len(cas) == 0 {
		return nil, err
	}

	for _, caRec := range cas {
		block, _ := pem.Decode([]byte(caRec.CertificatePEM))
		if block == nil {
			continue
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		// Match by issuer key hash (SHA-1 of the public key, per RFC 6960)
		pubKeyHash := sha1.Sum(caCert.RawSubjectPublicKeyInfo)
		if ocspReq.IssuerKeyHash != nil && len(ocspReq.IssuerKeyHash) > 0 {
			// Compare hashes
			match := true
			if len(pubKeyHash) >= len(ocspReq.IssuerKeyHash) {
				for i := range ocspReq.IssuerKeyHash {
					if pubKeyHash[i] != ocspReq.IssuerKeyHash[i] {
						match = false
						break
					}
				}
			} else {
				match = false
			}
			if !match {
				continue
			}
		}

		// Load private key
		keyPEM, err := resp.store.GetKey("ca", caRec.ID)
		if err != nil {
			continue
		}
		keyBlock, _ := pem.Decode([]byte(keyPEM))
		if keyBlock == nil {
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			continue
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			continue
		}

		return &caKeyPair{cert: caCert, key: signer}, nil
	}

	// No issuer match found — return error instead of silently using wrong CA
	return nil, fmt.Errorf("no CA matches OCSP request issuer key hash")
}

// getCAID returns the DB ID for a CA cert (by matching serial).
func (resp *Responder) getCAID(cert *x509.Certificate) int64 {
	cas, _ := resp.store.ListCAs()
	serial := strings.ToUpper(cert.SerialNumber.Text(16))
	for _, ca := range cas {
		if ca.Serial == serial {
			return ca.ID
		}
	}
	return 0
}
