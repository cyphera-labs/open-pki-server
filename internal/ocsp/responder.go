package ocsp

import (
	"crypto"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"time"

	gocsp "golang.org/x/crypto/ocsp"

	"github.com/cyphera-labs/open-pki-server/internal/storage"
)

// Responder handles OCSP requests.
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

// CAContext holds the CA cert and key needed to sign OCSP responses.
type CAContext struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
}

// Handle processes an OCSP POST request.
func (resp *Responder) Handle(caCtx *CAContext) http.HandlerFunc {
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

		// DB stores serials as uppercase hex
		serialHex := strings.ToUpper(ocspReq.SerialNumber.Text(16))

		now := time.Now().UTC()
		template := gocsp.Response{
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   now,
			NextUpdate:   now.Add(time.Duration(resp.validityMinutes) * time.Minute),
			Certificate:  caCtx.Certificate,
		}

		certRec, err := resp.store.GetCertBySerial(serialHex)
		if err != nil {
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
			default:
				template.Status = gocsp.Good
			}
		}

		respBytes, err := gocsp.CreateResponse(caCtx.Certificate, caCtx.Certificate, template, caCtx.PrivateKey)
		if err != nil {
			http.Error(w, "failed to create OCSP response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(respBytes)
	}
}
