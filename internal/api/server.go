package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cyphera-labs/open-pki-server/internal/ca"
	"github.com/cyphera-labs/open-pki-server/internal/cert"
	"github.com/cyphera-labs/open-pki-server/internal/dashboard"
	"github.com/cyphera-labs/open-pki-server/internal/profile"
	"github.com/cyphera-labs/open-pki-server/internal/storage"
)

// Server is the REST API server.
type Server struct {
	store    *storage.Store
	profiles map[string]*profile.Profile
	mux      *http.ServeMux
	apiKey   string
}

// NewServer creates a new API server.
func NewServer(store *storage.Store, profiles map[string]*profile.Profile, apiKey string) *Server {
	s := &Server{
		store:    store,
		profiles: profiles,
		mux:      http.NewServeMux(),
		apiKey:   apiKey,
	}
	s.routes()
	return s
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	// Dashboard
	s.mux.Handle("/", dashboard.Handler())

	s.mux.HandleFunc("GET /v1/health", s.handleHealth)

	// CA
	s.mux.HandleFunc("POST /v1/ca/root", s.auth(s.handleCreateRootCA))
	s.mux.HandleFunc("GET /v1/ca", s.auth(s.handleListCAs))
	s.mux.HandleFunc("GET /v1/ca/{id}", s.auth(s.handleGetCA))
	s.mux.HandleFunc("GET /v1/ca/bundle", s.auth(s.handleCABundle))

	// Certificates
	s.mux.HandleFunc("POST /v1/certificates/issue", s.auth(s.handleIssueCert))
	s.mux.HandleFunc("GET /v1/certificates", s.auth(s.handleListCerts))
	s.mux.HandleFunc("GET /v1/certificates/expiring", s.auth(s.handleListExpiring))
	s.mux.HandleFunc("GET /v1/certificates/{serial}", s.auth(s.handleGetCert))
	s.mux.HandleFunc("POST /v1/certificates/{serial}/revoke", s.auth(s.handleRevokeCert))
	s.mux.HandleFunc("POST /v1/certificates/renew", s.auth(s.handleRenewCert))

	// CRL
	s.mux.HandleFunc("GET /v1/crl", s.auth(s.handleCRL))

	// Audit
	s.mux.HandleFunc("GET /v1/audit", s.auth(s.handleAudit))

	// Stats
	s.mux.HandleFunc("GET /v1/stats", s.auth(s.handleStats))
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token != s.apiKey {
				jsonError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// --- Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, map[string]string{"status": "ok"})
}

func (s *Server) handleCreateRootCA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		Algorithm    string `json:"algorithm"`
		ValidityDays int    `json:"validity_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	result, err := ca.InitRootCA(ca.InitRootCAOptions{
		Name:         req.Name,
		Algorithm:    req.Algorithm,
		ValidityDays: req.ValidityDays,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	caID, err := s.store.InsertCA(&storage.CARecord{
		Name:           req.Name,
		Type:           "root",
		Subject:        result.Certificate.Subject.String(),
		Serial:         fmt.Sprintf("%X", result.Certificate.SerialNumber),
		NotBefore:      result.Certificate.NotBefore,
		NotAfter:       result.Certificate.NotAfter,
		CertificatePEM: string(result.CertPEM),
		KeyRef:         "local",
		Status:         "active",
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = s.store.InsertKey("ca", caID, "local", string(result.KeyPEM), req.Algorithm)
	_ = s.store.InsertAudit("api", "ca.created", "ca", fmt.Sprintf("%d", caID), map[string]any{"name": req.Name})

	jsonResp(w, map[string]any{
		"id":      caID,
		"name":    req.Name,
		"serial":  fmt.Sprintf("%X", result.Certificate.SerialNumber),
		"subject": result.Certificate.Subject.String(),
		"expires": result.Certificate.NotAfter.Format(time.RFC3339),
	})
}

func (s *Server) handleListCAs(w http.ResponseWriter, r *http.Request) {
	cas, err := s.store.ListCAs()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, cas)
}

func (s *Server) handleGetCA(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		jsonError(w, "invalid CA ID", http.StatusBadRequest)
		return
	}
	rec, err := s.store.GetCA(id)
	if err != nil {
		jsonError(w, "CA not found", http.StatusNotFound)
		return
	}
	jsonResp(w, rec)
}

func (s *Server) handleCABundle(w http.ResponseWriter, r *http.Request) {
	cas, err := s.store.ListCAs()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	for _, c := range cas {
		w.Write([]byte(c.CertificatePEM))
	}
}

func (s *Server) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CAID    int64    `json:"ca_id"`
		CN      string   `json:"common_name"`
		SANs    []string `json:"sans"`
		Profile string   `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.CN == "" {
		jsonError(w, "common_name is required", http.StatusBadRequest)
		return
	}
	if req.Profile == "" {
		req.Profile = "server"
	}

	prof, ok := s.profiles[req.Profile]
	if !ok {
		jsonError(w, fmt.Sprintf("unknown profile: %s", req.Profile), http.StatusBadRequest)
		return
	}

	// Load CA from store
	caRec, err := s.store.GetCA(req.CAID)
	if err != nil {
		jsonError(w, "CA not found", http.StatusNotFound)
		return
	}
	keyPEM, err := s.store.GetKey("ca", caRec.ID)
	if err != nil {
		jsonError(w, "CA key not found", http.StatusInternalServerError)
		return
	}

	loadedCA, err := ca.LoadCAFromPEM([]byte(caRec.CertificatePEM), []byte(keyPEM))
	if err != nil {
		jsonError(w, fmt.Sprintf("load CA: %s", err), http.StatusInternalServerError)
		return
	}

	var dnsNames []string
	var ips []net.IP
	for _, san := range req.SANs {
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	certPEM, _, err := loadedCA.IssueCert(ca.IssueCertOptions{
		CommonName: req.CN,
		DNSNames:   dnsNames,
		IPs:        ips,
		Profile:    prof,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Parse the issued cert for storage
	block, _ := pem.Decode(certPEM)
	issuedCert, _ := x509.ParseCertificate(block.Bytes)
	fingerprint := sha256.Sum256(issuedCert.RawSubjectPublicKeyInfo)

	certID, err := s.store.InsertCert(&storage.CertRecord{
		CAID:                 caRec.ID,
		Serial:               fmt.Sprintf("%X", issuedCert.SerialNumber),
		Subject:              issuedCert.Subject.String(),
		CommonName:           req.CN,
		SANs:                 req.SANs,
		Profile:              req.Profile,
		NotBefore:            issuedCert.NotBefore,
		NotAfter:             issuedCert.NotAfter,
		CertificatePEM:       string(certPEM),
		PublicKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		Status:               "active",
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = s.store.InsertAudit("api", "cert.issued", "certificate", fmt.Sprintf("%d", certID), map[string]any{
		"cn": req.CN, "profile": req.Profile, "serial": fmt.Sprintf("%X", issuedCert.SerialNumber),
	})

	jsonResp(w, map[string]any{
		"id":          certID,
		"serial":      fmt.Sprintf("%X", issuedCert.SerialNumber),
		"common_name": req.CN,
		"profile":     req.Profile,
		"expires":     issuedCert.NotAfter.Format(time.RFC3339),
		"certificate": string(certPEM),
	})
}

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.store.ListCerts()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, certs)
}

func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	rec, err := s.store.GetCertBySerial(serial)
	if err != nil {
		jsonError(w, "certificate not found", http.StatusNotFound)
		return
	}
	jsonResp(w, rec)
}

func (s *Server) handleListExpiring(w http.ResponseWriter, r *http.Request) {
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			days = v
		}
	}
	certs, err := s.store.ListExpiring(days)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, certs)
}

func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	var req struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Reason == "" {
		req.Reason = "unspecified"
	}

	if err := s.store.RevokeCert(serial, req.Reason); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	_ = s.store.InsertAudit("api", "cert.revoked", "certificate", serial, map[string]any{"reason": req.Reason})

	jsonResp(w, map[string]string{"status": "revoked", "serial": serial})
}

func (s *Server) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Serial == "" {
		jsonError(w, "serial is required", http.StatusBadRequest)
		return
	}

	// Get the original cert
	orig, err := s.store.GetCertBySerial(req.Serial)
	if err != nil {
		jsonError(w, "certificate not found", http.StatusNotFound)
		return
	}
	if orig.Status != "active" {
		jsonError(w, "can only renew active certificates", http.StatusBadRequest)
		return
	}

	prof, ok := s.profiles[orig.Profile]
	if !ok {
		jsonError(w, fmt.Sprintf("profile %s not found", orig.Profile), http.StatusInternalServerError)
		return
	}

	// Load CA
	caRec, err := s.store.GetCA(orig.CAID)
	if err != nil {
		jsonError(w, "CA not found", http.StatusInternalServerError)
		return
	}
	keyPEM, err := s.store.GetKey("ca", caRec.ID)
	if err != nil {
		jsonError(w, "CA key not found", http.StatusInternalServerError)
		return
	}
	loadedCA, err := ca.LoadCAFromPEM([]byte(caRec.CertificatePEM), []byte(keyPEM))
	if err != nil {
		jsonError(w, fmt.Sprintf("load CA: %s", err), http.StatusInternalServerError)
		return
	}

	// Parse original cert for SANs
	origBlock, _ := pem.Decode([]byte(orig.CertificatePEM))
	origCert, _ := x509.ParseCertificate(origBlock.Bytes)

	certPEM, _, err := loadedCA.IssueCert(ca.IssueCertOptions{
		CommonName: orig.CommonName,
		DNSNames:   origCert.DNSNames,
		IPs:        origCert.IPAddresses,
		Profile:    prof,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(certPEM)
	newCert, _ := x509.ParseCertificate(block.Bytes)
	fingerprint := sha256.Sum256(newCert.RawSubjectPublicKeyInfo)

	newID, err := s.store.InsertCert(&storage.CertRecord{
		CAID:                 orig.CAID,
		Serial:               fmt.Sprintf("%X", newCert.SerialNumber),
		Subject:              newCert.Subject.String(),
		CommonName:           orig.CommonName,
		SANs:                 orig.SANs,
		Profile:              orig.Profile,
		NotBefore:            newCert.NotBefore,
		NotAfter:             newCert.NotAfter,
		CertificatePEM:       string(certPEM),
		PublicKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		Status:               "active",
		RenewedFromSerial:    orig.Serial,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Revoke the old cert
	_ = s.store.RevokeCert(orig.Serial, "superseded")

	_ = s.store.InsertAudit("api", "cert.renewed", "certificate", fmt.Sprintf("%d", newID), map[string]any{
		"old_serial": orig.Serial, "new_serial": fmt.Sprintf("%X", newCert.SerialNumber),
	})

	jsonResp(w, map[string]any{
		"id":                newID,
		"serial":            fmt.Sprintf("%X", newCert.SerialNumber),
		"renewed_from":      orig.Serial,
		"expires":           newCert.NotAfter.Format(time.RFC3339),
		"certificate":       string(certPEM),
	})
}

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	caIDStr := r.URL.Query().Get("ca_id")
	if caIDStr == "" {
		caIDStr = "1"
	}
	caID, _ := strconv.ParseInt(caIDStr, 10, 64)

	caRec, err := s.store.GetCA(caID)
	if err != nil {
		jsonError(w, "CA not found", http.StatusNotFound)
		return
	}
	keyPEM, err := s.store.GetKey("ca", caRec.ID)
	if err != nil {
		jsonError(w, "CA key not found", http.StatusInternalServerError)
		return
	}
	loadedCA, err := ca.LoadCAFromPEM([]byte(caRec.CertificatePEM), []byte(keyPEM))
	if err != nil {
		jsonError(w, fmt.Sprintf("load CA: %s", err), http.StatusInternalServerError)
		return
	}

	entries, err := s.store.ListRevoked(caID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var revokedCerts []x509.RevocationListEntry
	for _, e := range entries {
		serial := new(big.Int)
		serial.SetString(e.Serial, 16)
		revokedCerts = append(revokedCerts, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: e.RevokedAt,
		})
	}

	now := time.Now().UTC()
	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(time.Now().Unix()),
		ThisUpdate:          now,
		NextUpdate:          now.Add(24 * time.Hour),
		RevokedCertificateEntries: revokedCerts,
	}

	crlDER, err := x509.CreateRevocationList(nil, crlTemplate, loadedCA.Certificate, loadedCA.PrivateKey)
	if err != nil {
		jsonError(w, fmt.Sprintf("create CRL: %s", err), http.StatusInternalServerError)
		return
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(crlPEM)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	events, err := s.store.ListAudit(limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, events)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetStats()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, stats)
}

// --- Helpers ---

func jsonResp(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// InspectCert is a helper for the API to return cert info.
func InspectCert(certPEM string) *cert.Info {
	info, _ := cert.InspectPEM([]byte(certPEM))
	return info
}
