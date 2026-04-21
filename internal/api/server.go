package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cyphera-labs/open-pki-server/internal/ca"
	"github.com/cyphera-labs/open-pki-server/internal/config"
	"github.com/cyphera-labs/open-pki-server/internal/dashboard"
	"github.com/cyphera-labs/open-pki-server/internal/dashauth"
	pkiocsp "github.com/cyphera-labs/open-pki-server/internal/ocsp"
	"github.com/cyphera-labs/open-pki-server/internal/profile"
	"github.com/cyphera-labs/open-pki-server/internal/storage"
)

// Server is the REST API server.
type Server struct {
	store    *storage.Store
	profiles map[string]*profile.Profile
	cfg      *config.Config
	mux      *http.ServeMux
	dashAuth *dashauth.DashAuth
}

// NewServer creates a new API server.
func NewServer(store *storage.Store, profiles map[string]*profile.Profile, cfg *config.Config) *Server {
	// PKI server uses HTTP (no TLS yet), so Secure flag = false on cookies
	da := dashauth.New(cfg.Server.APIKey, false)

	s := &Server{
		store:    store,
		profiles: profiles,
		cfg:      cfg,
		mux:      http.NewServeMux(),
		dashAuth: da,
	}
	s.routes()
	return s
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	// Auth endpoints (public — handles login/logout/status)
	s.dashAuth.RegisterRoutes(s.mux)

	// Dashboard static files (public — JS handles login screen)
	s.mux.Handle("/", dashboard.Handler())

	// Public endpoints
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)

	// CA
	s.mux.HandleFunc("POST /v1/ca/root", s.dashAuth.RequireAPIAuth(s.handleCreateRootCA))
	s.mux.HandleFunc("GET /v1/ca", s.dashAuth.RequireAPIAuth(s.handleListCAs))
	s.mux.HandleFunc("GET /v1/ca/bundle", s.dashAuth.RequireAPIAuth(s.handleCABundle))
	s.mux.HandleFunc("GET /v1/ca/{id}", s.dashAuth.RequireAPIAuth(s.handleGetCA))
	s.mux.HandleFunc("GET /v1/ca/{id}/crl", s.dashAuth.RequireAPIAuth(s.handleCRLForCA))

	// Certificates
	s.mux.HandleFunc("POST /v1/certificates/issue", s.dashAuth.RequireAPIAuth(s.handleIssueCert))
	s.mux.HandleFunc("POST /v1/certificates/issue-csr", s.dashAuth.RequireAPIAuth(s.handleIssueFromCSR))
	s.mux.HandleFunc("POST /v1/certificates/renew", s.dashAuth.RequireAPIAuth(s.handleRenewCert))
	s.mux.HandleFunc("GET /v1/certificates", s.dashAuth.RequireAPIAuth(s.handleListCerts))
	s.mux.HandleFunc("GET /v1/certificates/expiring", s.dashAuth.RequireAPIAuth(s.handleListExpiring))
	s.mux.HandleFunc("GET /v1/certificates/{serial}", s.dashAuth.RequireAPIAuth(s.handleGetCert))
	s.mux.HandleFunc("POST /v1/certificates/{serial}/revoke", s.dashAuth.RequireAPIAuth(s.handleRevokeCert))

	// CRL — public (no auth), DER format
	s.mux.HandleFunc("GET /crl/", s.handlePublicCRL)

	// OCSP — public (no auth)
	s.mux.HandleFunc("POST /ocsp", s.handleOCSP)

	// Inventory
	s.mux.HandleFunc("GET /v1/inventory", s.dashAuth.RequireAPIAuth(s.handleInventory))

	// Audit
	s.mux.HandleFunc("GET /v1/audit", s.dashAuth.RequireAPIAuth(s.handleAudit))

	// Stats + Metrics
	s.mux.HandleFunc("GET /v1/stats", s.dashAuth.RequireAPIAuth(s.handleStats))
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
}

// auth() replaced by dashauth.RequireAPIAuth — session cookie + Bearer token

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

	// Register in asset graph
	assetID := fmt.Sprintf("ca:%s", fmt.Sprintf("%X", result.Certificate.SerialNumber))
	_ = s.store.RegisterAsset(assetID, "certificate_authority", fmt.Sprintf("%d", caID), req.Name, "active")
	_ = s.store.EmitLifecycleEvent(assetID, "ca.created", "api", map[string]any{"name": req.Name})

	jsonResp(w, map[string]any{
		"id":      caID,
		"name":    req.Name,
		"serial":  fmt.Sprintf("%X", result.Certificate.SerialNumber),
		"subject": result.Certificate.Subject.String(),
		"expires": result.Certificate.NotAfter.Format(time.RFC3339),
		"crl_url": s.cfg.CRLURL(caID),
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

	// Count revoked certs for this CA
	revoked, _ := s.store.ListRevoked(id)

	jsonResp(w, map[string]any{
		"ca":            rec,
		"crl_url":       s.cfg.CRLURL(id),
		"revoked_count": len(revoked),
	})
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

	issueOpts := ca.IssueCertOptions{
		CommonName: req.CN,
		DNSNames:   dnsNames,
		IPs:        ips,
		Profile:    prof,
	}

	// Add CRL Distribution Point if configured
	if s.cfg.Revocation.CRLEnabled && s.cfg.Revocation.IncludeCRLDistributionPoints {
		issueOpts.CRLURL = s.cfg.CRLURL(req.CAID)
	}
	// Add OCSP URL if configured
	if s.cfg.Revocation.OCSPEnabled && s.cfg.Revocation.IncludeOCSPURL {
		issueOpts.OCSPURL = s.cfg.OCSPURL()
	}

	issuedCertPEM, issuedKeyPEM, err := loadedCA.IssueCert(issueOpts)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	block, _ := pem.Decode(issuedCertPEM)
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
		CertificatePEM:       string(issuedCertPEM),
		PublicKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		Status:               "active",
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	certSerial := fmt.Sprintf("%X", issuedCert.SerialNumber)
	certAssetID := fmt.Sprintf("cert:%s", certSerial)
	caAssetID := fmt.Sprintf("ca:%s", caRec.Serial)
	_ = s.store.RegisterAsset(certAssetID, "certificate", certSerial, req.CN, "active")
	_ = s.store.SetMetadata(certAssetID, "profile", req.Profile)
	_ = s.store.SetMetadata(certAssetID, "issuance_mode", "generated")
	_ = s.store.AddRelationship(certAssetID, "issued_by", caAssetID, nil)
	_ = s.store.EmitLifecycleEvent(certAssetID, "certificate.issued", "api", map[string]any{
		"cn": req.CN, "profile": req.Profile,
	})

	resp := map[string]any{
		"id":          certID,
		"serial":      certSerial,
		"common_name": req.CN,
		"profile":     req.Profile,
		"expires":     issuedCert.NotAfter.Format(time.RFC3339),
		"certificate": string(issuedCertPEM),
	}
	if issuedKeyPEM != nil {
		resp["private_key"] = string(issuedKeyPEM)
	}
	jsonResp(w, resp)
}

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	certs, err := s.store.ListCertsFiltered(status)
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

	// Build combined view: PKI data + asset context
	assetID := fmt.Sprintf("cert:%s", serial)
	meta, _ := s.store.GetMetadata(assetID)
	tags, _ := s.store.GetTags(assetID)
	rels, _ := s.store.GetRelationships(assetID)
	events, _ := s.store.ListLifecycleEvents(assetID, 20)

	jsonResp(w, map[string]any{
		"certificate": rec,
		"asset": map[string]any{
			"id":            assetID,
			"metadata":      meta,
			"tags":          tags,
			"relationships": rels,
			"events":        events,
		},
	})
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
		Reason  string `json:"reason"`
		Comment string `json:"comment"`
		Actor   string `json:"actor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "unspecified"
	}
	if req.Actor == "" {
		req.Actor = "api"
	}

	if !storage.ValidRevocationReason(req.Reason) {
		jsonError(w, fmt.Sprintf("invalid revocation reason: %s", req.Reason), http.StatusBadRequest)
		return
	}

	if err := s.store.RevokeCert(storage.RevokeOpts{
		Serial:  serial,
		Reason:  req.Reason,
		Comment: req.Comment,
		Actor:   req.Actor,
	}); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Update asset graph
	certAssetID := fmt.Sprintf("cert:%s", serial)
	_ = s.store.RegisterAsset(certAssetID, "certificate", serial, "", "revoked")
	_ = s.store.EmitLifecycleEvent(certAssetID, "certificate.revoked", req.Actor, map[string]any{
		"reason": req.Reason, "comment": req.Comment,
	})

	jsonResp(w, map[string]string{"status": "revoked", "serial": serial, "reason": req.Reason})
}

func (s *Server) handleIssueFromCSR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CAID    int64  `json:"ca_id"`
		CSR     string `json:"csr"`
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.CSR == "" {
		jsonError(w, "csr is required", http.StatusBadRequest)
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

	var crlURL, ocspURL string
	if s.cfg.Revocation.CRLEnabled && s.cfg.Revocation.IncludeCRLDistributionPoints {
		crlURL = s.cfg.CRLURL(req.CAID)
	}
	if s.cfg.Revocation.OCSPEnabled && s.cfg.Revocation.IncludeOCSPURL {
		ocspURL = s.cfg.OCSPURL()
	}

	certPEM, err := loadedCA.IssueFromCSRPEM([]byte(req.CSR), prof, crlURL, ocspURL)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	block, _ := pem.Decode(certPEM)
	issuedCert, _ := x509.ParseCertificate(block.Bytes)
	fingerprint := sha256.Sum256(issuedCert.RawSubjectPublicKeyInfo)

	var sans []string
	for _, dns := range issuedCert.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range issuedCert.IPAddresses {
		sans = append(sans, ip.String())
	}

	certID, err := s.store.InsertCert(&storage.CertRecord{
		CAID:                 caRec.ID,
		Serial:               fmt.Sprintf("%X", issuedCert.SerialNumber),
		Subject:              issuedCert.Subject.String(),
		CommonName:           issuedCert.Subject.CommonName,
		SANs:                 sans,
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

	// Register in asset graph (consistent with generated issuance)
	certSerial := fmt.Sprintf("%X", issuedCert.SerialNumber)
	certAssetID := fmt.Sprintf("cert:%s", certSerial)
	caAssetID := fmt.Sprintf("ca:%s", caRec.Serial)
	_ = s.store.RegisterAsset(certAssetID, "certificate", certSerial, issuedCert.Subject.CommonName, "active")
	_ = s.store.SetMetadata(certAssetID, "profile", req.Profile)
	_ = s.store.SetMetadata(certAssetID, "issuance_mode", "csr")
	_ = s.store.AddRelationship(certAssetID, "issued_by", caAssetID, nil)
	_ = s.store.EmitLifecycleEvent(certAssetID, "certificate.issued", "api", map[string]any{
		"cn": issuedCert.Subject.CommonName, "profile": req.Profile, "source": "csr",
	})

	jsonResp(w, map[string]any{
		"id":          certID,
		"serial":      certSerial,
		"common_name": issuedCert.Subject.CommonName,
		"profile":     req.Profile,
		"expires":     issuedCert.NotAfter.Format(time.RFC3339),
		"certificate": string(certPEM),
	})
}

func (s *Server) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Serial == "" {
		jsonError(w, "serial is required", http.StatusBadRequest)
		return
	}

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

	origBlock, _ := pem.Decode([]byte(orig.CertificatePEM))
	origCert, _ := x509.ParseCertificate(origBlock.Bytes)

	issueOpts := ca.IssueCertOptions{
		CommonName: orig.CommonName,
		DNSNames:   origCert.DNSNames,
		IPs:        origCert.IPAddresses,
		Profile:    prof,
	}
	if s.cfg.Revocation.CRLEnabled && s.cfg.Revocation.IncludeCRLDistributionPoints {
		issueOpts.CRLURL = s.cfg.CRLURL(orig.CAID)
	}
	if s.cfg.Revocation.OCSPEnabled && s.cfg.Revocation.IncludeOCSPURL {
		issueOpts.OCSPURL = s.cfg.OCSPURL()
	}

	renewedCertPEM, renewedKeyPEM, err := loadedCA.IssueCert(issueOpts)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(renewedCertPEM)
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
		CertificatePEM:       string(renewedCertPEM),
		PublicKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		Status:               "active",
		RenewedFromSerial:    orig.Serial,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = s.store.RevokeCert(storage.RevokeOpts{Serial: orig.Serial, Reason: "superseded", Actor: "api"})

	_ = s.store.InsertAudit("api", "certificate.renewed", "certificate", fmt.Sprintf("%d", newID), map[string]any{
		"old_serial": orig.Serial, "new_serial": fmt.Sprintf("%X", newCert.SerialNumber),
	})

	resp := map[string]any{
		"id":           newID,
		"serial":       fmt.Sprintf("%X", newCert.SerialNumber),
		"renewed_from": orig.Serial,
		"expires":      newCert.NotAfter.Format(time.RFC3339),
		"certificate":  string(renewedCertPEM),
	}
	if renewedKeyPEM != nil {
		resp["private_key"] = string(renewedKeyPEM)
	}
	jsonResp(w, resp)
}

// handleCRLForCA returns CRL for a CA via /v1/ca/{id}/crl (PEM by default, DER with Accept header)
func (s *Server) handleCRLForCA(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		jsonError(w, "invalid CA ID", http.StatusBadRequest)
		return
	}
	crlDER, err := s.generateCRL(id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return PEM for API consumers
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(crlPEM)

	// CRL download audit intentionally omitted — public endpoint would spam events
}

// handlePublicCRL returns CRL in DER format at /crl/{id}.crl
func (s *Server) handlePublicCRL(w http.ResponseWriter, r *http.Request) {
	// Parse CA ID from path like /crl/1.crl
	path := strings.TrimPrefix(r.URL.Path, "/crl/")
	path = strings.TrimSuffix(path, ".crl")
	caID, err := strconv.ParseInt(path, 10, 64)
	if err != nil {
		http.Error(w, "invalid CA ID", http.StatusBadRequest)
		return
	}
	crlDER, err := s.generateCRL(caID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%d.crl", caID))
	w.Write(crlDER)
}

func (s *Server) generateCRL(caID int64) ([]byte, error) {
	caRec, err := s.store.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("CA not found")
	}
	keyPEM, err := s.store.GetKey("ca", caRec.ID)
	if err != nil {
		return nil, fmt.Errorf("CA key not found")
	}
	loadedCA, err := ca.LoadCAFromPEM([]byte(caRec.CertificatePEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("load CA: %s", err)
	}

	entries, err := s.store.ListRevoked(caID)
	if err != nil {
		return nil, err
	}

	var crlEntries []ca.CRLEntry
	for _, e := range entries {
		crlEntries = append(crlEntries, ca.CRLEntry{SerialHex: e.Serial, RevokedAt: e.RevokedAt, ReasonCode: e.ReasonCode})
	}

	validityHours := s.cfg.Revocation.CRLValidityHours
	if validityHours <= 0 {
		validityHours = 24
	}

	crlDER, err := ca.GenerateCRL(loadedCA, crlEntries, validityHours)
	if err != nil {
		return nil, fmt.Errorf("create CRL: %s", err)
	}

	// CRL generation audit intentionally omitted from dynamic generation —
	// would fire on every CRL request. Audit revocation events instead.

	return crlDER, nil
}

func (s *Server) handleOCSP(w http.ResponseWriter, r *http.Request) {
	responder := pkiocsp.NewResponder(s.store, s.cfg.Revocation.OCSPResponseValidityMinutes)
	responder.Handler()(w, r)
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

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	views, err := s.store.ListInventory()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, views)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetStats()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, stats)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.store.GetStats()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "# HELP open_pki_cas_total Total certificate authorities\n")
	fmt.Fprintf(w, "# TYPE open_pki_cas_total gauge\n")
	fmt.Fprintf(w, "open_pki_cas_total %d\n", stats.TotalCAs)
	fmt.Fprintf(w, "# HELP open_pki_certificates_total Total certificates\n")
	fmt.Fprintf(w, "# TYPE open_pki_certificates_total gauge\n")
	fmt.Fprintf(w, "open_pki_certificates_total %d\n", stats.TotalCerts)
	fmt.Fprintf(w, "# HELP open_pki_certificates_active Active certificates\n")
	fmt.Fprintf(w, "# TYPE open_pki_certificates_active gauge\n")
	fmt.Fprintf(w, "open_pki_certificates_active %d\n", stats.ActiveCerts)
	fmt.Fprintf(w, "# HELP open_pki_certificates_revoked Revoked certificates\n")
	fmt.Fprintf(w, "# TYPE open_pki_certificates_revoked gauge\n")
	fmt.Fprintf(w, "open_pki_certificates_revoked %d\n", stats.RevokedCerts)
	fmt.Fprintf(w, "# HELP open_pki_certificates_expiring_soon Certificates expiring within 30 days\n")
	fmt.Fprintf(w, "# TYPE open_pki_certificates_expiring_soon gauge\n")
	fmt.Fprintf(w, "open_pki_certificates_expiring_soon %d\n", stats.ExpiringSoon)
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
