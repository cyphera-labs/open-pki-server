package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/cyphera-labs/open-pki-server/internal/profile"
)

func TestInitRootCA(t *testing.T) {
	result, err := InitRootCA(InitRootCAOptions{
		Name:         "test-root",
		Algorithm:    "ed25519",
		ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("InitRootCA: %v", err)
	}
	if result.Certificate == nil {
		t.Fatal("certificate is nil")
	}
	if !result.Certificate.IsCA {
		t.Error("expected IsCA=true")
	}
	if result.Certificate.Subject.CommonName != "test-root" {
		t.Errorf("CN = %q, want test-root", result.Certificate.Subject.CommonName)
	}
	if result.Certificate.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", result.Certificate.MaxPathLen)
	}
	if len(result.Certificate.SubjectKeyId) == 0 {
		t.Error("missing SubjectKeyId")
	}
	if len(result.CertPEM) == 0 || len(result.KeyPEM) == 0 {
		t.Error("PEM output is empty")
	}
}

func TestInitRootCA_ECDSA(t *testing.T) {
	result, err := InitRootCA(InitRootCAOptions{
		Name:      "ecdsa-root",
		Algorithm: "ecdsa-p256",
	})
	if err != nil {
		t.Fatalf("InitRootCA ecdsa: %v", err)
	}
	if result.Certificate.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("algorithm = %v, want ECDSA", result.Certificate.PublicKeyAlgorithm)
	}
}

func TestInitIntermediateCA(t *testing.T) {
	root, err := InitRootCA(InitRootCAOptions{Name: "root"})
	if err != nil {
		t.Fatalf("root: %v", err)
	}

	inter, err := root.InitIntermediateCA(InitIntermediateCAOptions{
		Name:         "intermediate",
		ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("InitIntermediateCA: %v", err)
	}
	if !inter.Certificate.IsCA {
		t.Error("intermediate should be CA")
	}
	if inter.Certificate.MaxPathLen != 0 || !inter.Certificate.MaxPathLenZero {
		t.Error("intermediate should have MaxPathLen=0, MaxPathLenZero=true")
	}
	if inter.Certificate.Issuer.CommonName != "root" {
		t.Errorf("issuer CN = %q, want root", inter.Certificate.Issuer.CommonName)
	}
	if len(inter.Certificate.AuthorityKeyId) == 0 {
		t.Error("missing AuthorityKeyId")
	}
}

func TestIssueCert_Server(t *testing.T) {
	root, _ := InitRootCA(InitRootCAOptions{Name: "root"})
	profiles := profile.Defaults()

	certPEM, keyPEM, err := root.IssueCert(IssueCertOptions{
		CommonName: "localhost",
		DNSNames:   []string{"localhost"},
		Profile:    profiles["server"],
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if certPEM == nil || keyPEM == nil {
		t.Fatal("PEM output nil")
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "localhost" {
		t.Errorf("CN = %q, want localhost", cert.Subject.CommonName)
	}
	if cert.IsCA {
		t.Error("end-entity cert should not be CA")
	}
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "localhost" {
		t.Error("missing DNS SAN")
	}
	if len(cert.SubjectKeyId) == 0 {
		t.Error("missing SubjectKeyId")
	}
	if len(cert.AuthorityKeyId) == 0 {
		t.Error("missing AuthorityKeyId")
	}

	// Check ExtKeyUsage
	found := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	if !found {
		t.Error("missing ExtKeyUsageServerAuth")
	}
}

func TestIssueCert_Client(t *testing.T) {
	root, _ := InitRootCA(InitRootCAOptions{Name: "root"})
	profiles := profile.Defaults()

	certPEM, _, err := root.IssueCert(IssueCertOptions{
		CommonName: "demo-client",
		Profile:    profiles["kmip-client"],
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	found := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Error("missing ExtKeyUsageClientAuth")
	}
}

func TestIssueCert_WithCDPAndOCSP(t *testing.T) {
	root, _ := InitRootCA(InitRootCAOptions{Name: "root"})
	profiles := profile.Defaults()

	certPEM, _, err := root.IssueCert(IssueCertOptions{
		CommonName: "localhost",
		DNSNames:   []string{"localhost"},
		Profile:    profiles["server"],
		CRLURL:     "http://pki.example.com/crl/1.crl",
		OCSPURL:    "http://pki.example.com/ocsp",
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if len(cert.CRLDistributionPoints) == 0 {
		t.Error("missing CRL Distribution Points")
	} else if cert.CRLDistributionPoints[0] != "http://pki.example.com/crl/1.crl" {
		t.Errorf("CDP = %q", cert.CRLDistributionPoints[0])
	}
	if len(cert.OCSPServer) == 0 {
		t.Error("missing OCSP AIA")
	} else if cert.OCSPServer[0] != "http://pki.example.com/ocsp" {
		t.Errorf("OCSP = %q", cert.OCSPServer[0])
	}
}

func TestIssueCert_CSR(t *testing.T) {
	root, _ := InitRootCA(InitRootCAOptions{Name: "root"})
	profiles := profile.Defaults()

	// Generate a CSR
	csrPEM := generateTestCSR(t, "csr-test", "csr-test.internal")

	certPEM, err := root.IssueFromCSRPEM(csrPEM, profiles["server"], "", "")
	if err != nil {
		t.Fatalf("IssueFromCSRPEM: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if cert.Subject.CommonName != "csr-test" {
		t.Errorf("CN = %q, want csr-test", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "csr-test.internal" {
		t.Error("missing DNS SAN from CSR")
	}
}

func TestChainVerification(t *testing.T) {
	root, _ := InitRootCA(InitRootCAOptions{Name: "root"})
	inter, _ := root.InitIntermediateCA(InitIntermediateCAOptions{Name: "inter"})
	profiles := profile.Defaults()

	certPEM, _, _ := inter.IssueCert(IssueCertOptions{
		CommonName: "leaf",
		DNSNames:   []string{"leaf.internal"},
		Profile:    profiles["server"],
	})

	// Verify chain: leaf → inter → root
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)

	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(inter.Certificate)

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func TestGenerateCRL(t *testing.T) {
	root, _ := InitRootCA(InitRootCAOptions{Name: "root"})

	entries := []CRLEntry{
		{SerialHex: "ABCDEF", RevokedAt: root.Certificate.NotBefore, ReasonCode: 1},
	}

	crlDER, err := GenerateCRL(root, entries, 24)
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	if len(crlDER) == 0 {
		t.Error("empty CRL")
	}

	// Parse the CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Errorf("revoked count = %d, want 1", len(crl.RevokedCertificateEntries))
	}

	// Verify CRL is signed by the CA
	if err := crl.CheckSignatureFrom(root.Certificate); err != nil {
		t.Fatalf("CRL signature verification failed: %v", err)
	}
}

func TestProfileValidation_RejectsBadSAN(t *testing.T) {
	root, _ := InitRootCA(InitRootCAOptions{Name: "root"})
	profiles := profile.Defaults()

	// kmip-server profile only allows localhost, .internal, .corp
	_, _, err := root.IssueCert(IssueCertOptions{
		CommonName: "evil.example.com",
		DNSNames:   []string{"evil.example.com"},
		Profile:    profiles["kmip-server"],
	})
	if err == nil {
		t.Error("expected error for disallowed SAN")
	}
}

// --- helpers ---

func generateTestCSR(t *testing.T, cn, san string) []byte {
	t.Helper()

	key, _, err := generateKeyPair("ed25519")
	if err != nil {
		t.Fatalf("generate key for CSR: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{san},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}
