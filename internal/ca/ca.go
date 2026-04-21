package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cyphera-labs/open-pki-server/internal/profile"
)

// CA holds a loaded certificate authority.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	CertPEM     []byte
	KeyPEM      []byte
}

// InitRootCAOptions configures root CA creation.
type InitRootCAOptions struct {
	Name         string
	Algorithm    string // "ed25519", "ecdsa-p256", "ecdsa-p384"
	ValidityDays int
	OutputDir    string
}

// InitRootCA creates a self-signed root CA with proper X.509 extensions.
func InitRootCA(opts InitRootCAOptions) (*CA, error) {
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 3650
	}
	if opts.Algorithm == "" {
		opts.Algorithm = "ed25519"
	}

	priv, pub, err := generateKeyPair(opts.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	// Subject Key Identifier = SHA-256 of public key
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	ski := sha256.Sum256(pubDER)

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.Name,
			Organization: []string{"Cyphera Open PKI"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(opts.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		SubjectKeyId:          ski[:20], // Use first 20 bytes per RFC 5280
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := marshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	if opts.OutputDir != "" {
		if err := writeFiles(opts.OutputDir, "ca", certPEM, keyPEM); err != nil {
			return nil, err
		}
	}

	return &CA{Certificate: cert, PrivateKey: priv, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// InitIntermediateCAOptions configures intermediate CA creation.
type InitIntermediateCAOptions struct {
	Name         string
	Algorithm    string
	ValidityDays int
	OutputDir    string
}

// InitIntermediateCA creates an intermediate CA signed by this root/parent CA.
func (parent *CA) InitIntermediateCA(opts InitIntermediateCAOptions) (*CA, error) {
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 1825 // 5 years
	}
	if opts.Algorithm == "" {
		opts.Algorithm = "ed25519"
	}

	priv, pub, err := generateKeyPair(opts.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	ski := sha256.Sum256(pubDER)

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.Name,
			Organization: []string{"Cyphera Open PKI"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(opts.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski[:20],
		AuthorityKeyId:        parent.Certificate.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent.Certificate, pub, parent.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := marshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	if opts.OutputDir != "" {
		name := opts.Name
		if name == "" {
			name = "intermediate"
		}
		if err := writeFiles(opts.OutputDir, name, certPEM, keyPEM); err != nil {
			return nil, err
		}
	}

	return &CA{Certificate: cert, PrivateKey: priv, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// IssueCertOptions configures certificate issuance.
type IssueCertOptions struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	Profile    *profile.Profile
	OutputDir  string
	OutputName string
	CRLURL     string
	OCSPURL    string
	CSR        *x509.CertificateRequest // If set, issue from CSR instead of generating keypair
}

// IssueCert creates a certificate signed by this CA.
// If opts.CSR is set, the public key comes from the CSR. Otherwise a new keypair is generated.
func (issuer *CA) IssueCert(opts IssueCertOptions) (certPEM, keyPEM []byte, err error) {
	if opts.Profile == nil {
		return nil, nil, fmt.Errorf("profile is required")
	}

	var pub crypto.PublicKey
	var priv crypto.Signer

	if opts.CSR != nil {
		// CSR-based issuance: validate CSR signature
		if err := opts.CSR.CheckSignature(); err != nil {
			return nil, nil, fmt.Errorf("invalid CSR signature: %w", err)
		}

		// Extract subject from CSR but validate against profile
		if opts.CommonName == "" {
			opts.CommonName = opts.CSR.Subject.CommonName
		}
		if len(opts.DNSNames) == 0 {
			opts.DNSNames = opts.CSR.DNSNames
		}
		if len(opts.IPs) == 0 {
			opts.IPs = opts.CSR.IPAddresses
		}
		pub = opts.CSR.PublicKey
	} else {
		// Server-generated keypair
		priv, pub, err = generateKeyPair("ed25519")
		if err != nil {
			return nil, nil, fmt.Errorf("generate key: %w", err)
		}
	}

	// Validate SANs and subject against profile — NEVER blindly sign
	if err := opts.Profile.ValidateSANs(opts.DNSNames, opts.IPs); err != nil {
		return nil, nil, err
	}
	if err := opts.Profile.ValidateSubject(opts.CommonName); err != nil {
		return nil, nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	notBefore, notAfter := opts.Profile.Validity()

	// Subject Key Identifier for the end-entity cert
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	ski := sha256.Sum256(pubDER)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		ExtKeyUsage:    opts.Profile.KeyUsages(),
		DNSNames:       opts.DNSNames,
		IPAddresses:    opts.IPs,
		SubjectKeyId:   ski[:20],
		AuthorityKeyId: issuer.Certificate.SubjectKeyId,
	}

	switch opts.Profile.Type {
	case "server":
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	case "client":
		template.KeyUsage = x509.KeyUsageDigitalSignature
	default:
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	if opts.CRLURL != "" {
		template.CRLDistributionPoints = []string{opts.CRLURL}
	}
	if opts.OCSPURL != "" {
		template.OCSPServer = []string{opts.OCSPURL}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer.Certificate, pub, issuer.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Only marshal private key if we generated it (not CSR-based)
	if priv != nil {
		keyPEM, err = marshalPrivateKey(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal key: %w", err)
		}
	}

	if opts.OutputDir != "" {
		name := opts.OutputName
		if name == "" {
			name = opts.CommonName
		}
		if err := writeFiles(opts.OutputDir, name, certPEM, keyPEM); err != nil {
			return nil, nil, err
		}
	}

	return certPEM, keyPEM, nil
}

// IssueFromCSRPEM parses a PEM-encoded CSR and issues a certificate.
func (issuer *CA) IssueFromCSRPEM(csrPEM []byte, prof *profile.Profile, crlURL, ocspURL string) (certPEM []byte, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}

	certPEM, _, err = issuer.IssueCert(IssueCertOptions{
		CSR:     csr,
		Profile: prof,
		CRLURL:  crlURL,
		OCSPURL: ocspURL,
	})
	return certPEM, err
}

// LoadCAFromPEM loads a CA from PEM byte slices.
func LoadCAFromPEM(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block in certificate data")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block in key data")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	return &CA{Certificate: cert, PrivateKey: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// LoadCA reads a CA certificate and key from PEM files.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	return LoadCAFromPEM(certPEM, keyPEM)
}

// CRLEntry represents a single revoked certificate for CRL generation.
type CRLEntry struct {
	SerialHex  string
	RevokedAt  time.Time
	ReasonCode int
}

// GenerateCRL creates a signed CRL from revoked entries.
func GenerateCRL(issuerCA *CA, entries []CRLEntry, validityHours int) ([]byte, error) {
	if validityHours <= 0 {
		validityHours = 24
	}

	var revokedCerts []x509.RevocationListEntry
	for _, e := range entries {
		serial := new(big.Int)
		serial.SetString(e.SerialHex, 16)
		entry := x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: e.RevokedAt,
		}
		if e.ReasonCode > 0 {
			entry.ReasonCode = e.ReasonCode
		}
		revokedCerts = append(revokedCerts, entry)
	}

	now := time.Now().UTC()
	template := &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(time.Duration(validityHours) * time.Hour),
		RevokedCertificateEntries: revokedCerts,
	}

	return x509.CreateRevocationList(rand.Reader, template, issuerCA.Certificate, issuerCA.PrivateKey)
}

// EncodeCRLPEM wraps DER-encoded CRL bytes in PEM.
func EncodeCRLPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

// --- helpers ---

func generateKeyPair(algorithm string) (crypto.Signer, crypto.PublicKey, error) {
	switch algorithm {
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, pub, err
	case "ecdsa-p256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case "ecdsa-p384":
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s (supported: ed25519, ecdsa-p256, ecdsa-p384)", algorithm)
	}
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func marshalPrivateKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		if k, err2 := x509.ParseECPrivateKey(der); err2 == nil {
			return k, nil
		}
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}
	return signer, nil
}

func writeFiles(dir, name string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	certPath := filepath.Join(dir, name+".pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if keyPEM != nil {
		keyPath := filepath.Join(dir, name+"-key.pem")
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return fmt.Errorf("write key: %w", err)
		}
	}
	return nil
}
