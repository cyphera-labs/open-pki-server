package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
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

// InitRootCA creates a self-signed root CA.
func InitRootCA(opts InitRootCAOptions) (*CA, error) {
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 3650 // 10 years
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

	return &CA{
		Certificate: cert,
		PrivateKey:  priv,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// IssueCertOptions configures certificate issuance.
type IssueCertOptions struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	Profile    *profile.Profile
	OutputDir  string
	OutputName string
}

// IssueCert creates a certificate signed by this CA.
func (ca *CA) IssueCert(opts IssueCertOptions) (certPEM, keyPEM []byte, err error) {
	if opts.Profile == nil {
		return nil, nil, fmt.Errorf("profile is required")
	}

	// Validate SANs and subject against profile
	if err := opts.Profile.ValidateSANs(opts.DNSNames, opts.IPs); err != nil {
		return nil, nil, err
	}
	if err := opts.Profile.ValidateSubject(opts.CommonName); err != nil {
		return nil, nil, err
	}

	priv, pub, err := generateKeyPair("ed25519")
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	notBefore, notAfter := opts.Profile.Validity()

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		ExtKeyUsage:  opts.Profile.KeyUsages(),
		DNSNames:     opts.DNSNames,
		IPAddresses:  opts.IPs,
	}

	// Set KeyUsage based on profile type
	switch opts.Profile.Type {
	case "server":
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	case "client":
		template.KeyUsage = x509.KeyUsageDigitalSignature
	default:
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, pub, ca.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err = marshalPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
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

// LoadCAFromPEM loads a CA from PEM byte slices (for in-memory/database use).
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

	return &CA{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
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

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block in %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block in %s", keyPath)
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// --- helpers ---

func generateKeyPair(algorithm string) (crypto.Signer, crypto.PublicKey, error) {
	switch algorithm {
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, pub, nil
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
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
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
		// Try PKCS1 and EC as fallbacks
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
	keyPath := filepath.Join(dir, name+"-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}
