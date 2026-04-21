package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// Info holds parsed certificate details for display.
type Info struct {
	Subject         string
	Issuer          string
	SerialHex       string
	NotBefore       string
	NotAfter        string
	IsCA            bool
	KeyAlgorithm    string
	SignatureAlgo   string
	DNSNames        []string
	IPAddresses     []string
	ExtKeyUsage     []string
	Fingerprint     string
	PublicKeyFingerprint string
}

// InspectPEM parses certificate info from PEM bytes.
func InspectPEM(data []byte) (*Info, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return infoFromCert(cert), nil
}

// Inspect reads a PEM file and returns parsed certificate info.
func Inspect(path string) (*Info, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return infoFromCert(cert), nil
}

func infoFromCert(cert *x509.Certificate) *Info {
	fingerprint := sha256.Sum256(cert.Raw)
	pubKeyFingerprint := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	var ekuNames []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			ekuNames = append(ekuNames, "server_auth")
		case x509.ExtKeyUsageClientAuth:
			ekuNames = append(ekuNames, "client_auth")
		default:
			ekuNames = append(ekuNames, fmt.Sprintf("unknown(%d)", eku))
		}
	}

	return &Info{
		Subject:              cert.Subject.String(),
		Issuer:               cert.Issuer.String(),
		SerialHex:            fmt.Sprintf("%X", cert.SerialNumber),
		NotBefore:            cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"),
		NotAfter:             cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"),
		IsCA:                 cert.IsCA,
		KeyAlgorithm:         cert.PublicKeyAlgorithm.String(),
		SignatureAlgo:        cert.SignatureAlgorithm.String(),
		DNSNames:             cert.DNSNames,
		IPAddresses:          ips,
		ExtKeyUsage:          ekuNames,
		Fingerprint:          hex.EncodeToString(fingerprint[:]),
		PublicKeyFingerprint: hex.EncodeToString(pubKeyFingerprint[:]),
	}
}

// FormatInfo produces a human-readable summary.
func FormatInfo(info *Info) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Subject:          %s\n", info.Subject)
	fmt.Fprintf(&b, "Issuer:           %s\n", info.Issuer)
	fmt.Fprintf(&b, "Serial:           %s\n", info.SerialHex)
	fmt.Fprintf(&b, "Not Before:       %s\n", info.NotBefore)
	fmt.Fprintf(&b, "Not After:        %s\n", info.NotAfter)
	fmt.Fprintf(&b, "Is CA:            %v\n", info.IsCA)
	fmt.Fprintf(&b, "Key Algorithm:    %s\n", info.KeyAlgorithm)
	fmt.Fprintf(&b, "Signature Algo:   %s\n", info.SignatureAlgo)
	if len(info.DNSNames) > 0 {
		fmt.Fprintf(&b, "DNS Names:        %s\n", strings.Join(info.DNSNames, ", "))
	}
	if len(info.IPAddresses) > 0 {
		fmt.Fprintf(&b, "IP Addresses:     %s\n", strings.Join(info.IPAddresses, ", "))
	}
	if len(info.ExtKeyUsage) > 0 {
		fmt.Fprintf(&b, "Ext Key Usage:    %s\n", strings.Join(info.ExtKeyUsage, ", "))
	}
	fmt.Fprintf(&b, "Fingerprint:      sha256:%s\n", info.Fingerprint)
	fmt.Fprintf(&b, "Public Key FP:    sha256:%s\n", info.PublicKeyFingerprint)
	return b.String()
}
