package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// VerifyResult holds the outcome of certificate verification.
type VerifyResult struct {
	Valid  bool
	Chain  []string // Subject strings of the chain
	Errors []string
}

// Verify checks a certificate against a CA certificate.
func Verify(certPath, caPath string) (*VerifyResult, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block in %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caPath)
	}

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return &VerifyResult{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	var chainSubjects []string
	if len(chains) > 0 {
		for _, c := range chains[0] {
			chainSubjects = append(chainSubjects, c.Subject.String())
		}
	}

	return &VerifyResult{
		Valid: true,
		Chain: chainSubjects,
	}, nil
}

// FormatVerifyResult produces a human-readable verification summary.
func FormatVerifyResult(r *VerifyResult) string {
	if r.Valid {
		s := "VALID\n"
		if len(r.Chain) > 0 {
			s += "Chain:\n"
			for i, subj := range r.Chain {
				s += fmt.Sprintf("  [%d] %s\n", i, subj)
			}
		}
		return s
	}
	s := "INVALID\n"
	for _, e := range r.Errors {
		s += fmt.Sprintf("  - %s\n", e)
	}
	return s
}
