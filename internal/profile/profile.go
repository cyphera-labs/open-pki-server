package profile

import (
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Profile defines a certificate issuance template.
type Profile struct {
	Name                   string   `json:"name"`
	Type                   string   `json:"type"` // "server" or "client"
	ValidityDays           int      `json:"validity_days"`
	ExtendedKeyUsage       []string `json:"extended_key_usage"`
	AllowedDNSSuffixes     []string `json:"allowed_dns_suffixes,omitempty"`
	AllowedIPs             []string `json:"allowed_ips,omitempty"`
	AllowedSubjectPrefixes []string `json:"allowed_subject_prefixes,omitempty"`
}

// Defaults returns the built-in certificate profiles.
func Defaults() map[string]*Profile {
	return map[string]*Profile{
		"server": {
			Name:             "server",
			Type:             "server",
			ValidityDays:     397,
			ExtendedKeyUsage: []string{"server_auth"},
		},
		"client": {
			Name:             "client",
			Type:             "client",
			ValidityDays:     397,
			ExtendedKeyUsage: []string{"client_auth"},
		},
		"kmip-server": {
			Name:               "kmip-server",
			Type:               "server",
			ValidityDays:       397,
			AllowedDNSSuffixes: []string{"localhost", ".internal", ".corp"},
			AllowedIPs:         []string{"127.0.0.1", "10.0.0.0/8"},
			ExtendedKeyUsage:   []string{"server_auth"},
		},
		"kmip-client": {
			Name:                   "kmip-client",
			Type:                   "client",
			ValidityDays:           397,
			AllowedSubjectPrefixes: []string{"kmip-", "demo-"},
			ExtendedKeyUsage:       []string{"client_auth"},
		},
	}
}

// Validity returns the NotBefore and NotAfter times for this profile.
func (p *Profile) Validity() (time.Time, time.Time) {
	now := time.Now().UTC()
	return now, now.Add(time.Duration(p.ValidityDays) * 24 * time.Hour)
}

// KeyUsages returns the x509 ExtKeyUsage values for this profile.
func (p *Profile) KeyUsages() []x509.ExtKeyUsage {
	var usages []x509.ExtKeyUsage
	for _, u := range p.ExtendedKeyUsage {
		switch u {
		case "server_auth":
			usages = append(usages, x509.ExtKeyUsageServerAuth)
		case "client_auth":
			usages = append(usages, x509.ExtKeyUsageClientAuth)
		}
	}
	return usages
}

// ValidateSANs checks DNS names and IPs against the profile's allowed lists.
func (p *Profile) ValidateSANs(dnsNames []string, ips []net.IP) error {
	if len(p.AllowedDNSSuffixes) > 0 {
		for _, dns := range dnsNames {
			if !matchesDNSSuffix(dns, p.AllowedDNSSuffixes) {
				return fmt.Errorf("DNS name %q not allowed by profile %q (allowed suffixes: %v)", dns, p.Name, p.AllowedDNSSuffixes)
			}
		}
	}
	return nil
}

// ValidateSubject checks the CN against the profile's allowed subject prefixes.
func (p *Profile) ValidateSubject(cn string) error {
	if len(p.AllowedSubjectPrefixes) > 0 {
		for _, prefix := range p.AllowedSubjectPrefixes {
			if strings.HasPrefix(cn, prefix) {
				return nil
			}
		}
		return fmt.Errorf("CN %q not allowed by profile %q (allowed prefixes: %v)", cn, p.Name, p.AllowedSubjectPrefixes)
	}
	return nil
}

func matchesDNSSuffix(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if name == suffix || strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
