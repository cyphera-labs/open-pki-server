package config

import "fmt"

// Config holds server configuration.
type Config struct {
	Server     ServerConfig     `json:"server"`
	Revocation RevocationConfig `json:"revocation"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	APIKey        string `json:"api_key"`
	PublicBaseURL string `json:"public_base_url"`
}

// RevocationConfig holds revocation settings.
type RevocationConfig struct {
	CRLEnabled                   bool   `json:"crl_enabled"`
	CRLValidityHours             int    `json:"crl_validity_hours"`
	IncludeCRLDistributionPoints bool   `json:"include_crl_distribution_points"`
	CRLPathTemplate              string `json:"crl_path_template"`
	OCSPEnabled                  bool   `json:"ocsp_enabled"`
	OCSPPath                     string `json:"ocsp_path"`
	OCSPResponseValidityMinutes  int    `json:"ocsp_response_validity_minutes"`
	IncludeOCSPURL               bool   `json:"include_ocsp_url"`
}

// Default returns a default configuration.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host:          "0.0.0.0",
			Port:          8300,
			PublicBaseURL: "http://localhost:8300",
		},
		Revocation: RevocationConfig{
			CRLEnabled:                   true,
			CRLValidityHours:             24,
			IncludeCRLDistributionPoints: true,
			CRLPathTemplate:              "/crl/%d.crl",
			OCSPEnabled:                  false,
			OCSPPath:                     "/ocsp",
			OCSPResponseValidityMinutes:  60,
			IncludeOCSPURL:               false,
		},
	}
}

// CRLURL returns the full CRL URL for a given CA ID.
func (c *Config) CRLURL(caID int64) string {
	return c.Server.PublicBaseURL + fmt.Sprintf(c.Revocation.CRLPathTemplate, caID)
}

// OCSPURL returns the full OCSP URL.
func (c *Config) OCSPURL() string {
	return c.Server.PublicBaseURL + c.Revocation.OCSPPath
}
