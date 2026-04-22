package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyphera-labs/open-pki-server/internal/api"
	"github.com/cyphera-labs/open-pki-server/internal/ca"
	"github.com/cyphera-labs/open-pki-server/internal/cert"
	"github.com/cyphera-labs/open-pki-server/internal/config"
	"github.com/cyphera-labs/open-pki-server/internal/profile"
	"github.com/cyphera-labs/open-pki-server/internal/storage"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "open-pki",
		Short: "Cyphera Open PKI — certificate authority and lifecycle CLI",
	}

	root.AddCommand(
		initCACmd(),
		initIntermediateCmd(),
		issueServerCertCmd(),
		issueClientCertCmd(),
		issueFromCSRCmd(),
		inspectCmd(),
		verifyCmd(),
		bundleCmd(),
		revokeCmd(),
		crlCmd(),
		listCmd(),
		serveCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func initCACmd() *cobra.Command {
	var (
		name      string
		algorithm string
		validity  int
		outDir    string
	)

	cmd := &cobra.Command{
		Use:   "init-ca",
		Short: "Create a self-signed root CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := ca.InitRootCA(ca.InitRootCAOptions{
				Name:         name,
				Algorithm:    algorithm,
				ValidityDays: validity,
				OutputDir:    outDir,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Root CA created: %s\n", result.Certificate.Subject.CommonName)
			fmt.Printf("  Serial:   %X\n", result.Certificate.SerialNumber)
			fmt.Printf("  Expires:  %s\n", result.Certificate.NotAfter.UTC().Format("2006-01-02"))
			if outDir != "" {
				fmt.Printf("  Files:    %s/ca.pem, %s/ca-key.pem\n", outDir, outDir)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "root-ca", "CA common name")
	cmd.Flags().StringVar(&algorithm, "algorithm", "ed25519", "Key algorithm (ed25519, ecdsa-p256, ecdsa-p384)")
	cmd.Flags().IntVar(&validity, "validity-days", 3650, "CA validity in days")
	cmd.Flags().StringVar(&outDir, "out", ".", "Output directory")

	return cmd
}

func issueServerCertCmd() *cobra.Command {
	var (
		profileName string
		cn          string
		sans        []string
		outDir      string
		caCertPath  string
		caKeyPath   string
	)

	cmd := &cobra.Command{
		Use:   "issue-server-cert",
		Short: "Issue a server certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			return issueCert(profileName, cn, sans, outDir, caCertPath, caKeyPath, "server")
		},
	}

	cmd.Flags().StringVar(&profileName, "profile", "server", "Certificate profile")
	cmd.Flags().StringVar(&cn, "cn", "", "Common name (required)")
	cmd.Flags().StringSliceVar(&sans, "san", nil, "Subject alternative names (DNS or IP)")
	cmd.Flags().StringVar(&outDir, "out", ".", "Output directory")
	cmd.Flags().StringVar(&caCertPath, "ca-cert", "ca.pem", "CA certificate path")
	cmd.Flags().StringVar(&caKeyPath, "ca-key", "ca-key.pem", "CA key path")
	_ = cmd.MarkFlagRequired("cn")

	return cmd
}

func issueClientCertCmd() *cobra.Command {
	var (
		profileName string
		cn          string
		outDir      string
		caCertPath  string
		caKeyPath   string
	)

	cmd := &cobra.Command{
		Use:   "issue-client-cert",
		Short: "Issue a client certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			return issueCert(profileName, cn, nil, outDir, caCertPath, caKeyPath, "client")
		},
	}

	cmd.Flags().StringVar(&profileName, "profile", "client", "Certificate profile")
	cmd.Flags().StringVar(&cn, "cn", "", "Common name (required)")
	cmd.Flags().StringVar(&outDir, "out", ".", "Output directory")
	cmd.Flags().StringVar(&caCertPath, "ca-cert", "ca.pem", "CA certificate path")
	cmd.Flags().StringVar(&caKeyPath, "ca-key", "ca-key.pem", "CA key path")
	_ = cmd.MarkFlagRequired("cn")

	return cmd
}

func issueCert(profileName, cn string, sans []string, outDir, caCertPath, caKeyPath, defaultProfile string) error {
	if profileName == "" {
		profileName = defaultProfile
	}

	profiles := profile.Defaults()
	prof, ok := profiles[profileName]
	if !ok {
		return fmt.Errorf("unknown profile %q (available: %s)", profileName, availableProfiles(profiles))
	}

	loadedCA, err := ca.LoadCA(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	var dnsNames []string
	var ips []net.IP
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	_, _, err = loadedCA.IssueCert(ca.IssueCertOptions{
		CommonName: cn,
		DNSNames:   dnsNames,
		IPs:        ips,
		Profile:    prof,
		OutputDir:  outDir,
		OutputName: cn,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Certificate issued: %s\n", cn)
	fmt.Printf("  Profile:  %s\n", profileName)
	if outDir != "" {
		fmt.Printf("  Files:    %s/%s.pem, %s/%s-key.pem\n", outDir, cn, outDir, cn)
	}
	return nil
}

func inspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect [file]",
		Short: "Inspect a PEM certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := cert.Inspect(args[0])
			if err != nil {
				return err
			}
			fmt.Print(cert.FormatInfo(info))
			return nil
		},
	}
	return cmd
}

func verifyCmd() *cobra.Command {
	var caPath string

	cmd := &cobra.Command{
		Use:   "verify [cert-file]",
		Short: "Verify a certificate against a CA",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := cert.Verify(args[0], caPath)
			if err != nil {
				return err
			}
			fmt.Print(cert.FormatVerifyResult(result))
			if !result.Valid {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&caPath, "ca", "ca.pem", "CA certificate path")
	return cmd
}

func bundleCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "bundle [cert-files...]",
		Short: "Create a trust bundle from CA certificates",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cert.Bundle(output, args...); err != nil {
				return err
			}
			fmt.Printf("Bundle written: %s (%d certificates)\n", output, len(args))
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "bundle.pem", "Output file")
	return cmd
}

func initIntermediateCmd() *cobra.Command {
	var (
		name       string
		algorithm  string
		validity   int
		outDir     string
		caCertPath string
		caKeyPath  string
	)

	cmd := &cobra.Command{
		Use:   "init-intermediate",
		Short: "Create an intermediate CA signed by a parent CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			parentCA, err := ca.LoadCA(caCertPath, caKeyPath)
			if err != nil {
				return fmt.Errorf("load parent CA: %w", err)
			}

			result, err := parentCA.InitIntermediateCA(ca.InitIntermediateCAOptions{
				Name:         name,
				Algorithm:    algorithm,
				ValidityDays: validity,
				OutputDir:    outDir,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Intermediate CA created: %s\n", result.Certificate.Subject.CommonName)
			fmt.Printf("  Issuer:   %s\n", result.Certificate.Issuer.CommonName)
			fmt.Printf("  Serial:   %X\n", result.Certificate.SerialNumber)
			fmt.Printf("  Expires:  %s\n", result.Certificate.NotAfter.UTC().Format("2006-01-02"))
			if outDir != "" {
				fmt.Printf("  Files:    %s/%s.pem, %s/%s-key.pem\n", outDir, name, outDir, name)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "intermediate-ca", "Intermediate CA common name")
	cmd.Flags().StringVar(&algorithm, "algorithm", "ed25519", "Key algorithm")
	cmd.Flags().IntVar(&validity, "validity-days", 1825, "Validity in days (default 5 years)")
	cmd.Flags().StringVar(&outDir, "out", ".", "Output directory")
	cmd.Flags().StringVar(&caCertPath, "ca-cert", "ca.pem", "Parent CA certificate path")
	cmd.Flags().StringVar(&caKeyPath, "ca-key", "ca-key.pem", "Parent CA key path")

	return cmd
}

func issueFromCSRCmd() *cobra.Command {
	var (
		csrPath    string
		profileName string
		outDir     string
		caCertPath string
		caKeyPath  string
	)

	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a certificate from a CSR",
		RunE: func(cmd *cobra.Command, args []string) error {
			csrPEM, err := os.ReadFile(csrPath)
			if err != nil {
				return fmt.Errorf("read CSR: %w", err)
			}

			profiles := profile.Defaults()
			prof, ok := profiles[profileName]
			if !ok {
				return fmt.Errorf("unknown profile %q (available: %s)", profileName, availableProfiles(profiles))
			}

			loadedCA, err := ca.LoadCA(caCertPath, caKeyPath)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}

			certPEM, err := loadedCA.IssueFromCSRPEM(csrPEM, prof, "", "")
			if err != nil {
				return err
			}

			info, _ := cert.InspectPEM(certPEM)
			cn := "cert"
			if info != nil {
				cn = info.Subject
			}

			if outDir != "" {
				outPath := filepath.Join(outDir, "issued.pem")
				if err := os.MkdirAll(outDir, 0700); err != nil {
					return err
				}
				if err := os.WriteFile(outPath, certPEM, 0644); err != nil {
					return err
				}
				fmt.Printf("Certificate issued from CSR: %s\n", cn)
				fmt.Printf("  Profile:  %s\n", profileName)
				fmt.Printf("  File:     %s\n", outPath)
			} else {
				os.Stdout.Write(certPEM)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&csrPath, "csr", "", "Path to CSR PEM file (required)")
	cmd.Flags().StringVar(&profileName, "profile", "server", "Certificate profile")
	cmd.Flags().StringVar(&outDir, "out", "", "Output directory (omit for stdout)")
	cmd.Flags().StringVar(&caCertPath, "ca-cert", "ca.pem", "CA certificate path")
	cmd.Flags().StringVar(&caKeyPath, "ca-key", "ca-key.pem", "CA key path")
	_ = cmd.MarkFlagRequired("csr")

	return cmd
}

func revokeCmd() *cobra.Command {
	var (
		serial  string
		reason  string
		comment string
		dbPath  string
	)

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if serial == "" {
				return fmt.Errorf("--serial is required")
			}
			if reason == "" {
				reason = "unspecified"
			}
			if !storage.ValidRevocationReason(reason) {
				return fmt.Errorf("invalid reason %q (valid: unspecified, key_compromise, ca_compromise, affiliation_changed, superseded, cessation_of_operation, certificate_hold, remove_from_crl, privilege_withdrawn, aa_compromise)", reason)
			}

			store, err := storage.Open(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := store.RevokeCert(storage.RevokeOpts{
				Serial: serial, Reason: reason, Comment: comment, Actor: "cli",
			}); err != nil {
				return err
			}
			_ = store.InsertAudit("cli", "certificate.revoked", "certificate", serial, map[string]any{
				"reason": reason, "comment": comment,
			})
			fmt.Printf("Certificate revoked: %s (reason: %s)\n", serial, reason)
			return nil
		},
	}

	cmd.Flags().StringVar(&serial, "serial", "", "Certificate serial number (required)")
	cmd.Flags().StringVar(&reason, "reason", "unspecified", "Revocation reason")
	cmd.Flags().StringVar(&comment, "comment", "", "Revocation comment")
	cmd.Flags().StringVar(&dbPath, "db", "./open-pki.db", "SQLite database path")
	return cmd
}

func crlCmd() *cobra.Command {
	var (
		caName string
		caID   int64
		dbPath string
		outFile string
		format  string
	)

	cmd := &cobra.Command{
		Use:   "crl",
		Short: "Generate and export a CRL for a CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()

			var caRec *storage.CARecord
			if caName != "" {
				caRec, err = store.GetCAByName(caName)
			} else {
				caRec, err = store.GetCA(caID)
			}
			if err != nil {
				return fmt.Errorf("CA not found: %w", err)
			}

			keyPEM, err := store.GetKey("ca", caRec.ID)
			if err != nil {
				return fmt.Errorf("CA key not found: %w", err)
			}
			loadedCA, err := ca.LoadCAFromPEM([]byte(caRec.CertificatePEM), []byte(keyPEM))
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}

			entries, err := store.ListRevoked(caRec.ID)
			if err != nil {
				return err
			}

			var crlEntries []ca.CRLEntry
			for _, e := range entries {
				crlEntries = append(crlEntries, ca.CRLEntry{SerialHex: e.Serial, RevokedAt: e.RevokedAt, ReasonCode: e.ReasonCode})
			}
			crlDER, err := ca.GenerateCRL(loadedCA, crlEntries, 24)
			if err != nil {
				return err
			}

			_ = store.InsertAudit("cli", "crl.generated", "ca", fmt.Sprintf("%d", caRec.ID), map[string]any{
				"revoked_count": len(entries),
			})

			if outFile != "" {
				var data []byte
				if format == "der" {
					data = crlDER
				} else {
					data = ca.EncodeCRLPEM(crlDER)
				}
				if err := os.WriteFile(outFile, data, 0644); err != nil {
					return err
				}
				fmt.Printf("CRL written: %s (%d revoked entries, format: %s)\n", outFile, len(entries), format)
			} else {
				// Print to stdout
				if format == "der" {
					os.Stdout.Write(crlDER)
				} else {
					os.Stdout.Write(ca.EncodeCRLPEM(crlDER))
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&caName, "ca", "", "CA name")
	cmd.Flags().Int64Var(&caID, "ca-id", 1, "CA ID")
	cmd.Flags().StringVar(&dbPath, "db", "./open-pki.db", "SQLite database path")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "Output file (omit for stdout)")
	cmd.Flags().StringVar(&format, "format", "pem", "Output format (pem or der)")
	return cmd
}

func listCmd() *cobra.Command {
	var (
		status string
		dbPath string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()

			certs, err := store.ListCertsFiltered(status)
			if err != nil {
				return err
			}

			if len(certs) == 0 {
				fmt.Println("No certificates found.")
				return nil
			}

			fmt.Printf("%-20s %-15s %-10s %-10s %s\n", "COMMON NAME", "PROFILE", "STATUS", "EXPIRES", "SERIAL")
			for _, c := range certs {
				expires := c.NotAfter.Format("2006-01-02")
				fmt.Printf("%-20s %-15s %-10s %-10s %s\n", c.CommonName, c.Profile, c.Status, expires, c.Serial)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&status, "status", "", "Filter by status (active, revoked, expired)")
	cmd.Flags().StringVar(&dbPath, "db", "./open-pki.db", "SQLite database path")
	return cmd
}

func serveCmd() *cobra.Command {
	var (
		addr         string
		dbPath       string
		apiKey       string
		baseURL      string
		devMode      bool
		tlsCert      string
		tlsKey       string
		insecureHTTP bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the PKI server with REST API and dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Auth enforcement
			if !devMode && apiKey == "" {
				log.Fatal("FATAL: --api-key is required unless --dev is explicitly set.\n" +
					"  Use --api-key <key> for authenticated mode.\n" +
					"  Use --dev for local development (no auth).")
			}

			// TLS enforcement
			useTLS := tlsCert != "" && tlsKey != ""
			if !devMode && !useTLS && !insecureHTTP {
				log.Fatal("FATAL: TLS is required outside --dev.\n" +
					"  Provide --tls-cert and --tls-key for TLS.\n" +
					"  Or use --insecure-http for loopback-only evaluation.")
			}
			if !devMode && insecureHTTP && !isLoopbackAddr(addr) {
				log.Fatal("FATAL: --insecure-http is only allowed when binding to loopback (127.0.0.1 or localhost).")
			}

			// Base URL enforcement
			if !devMode && baseURL == "" {
				log.Fatal("FATAL: --base-url is required outside --dev.\n" +
					"  CRL/OCSP URLs in issued certificates need a real base URL.")
			}

			if devMode {
				log.Println("========================================")
				log.Println("  DEV MODE — NOT FOR PRODUCTION")
				log.Println("========================================")
				if baseURL == "" {
					baseURL = "http://localhost:8300"
				}
			}

			store, err := storage.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer store.Close()

			cfg := config.Default()
			cfg.Server.APIKey = apiKey
			cfg.Server.PublicBaseURL = baseURL

			profiles := profile.Defaults()
			srv := api.NewServer(store, profiles, cfg, useTLS)

			log.Printf("Cyphera Open PKI Server listening on %s", addr)
			log.Printf("  Database:  %s", dbPath)
			log.Printf("  Base URL:  %s", cfg.Server.PublicBaseURL)
			log.Printf("  CRL:       %s/crl/{ca_id}.crl", cfg.Server.PublicBaseURL)
			if apiKey != "" {
				log.Printf("  API key:   enabled")
			} else {
				log.Printf("  API key:   disabled (no auth)")
			}
			if useTLS {
				log.Printf("  TLS:       enabled")
				return http.ListenAndServeTLS(addr, tlsCert, tlsKey, srv.Handler())
			}
			log.Printf("  TLS:       disabled (HTTP)")
			return http.ListenAndServe(addr, srv.Handler())
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":8300", "Listen address")
	cmd.Flags().StringVar(&dbPath, "db", "./open-pki.db", "SQLite database path")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "API key for authentication")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate PEM file")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "TLS private key PEM file")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Public base URL for CRL/OCSP URLs (required outside --dev)")
	cmd.Flags().BoolVar(&devMode, "dev", false, "Dev mode — local development only, no auth, no TLS")
	cmd.Flags().BoolVar(&insecureHTTP, "insecure-http", false, "Allow plain HTTP outside --dev (loopback only)")

	return cmd
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return host == "127.0.0.1" || host == "::1" || host == "localhost" || host == ""
}

func availableProfiles(profiles map[string]*profile.Profile) string {
	var names []string
	for name := range profiles {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}
