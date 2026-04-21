package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/cyphera-labs/open-pki-server/internal/api"
	"github.com/cyphera-labs/open-pki-server/internal/ca"
	"github.com/cyphera-labs/open-pki-server/internal/cert"
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
		issueServerCertCmd(),
		issueClientCertCmd(),
		inspectCmd(),
		verifyCmd(),
		bundleCmd(),
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

func serveCmd() *cobra.Command {
	var (
		addr   string
		dbPath string
		apiKey string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the PKI server with REST API",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer store.Close()

			profiles := profile.Defaults()
			srv := api.NewServer(store, profiles, apiKey)

			log.Printf("Cyphera Open PKI Server listening on %s", addr)
			log.Printf("  Database: %s", dbPath)
			if apiKey != "" {
				log.Printf("  API key:  enabled")
			} else {
				log.Printf("  API key:  disabled (no auth)")
			}
			return http.ListenAndServe(addr, srv.Handler())
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":8300", "Listen address")
	cmd.Flags().StringVar(&dbPath, "db", "./open-pki.db", "SQLite database path")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "API key for authentication (optional)")

	return cmd
}

func availableProfiles(profiles map[string]*profile.Profile) string {
	var names []string
	for name := range profiles {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}
