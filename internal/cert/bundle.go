package cert

import (
	"fmt"
	"os"
)

// Bundle concatenates CA certificate PEM files into a trust bundle.
func Bundle(outputPath string, certPaths ...string) error {
	var bundle []byte
	for _, p := range certPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		bundle = append(bundle, data...)
		// Ensure newline between certs
		if len(data) > 0 && data[len(data)-1] != '\n' {
			bundle = append(bundle, '\n')
		}
	}

	if err := os.WriteFile(outputPath, bundle, 0644); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}
	return nil
}
