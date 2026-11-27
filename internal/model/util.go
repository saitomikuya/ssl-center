package model

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var containerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// ValidateContainerName enforces a strict Docker container name whitelist
// to prevent command injection when building docker exec commands.
func ValidateContainerName(name string) error {
	if !containerNameRegex.MatchString(name) {
		return fmt.Errorf("invalid container name %q: must match ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$", name)
	}
	return nil
}

// ShellQuote wraps s in POSIX single quotes, escaping embedded single quotes safely.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// NormalizeDomain trims whitespace, lowercases, and removes any trailing dot,
// while preserving wildcard prefixes such as "*.example.com".
func NormalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".")
	return d
}

// DefaultCaddyReloadCmd builds the mandatory `--force` Caddy reload command
// with safe POSIX single-quote escaping.
func DefaultCaddyReloadCmd(container, containerCaddyfile string) string {
	if container == "" {
		container = "caddy"
	}
	if containerCaddyfile == "" {
		containerCaddyfile = "/etc/caddy/Caddyfile"
	}
	return fmt.Sprintf("docker exec %s caddy reload --config %s --force",
		ShellQuote(container), ShellQuote(containerCaddyfile))
}

// ParseLeafFingerprintSHA256 extracts the first CERTIFICATE PEM block from certPEM
// and returns its lowercase SHA-256 hex digest over the leaf DER bytes.
func ParseLeafFingerprintSHA256(certPEM []byte) (string, error) {
	rest := certPEM
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse leaf x509 certificate: %w", err)
		}
		sum := sha256.Sum256(cert.Raw)
		return hex.EncodeToString(sum[:]), nil
	}
	return "", errors.New("no CERTIFICATE PEM block found")
}
