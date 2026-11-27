package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestValidateContainerName(t *testing.T) {
	valid := []string{"caddy", "my-caddy_1.prod", "A1"}
	for _, name := range valid {
		if err := ValidateContainerName(name); err != nil {
			t.Fatalf("expected %q to be valid, got %v", name, err)
		}
	}

	invalid := []string{"", "-caddy", ".caddy", "caddy;rm -rf /", "caddy$(id)", strings.Repeat("a", 129), "caddy name"}
	for _, name := range invalid {
		if err := ValidateContainerName(name); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
}

func TestShellQuoteAndDefaultCaddyReloadCmd(t *testing.T) {
	if got := ShellQuote("a'b"); got != `'a'\''b'` {
		t.Fatalf("ShellQuote = %q", got)
	}
	cmd := DefaultCaddyReloadCmd("caddy", "/etc/caddy/Caddyfile")
	if !strings.Contains(cmd, "--force") {
		t.Fatalf("reload command missing --force: %s", cmd)
	}
	if cmd != "docker exec 'caddy' caddy reload --config '/etc/caddy/Caddyfile' --force" {
		t.Fatalf("unexpected reload cmd: %s", cmd)
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"  Example.COM. ":   "example.com",
		"*.Example.Org.":    "*.example.org",
		"sub.domain.net":    "sub.domain.net",
		"  LOCALHOST  ":     "localhost",
	}
	for in, want := range cases {
		if got := NormalizeDomain(in); got != want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseLeafFingerprintSHA256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	fullchain := append([]byte{}, leafPEM...)
	fullchain = append(fullchain, leafPEM...)

	fp, err := ParseLeafFingerprintSHA256(fullchain)
	if err != nil {
		t.Fatalf("ParseLeafFingerprintSHA256 failed: %v", err)
	}
	sum := sha256.Sum256(der)
	want := hex.EncodeToString(sum[:])
	if fp != want {
		t.Fatalf("fingerprint = %q, want %q", fp, want)
	}

	if _, err := ParseLeafFingerprintSHA256([]byte("not a cert")); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}
