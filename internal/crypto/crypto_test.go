package crypto

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoadOrCreateMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "nested", "master.key")

	key1, created1, err := LoadOrCreateMasterKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateMasterKey create failed: %v", err)
	}
	if !created1 {
		t.Fatal("expected created=true on first call")
	}
	if len(key1) != MasterKeySize {
		t.Fatalf("key length = %d, want %d", len(key1), MasterKeySize)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat master.key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("master.key perm = %o, want 0600", info.Mode().Perm())
	}

	key2, created2, err := LoadOrCreateMasterKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateMasterKey load failed: %v", err)
	}
	if created2 {
		t.Fatal("expected created=false on second call")
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("reloaded master key differs from created key")
	}

	// Corrupt length check
	badPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateMasterKey(badPath); err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestCipherAESGCMAndReload(t *testing.T) {
	key1 := make([]byte, MasterKeySize)
	key2 := make([]byte, MasterKeySize)
	_, _ = rand.Read(key1)
	_, _ = rand.Read(key2)

	c, err := NewCipher(key1)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	// Empty string handling
	encEmpty, err := c.Encrypt("", "hosts:ssh_password_enc")
	if err != nil || encEmpty != "" {
		t.Fatalf("Encrypt empty = (%q, %v), want (\"\", nil)", encEmpty, err)
	}
	decEmpty, err := c.Decrypt("", "hosts:ssh_password_enc")
	if err != nil || decEmpty != "" {
		t.Fatalf("Decrypt empty = (%q, %v), want (\"\", nil)", decEmpty, err)
	}

	secret := "cf_token_super_secret_value"
	aad := "dns_credentials:config_enc"
	ct, err := c.Encrypt(secret, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(ct, EnvelopePrefix) {
		t.Fatalf("ciphertext %q missing prefix %q", ct, EnvelopePrefix)
	}

	pt, err := c.Decrypt(ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != secret {
		t.Fatalf("Decrypt = %q, want %q", pt, secret)
	}

	// Wrong AAD must fail
	if _, err := c.Decrypt(ct, "hosts:ssh_password_enc"); err == nil {
		t.Fatal("expected Decrypt to fail with wrong AAD")
	}

	// Missing prefix or short payload must fail
	if _, err := c.Decrypt("raw_invalid", aad); err == nil {
		t.Fatal("expected error for missing v1: prefix")
	}
	if _, err := c.Decrypt("v1:AAAA", aad); err == nil {
		t.Fatal("expected error for short payload")
	}

	// ReloadKey
	if err := c.ReloadKey(key2); err != nil {
		t.Fatalf("ReloadKey: %v", err)
	}
	if _, err := c.Decrypt(ct, aad); err == nil {
		t.Fatal("expected old ciphertext to fail after ReloadKey")
	}
	ct2, err := c.Encrypt(secret, aad)
	if err != nil {
		t.Fatalf("Encrypt after ReloadKey: %v", err)
	}
	pt2, err := c.Decrypt(ct2, aad)
	if err != nil || pt2 != secret {
		t.Fatalf("Decrypt after ReloadKey = (%q, %v)", pt2, err)
	}
}

func TestSecretRedactor(t *testing.T) {
	r := NewSecretRedactor()
	r.Add("short", "cf_secret_token_12345", "cf_secret_token_12345_extended")

	// Short secrets (<6) must be ignored
	if got := r.Redact("short word stays"); got != "short word stays" {
		t.Fatalf("short secret was redacted: %q", got)
	}

	// Longest-first replacement
	got := r.Redact("token=cf_secret_token_12345_extended and old=cf_secret_token_12345")
	if got != "token=***REDACTED*** and old=***REDACTED***" {
		t.Fatalf("unexpected redaction output: %q", got)
	}

	// Multi-line PEM key registration & individual line redaction
	pemKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\nAAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=\n-----END OPENSSH PRIVATE KEY-----"
	r.Add(pemKey)

	lineLeak := "debug line: AAAA" + "E2VjZHNhLXNoYTItbmlzdHAyNTY="
	if redacted := r.Redact(lineLeak); strings.Contains(redacted, "E2VjZHNhLXNoYTItbmlzdHAyNTY") {
		t.Fatalf("PEM body line was not redacted: %q", redacted)
	}

	// Unregistered PEM fallback
	otherPEM := "prefix\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----\nsuffix"
	redactedPEM := r.Redact(otherPEM)
	if strings.Contains(redactedPEM, "MIIEowIBAAKCAQEA1234567890") {
		t.Fatalf("PEM regex fallback failed: %q", redactedPEM)
	}

	// Remove & ReplaceAll
	r.Remove("cf_secret_token_12345")
	if out := r.Redact("cf_secret_token_12345"); out != "cf_secret_token_12345" {
		t.Fatalf("removed secret still redacted: %q", out)
	}

	r.ReplaceAll([]string{"new_dynamic_secret_999"})
	if out := r.Redact("cf_secret_token_12345_extended new_dynamic_secret_999"); out != "cf_secret_token_12345_extended ***REDACTED***" {
		t.Fatalf("ReplaceAll mismatch: %q", out)
	}

	// RedactingWriter
	var buf bytes.Buffer
	rw := r.RedactingWriter(&buf)
	n, err := rw.Write([]byte("hello new_dynamic_secret_999 world"))
	if err != nil {
		t.Fatalf("RedactingWriter.Write: %v", err)
	}
	if n != len("hello new_dynamic_secret_999 world") {
		t.Fatalf("Write returned %d, want %d", n, len("hello new_dynamic_secret_999 world"))
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("RedactingWriter.Close: %v", err)
	}
	if buf.String() != "hello ***REDACTED*** world" {
		t.Fatalf("RedactingWriter buffer = %q", buf.String())
	}
}

func TestSecretRedactorHardening(t *testing.T) {
	// 1. Reference-counted Remove preserves shared PEM lines
	r := NewSecretRedactor()
	sharedHeaderLine := "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz"
	pem1Unique := "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPemOne11111"
	pem2Unique := "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPemTwo22222"

	pem1 := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + sharedHeaderLine + "\n" + pem1Unique + "\n-----END OPENSSH PRIVATE KEY-----"
	pem2 := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + sharedHeaderLine + "\n" + pem2Unique + "\n-----END OPENSSH PRIVATE KEY-----"

	r.Add(pem1, pem2)
	r.Remove(pem1)

	if got := r.Redact("shared: " + sharedHeaderLine); got != "shared: ***REDACTED***" {
		t.Fatalf("shared PEM line leaked after Remove(pem1): %q", got)
	}
	if got := r.Redact("unique1: " + pem1Unique); got != "unique1: "+pem1Unique {
		t.Fatalf("pem1 unique line should have been removed: %q", got)
	}
	if got := r.Redact("unique2: " + pem2Unique); got != "unique2: ***REDACTED***" {
		t.Fatalf("pem2 unique line should remain redacted: %q", got)
	}

	r.Remove(pem2)
	if got := r.Redact("shared: " + sharedHeaderLine); got != "shared: "+sharedHeaderLine {
		t.Fatalf("shared PEM line should be removed after Remove(pem2): %q", got)
	}

	// 2. Placeholder collision ("REDACTED" secret must not double-redact "***REDACTED***")
	r.ReplaceAll([]string{"REDACTED", "my_api_token_99", "super_REDACTED_key"})
	if got := r.Redact("token=my_api_token_99"); got != "token=***REDACTED***" {
		t.Fatalf("placeholder collision output = %q, want token=***REDACTED***", got)
	}
	if got := r.Redact("k=super_REDACTED_key"); got != "k=***REDACTED***" {
		t.Fatalf("super_REDACTED_key output = %q, want k=***REDACTED***", got)
	}

	// 3. Chunked RedactingWriter across Write boundaries
	r.ReplaceAll([]string{"super_secret_token_xyz"})
	var out bytes.Buffer
	rw := r.RedactingWriter(&out)
	if _, err := rw.Write([]byte("prefix super_secret_")); err != nil {
		t.Fatalf("Write chunk 1: %v", err)
	}
	if _, err := rw.Write([]byte("token_xyz suffix")); err != nil {
		t.Fatalf("Write chunk 2: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if out.String() != "prefix ***REDACTED*** suffix" {
		t.Fatalf("chunked RedactingWriter = %q, want %q", out.String(), "prefix ***REDACTED*** suffix")
	}

	// 4. Chunked RedactingWriter with long prefix and multi-line logs + Flush + split unregistered PEM
	out.Reset()
	rw2 := r.RedactingWriter(&out)
	chunks := []string{
		"log start before super_secret_",
		"token_xyz middle\nsecond line ok\n",
		"-----BEGIN RSA PRIVATE KEY-----\n",
		"MIIEowIBAAKCAQEA1234567890\n",
		"-----END RSA PRIVATE KEY-----\n",
	}
	for i, c := range chunks {
		if _, err := rw2.Write([]byte(c)); err != nil {
			t.Fatalf("Write chunk %d: %v", i, err)
		}
	}
	if err := rw2.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	gotStream := out.String()
	wantStream := "log start before ***REDACTED*** middle\nsecond line ok\n***REDACTED***\n"
	if gotStream != wantStream {
		t.Fatalf("multi-chunk stream = %q, want %q", gotStream, wantStream)
	}
}

func TestCryptoConcurrentRace(t *testing.T) {
	key := make([]byte, MasterKeySize)
	_, _ = rand.Read(key)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	r := NewSecretRedactor()
	r.Add("initial_secret_value_123")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				ct, err := c.Encrypt("payload_secret_value", "table:col")
				if err == nil {
					_, _ = c.Decrypt(ct, "table:col")
				}
				_ = r.Redact("log line with initial_secret_value_123")
				if j%5 == 0 {
					r.Add("dynamic_secret_value_456")
				}
			}
		}(i)
	}
	wg.Wait()
}
