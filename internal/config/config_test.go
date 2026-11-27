package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	for _, k := range []string{"DATA_DIR", "LISTEN_ADDR", "PORT", "INIT_PASSWORD", "INIT_FORCE_CHANGE", "COOKIE_SECURE", "TRUST_PROXY", "LOG_LEVEL", "TZ"} {
		t.Setenv(k, "")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.DataDir != "/data" {
		t.Fatalf("DataDir = %q, want /data", cfg.DataDir)
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.CookieSecure != CookieSecureAuto {
		t.Fatalf("CookieSecure = %q, want auto", cfg.CookieSecure)
	}
	if cfg.TrustProxy {
		t.Fatalf("TrustProxy = true, want false")
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.TZ != "Asia/Shanghai" {
		t.Fatalf("TZ = %q, want Asia/Shanghai", cfg.TZ)
	}
}

func TestLoadCustomAndEnsureDataDirs(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "custom_data")
	t.Setenv("DATA_DIR", dataDir)
	t.Setenv("LISTEN_ADDR", "127.0.0.1:9090")
	t.Setenv("INIT_PASSWORD", "secret123456")
	t.Setenv("INIT_FORCE_CHANGE", "true")
	t.Setenv("COOKIE_SECURE", "false")
	t.Setenv("TRUST_PROXY", "true")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("TZ", "UTC")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9090" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if !cfg.InitForceChange || !cfg.TrustProxy {
		t.Fatalf("expected InitForceChange and TrustProxy true")
	}
	if err := cfg.EnsureDataDirs(); err != nil {
		t.Fatalf("EnsureDataDirs() error: %v", err)
	}

	for _, dir := range []string{cfg.DataDir, cfg.CertsDir(), cfg.TmpDir()} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
	}
	tmpInfo, _ := os.Stat(cfg.TmpDir())
	if tmpInfo.Mode().Perm() != 0o700 {
		t.Fatalf("tmp dir perm = %o, want 0700", tmpInfo.Mode().Perm())
	}
	if cfg.CertDir(42) != filepath.Join(dataDir, "certs", "cert_42") {
		t.Fatalf("CertDir(42) = %q", cfg.CertDir(42))
	}
}

func TestLoadInvalidValues(t *testing.T) {
	t.Setenv("COOKIE_SECURE", "invalid")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid COOKIE_SECURE")
	}
	t.Setenv("COOKIE_SECURE", "auto")
	t.Setenv("LOG_LEVEL", "verbose")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid LOG_LEVEL")
	}
}
