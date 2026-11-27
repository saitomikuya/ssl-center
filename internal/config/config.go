package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CookieSecureMode controls the Secure flag on the session cookie.
type CookieSecureMode string

const (
	CookieSecureAuto  CookieSecureMode = "auto"
	CookieSecureTrue  CookieSecureMode = "true"
	CookieSecureFalse CookieSecureMode = "false"
)

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	DataDir         string
	ListenAddr      string
	InitPassword    string
	InitForceChange bool
	CookieSecure    CookieSecureMode
	TrustProxy      bool
	LogLevel        string
	TZ              string
}

// Load reads configuration from environment variables with safe production defaults.
func Load() (*Config, error) {
	cfg := &Config{
		DataDir:         getEnvDefault("DATA_DIR", "/data"),
		ListenAddr:      os.Getenv("LISTEN_ADDR"),
		InitPassword:    os.Getenv("INIT_PASSWORD"),
		InitForceChange: parseBoolEnv("INIT_FORCE_CHANGE", false),
		CookieSecure:    CookieSecureMode(strings.ToLower(getEnvDefault("COOKIE_SECURE", "auto"))),
		TrustProxy:      parseBoolEnv("TRUST_PROXY", false),
		LogLevel:        strings.ToLower(getEnvDefault("LOG_LEVEL", "info")),
		TZ:              getEnvDefault("TZ", "Asia/Shanghai"),
	}

	if cfg.ListenAddr == "" {
		if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
			if strings.HasPrefix(port, ":") {
				cfg.ListenAddr = port
			} else {
				cfg.ListenAddr = ":" + port
			}
		} else {
			cfg.ListenAddr = ":8080"
		}
	}

	switch cfg.CookieSecure {
	case CookieSecureAuto, CookieSecureTrue, CookieSecureFalse:
	default:
		return nil, fmt.Errorf("invalid COOKIE_SECURE %q: must be auto, true, or false", cfg.CookieSecure)
	}

	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("invalid LOG_LEVEL %q: must be debug, info, warn, or error", cfg.LogLevel)
	}

	if cfg.DataDir == "" {
		return nil, fmt.Errorf("DATA_DIR must not be empty")
	}
	cfg.DataDir = filepath.Clean(cfg.DataDir)

	return cfg, nil
}

// EnsureDataDirs creates DATA_DIR, certs/, and tmp/ with appropriate permissions.
func (c *Config) EnsureDataDirs() error {
	if err := os.MkdirAll(c.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir %s: %w", c.DataDir, err)
	}
	if err := os.MkdirAll(c.CertsDir(), 0o755); err != nil {
		return fmt.Errorf("create certs dir %s: %w", c.CertsDir(), err)
	}
	if err := os.MkdirAll(c.TmpDir(), 0o700); err != nil {
		return fmt.Errorf("create tmp dir %s: %w", c.TmpDir(), err)
	}
	return nil
}

// MasterKeyPath returns the path to master.key.
func (c *Config) MasterKeyPath() string {
	return filepath.Join(c.DataDir, "master.key")
}

// DBPath returns the path to app.db.
func (c *Config) DBPath() string {
	return filepath.Join(c.DataDir, "app.db")
}

// CertsDir returns the path to certs/.
func (c *Config) CertsDir() string {
	return filepath.Join(c.DataDir, "certs")
}

// CertDir returns the directory path for a specific certificate ID.
func (c *Config) CertDir(certID int64) string {
	return filepath.Join(c.CertsDir(), fmt.Sprintf("cert_%d", certID))
}

// TmpDir returns the path to tmp/.
func (c *Config) TmpDir() string {
	return filepath.Join(c.DataDir, "tmp")
}

// Location resolves the configured TZ, falling back to UTC if unavailable.
func (c *Config) Location() *time.Location {
	if c.TZ == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(c.TZ)
	if err != nil {
		return time.UTC
	}
	return loc
}

func getEnvDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func parseBoolEnv(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
