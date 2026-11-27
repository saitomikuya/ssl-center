package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"ssl-center/internal/config"
)

const (
	SessionCookieName = "ssl_center_session"
	SessionTTL        = 7 * 24 * time.Hour
)

// GenerateSessionTokens returns a raw 32-byte hex cookie token, its SHA-256 hex digest
// for database storage, and a 32-byte hex CSRF token.
func GenerateSessionTokens() (rawToken, tokenHash, csrfToken string, err error) {
	rawBytes := make([]byte, 32)
	if _, err = rand.Read(rawBytes); err != nil {
		return "", "", "", err
	}
	csrfBytes := make([]byte, 32)
	if _, err = rand.Read(csrfBytes); err != nil {
		return "", "", "", err
	}
	rawToken = hex.EncodeToString(rawBytes)
	tokenHash = HashSessionToken(rawToken)
	csrfToken = hex.EncodeToString(csrfBytes)
	return rawToken, tokenHash, csrfToken, nil
}

// HashSessionToken returns the SHA-256 hex digest of a raw cookie token.
func HashSessionToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// ResolveCookieSecure determines whether the session cookie should carry the Secure flag.
func ResolveCookieSecure(mode config.CookieSecureMode, r *http.Request) bool {
	switch mode {
	case config.CookieSecureTrue:
		return true
	case config.CookieSecureFalse:
		return false
	default: // auto
		if r == nil {
			return false
		}
		if r.TLS != nil {
			return true
		}
		proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
		if strings.EqualFold(proto, "https") {
			return true
		}
		return false
	}
}

// SetSessionCookie writes the HttpOnly SameSite=Lax session cookie.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, mode config.CookieSecureMode, rawToken string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    rawToken,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   ResolveCookieSecure(mode, r),
	})
}

// ClearSessionCookie expires the session cookie on the client.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request, mode config.CookieSecureMode) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   ResolveCookieSecure(mode, r),
	})
}
