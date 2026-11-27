package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ssl-center/internal/config"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

func TestArgon2idPasswordHashVerify(t *testing.T) {
	hash, err := HashPassword("CorrectHorseBatteryStaple!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword("CorrectHorseBatteryStaple!", hash)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword valid = (%v, %v), want (true, nil)", ok, err)
	}
	bad, err := VerifyPassword("WrongPassword", hash)
	if err != nil || bad {
		t.Fatalf("VerifyPassword wrong = (%v, %v), want (false, nil)", bad, err)
	}
	if _, err := VerifyPassword("x", "invalid-hash"); err == nil {
		t.Fatal("expected error on invalid PHC format")
	}
}

func TestBootstrapAdminModes(t *testing.T) {
	ctx := context.Background()

	// Case 1: No INIT_PASSWORD -> generates 16-char password + must_change_password=true
	dir1 := t.TempDir()
	db1, err := db.Open(filepath.Join(dir1, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close()

	svc1 := NewService(db1, &config.Config{CookieSecure: config.CookieSecureAuto}, nil)
	genPwd, err := svc1.BootstrapAdmin(ctx)
	if err != nil {
		t.Fatalf("BootstrapAdmin generated: %v", err)
	}
	if len(genPwd) != 16 {
		t.Fatalf("generated password len = %d, want 16", len(genPwd))
	}
	if !svc1.MustChangePassword(ctx) {
		t.Fatal("expected MustChangePassword=true for generated password")
	}

	// Re-running bootstrap must be idempotent
	genPwd2, err := svc1.BootstrapAdmin(ctx)
	if err != nil || genPwd2 != "" {
		t.Fatalf("second BootstrapAdmin = (%q, %v), want (\"\", nil)", genPwd2, err)
	}

	// Case 2: INIT_PASSWORD set -> must_change_password=false unless INIT_FORCE_CHANGE=true
	dir2 := t.TempDir()
	db2, err := db.Open(filepath.Join(dir2, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	svc2 := NewService(db2, &config.Config{InitPassword: "preset-password-123"}, nil)
	gen2, err := svc2.BootstrapAdmin(ctx)
	if err != nil || gen2 != "" {
		t.Fatalf("BootstrapAdmin preset = (%q, %v)", gen2, err)
	}
	if svc2.MustChangePassword(ctx) {
		t.Fatal("expected MustChangePassword=false when INIT_PASSWORD set without force")
	}
}

func TestSessionLifecycleRateLimitAndChangePassword(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	limiter := NewRateLimiter(3, 5*time.Minute, 5*time.Minute)
	svc := NewService(d, &config.Config{InitPassword: "init-password-123", InitForceChange: true}, limiter)
	if _, err := svc.BootstrapAdmin(ctx); err != nil {
		t.Fatal(err)
	}

	// 3 failed attempts trigger lockout
	for i := 0; i < 2; i++ {
		_, _, _, _, err := svc.Login(ctx, "192.0.2.10", "ua", "bad-pwd")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d err = %v, want ErrInvalidCredentials", i+1, err)
		}
	}
	_, _, _, retryAfter, err := svc.Login(ctx, "192.0.2.10", "ua", "bad-pwd")
	if !errors.Is(err, ErrRateLimited) || retryAfter <= 0 {
		t.Fatalf("3rd failed attempt = (%v, %v), want ErrRateLimited", err, retryAfter)
	}

	// Different IP succeeds and clears its own counter
	rawTok, sess, mustChange, _, err := svc.Login(ctx, "192.0.2.20", "ua", "init-password-123")
	if err != nil {
		t.Fatalf("Login valid IP failed: %v", err)
	}
	if !mustChange || sess.CSRFToken == "" || rawTok == "" {
		t.Fatalf("unexpected login result: mustChange=%v sess=%+v", mustChange, sess)
	}

	// ValidateSession succeeds and stores hash (not raw token) in DB
	if _, err := d.GetSession(ctx, rawTok); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("raw token must not be stored directly in sessions.id")
	}
	gotSess, gotMustChange, err := svc.ValidateSession(ctx, rawTok)
	if err != nil || !gotMustChange || gotSess.ID != sess.ID {
		t.Fatalf("ValidateSession = (%+v, %v, %v)", gotSess, gotMustChange, err)
	}

	// Second session created, then ChangePassword revokes other sessions
	rawTok2, _, _, _, err := svc.Login(ctx, "192.0.2.21", "ua2", "init-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ChangePassword(ctx, sess.ID, "init-password-123", "brand-new-strong-password", "192.0.2.20"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if svc.MustChangePassword(ctx) {
		t.Fatal("expected MustChangePassword=false after ChangePassword")
	}
	if _, _, err := svc.ValidateSession(ctx, rawTok2); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("other session should be invalidated after ChangePassword, got %v", err)
	}
	if _, gotMC, err := svc.ValidateSession(ctx, rawTok); err != nil || gotMC {
		t.Fatalf("current session after ChangePassword = (%v, %v)", gotMC, err)
	}

	// Logout
	if err := svc.Logout(ctx, rawTok); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ValidateSession(ctx, rawTok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("logged-out session still valid: %v", err)
	}

	// Verify audit event recorded
	evts, err := d.ListRecentAuditEvents(ctx, 10)
	if err != nil || len(evts) == 0 {
		t.Fatalf("expected audit events recorded")
	}
	_ = model.AuditEvent{}
}

func TestCookieSecureAndExtractClientIP(t *testing.T) {
	reqHTTP := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	if ResolveCookieSecure(config.CookieSecureAuto, reqHTTP) {
		t.Fatal("auto over plain HTTP should be false")
	}
	reqProxyHTTPS := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	reqProxyHTTPS.Header.Set("X-Forwarded-Proto", "https")
	if !ResolveCookieSecure(config.CookieSecureAuto, reqProxyHTTPS) {
		t.Fatal("auto with X-Forwarded-Proto=https should be true")
	}
	reqTLS := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	reqTLS.TLS = &tls.ConnectionState{}
	if !ResolveCookieSecure(config.CookieSecureAuto, reqTLS) {
		t.Fatal("auto over TLS should be true")
	}

	reqIP := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	reqIP.RemoteAddr = "10.0.0.5:12345"
	reqIP.Header.Set("X-Real-IP", "203.0.113.250")
	reqIP.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.42")
	if got := ExtractClientIP(reqIP, false); got != "10.0.0.5" {
		t.Fatalf("ExtractClientIP(trustProxy=false) = %q, want 10.0.0.5", got)
	}
	if got := ExtractClientIP(reqIP, true); got != "198.51.100.42" {
		t.Fatalf("ExtractClientIP(trustProxy=true) = %q, want rightmost XFF 198.51.100.42", got)
	}

	// Trailing invalid entry in XFF should fall back to rightmost valid XFF entry
	reqTrailingInvalid := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	reqTrailingInvalid.RemoteAddr = "10.0.0.5:12345"
	reqTrailingInvalid.Header.Set("X-Real-IP", "203.0.113.250")
	reqTrailingInvalid.Header.Set("X-Forwarded-For", "192.0.2.1, 198.51.100.77, not-an-ip")
	if got := ExtractClientIP(reqTrailingInvalid, true); got != "198.51.100.77" {
		t.Fatalf("ExtractClientIP with trailing invalid XFF = %q, want 198.51.100.77", got)
	}

	// Absent/invalid XFF falls back to X-Real-IP, then RemoteAddr
	reqOnlyXRI := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	reqOnlyXRI.RemoteAddr = "10.0.0.5:12345"
	reqOnlyXRI.Header.Set("X-Forwarded-For", "garbage")
	reqOnlyXRI.Header.Set("X-Real-IP", "198.51.100.99")
	if got := ExtractClientIP(reqOnlyXRI, true); got != "198.51.100.99" {
		t.Fatalf("ExtractClientIP X-Real-IP fallback = %q, want 198.51.100.99", got)
	}

	reqNoProxyHdrs := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	reqNoProxyHdrs.RemoteAddr = "10.0.0.5:12345"
	if got := ExtractClientIP(reqNoProxyHdrs, true); got != "10.0.0.5" {
		t.Fatalf("ExtractClientIP RemoteAddr fallback = %q, want 10.0.0.5", got)
	}
}

func TestTrustProxySpoofingCannotBypassRateLimit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	cfg := &config.Config{
		InitPassword:    "init-password-123",
		InitForceChange: false,
		TrustProxy:      true,
	}
	limiter := NewRateLimiter(3, 5*time.Minute, 5*time.Minute)
	svc := NewService(d, cfg, limiter)
	if _, err := svc.BootstrapAdmin(ctx); err != nil {
		t.Fatal(err)
	}

	// Attacker rotates X-Real-IP and prepends rotating fake IPs to X-Forwarded-For
	// while the trusted proxy appends the true client IP (198.51.100.77).
	for i := 1; i <= 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		req.RemoteAddr = "10.0.0.1:4444"
		req.Header.Set("X-Real-IP", fmt.Sprintf("203.0.113.%d", i))
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d, 198.51.100.77", i))

		clientIP := ExtractClientIP(req, cfg.TrustProxy)
		if clientIP != "198.51.100.77" {
			t.Fatalf("attempt %d resolved IP = %q, want 198.51.100.77", i, clientIP)
		}

		_, _, _, retryAfter, loginErr := svc.Login(ctx, clientIP, "ua", "wrong-password")
		if i < 3 {
			if !errors.Is(loginErr, ErrInvalidCredentials) {
				t.Fatalf("attempt %d err = %v, want ErrInvalidCredentials", i, loginErr)
			}
		} else {
			if !errors.Is(loginErr, ErrRateLimited) || retryAfter <= 0 {
				t.Fatalf("attempt %d = (%v, %v), want ErrRateLimited", i, loginErr, retryAfter)
			}
		}
	}
}
