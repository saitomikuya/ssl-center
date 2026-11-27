package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"ssl-center/internal/config"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

const MinPasswordLength = 8

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrRateLimited        = errors.New("too many failed login attempts")
	ErrSessionInvalid     = errors.New("session is missing or expired")
	ErrWeakPassword       = errors.New("password must be at least 8 characters")
	ErrSamePassword       = errors.New("new password must differ from current password")
)

// Service coordinates single-admin authentication, password bootstrap,
// session management, and IP rate limiting.
type Service struct {
	db      *db.DB
	cfg     *config.Config
	limiter *RateLimiter
}

// NewService constructs an auth Service.
func NewService(database *db.DB, cfg *config.Config, limiter *RateLimiter) *Service {
	if limiter == nil {
		limiter = NewRateLimiter(DefaultMaxAttempts, DefaultWindow, DefaultLockout)
	}
	return &Service{
		db:      database,
		cfg:     cfg,
		limiter: limiter,
	}
}

// BootstrapAdmin initializes admin_password_hash and must_change_password on a fresh database.
// If INIT_PASSWORD is empty, a 16-character random password is generated, logged once to stdout,
// and returned; otherwise generatedPassword is empty.
func (s *Service) BootstrapAdmin(ctx context.Context) (string, error) {
	existing, err := s.db.GetSetting(ctx, model.SettingAdminPasswordHash)
	if err == nil && strings.TrimSpace(existing) != "" {
		return "", nil
	}
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return "", fmt.Errorf("check admin password hash: %w", err)
	}

	var rawPassword string
	var generated string
	mustChange := "false"

	if strings.TrimSpace(s.cfg.InitPassword) != "" {
		rawPassword = s.cfg.InitPassword
		if s.cfg.InitForceChange {
			mustChange = "true"
		}
	} else {
		pwd, err := GenerateRandomPassword(16)
		if err != nil {
			return "", err
		}
		rawPassword = pwd
		generated = pwd
		mustChange = "true"
		fmt.Printf("[SECURITY] Initial admin password (change on first login): %s\n", pwd)
	}

	hash, err := HashPassword(rawPassword)
	if err != nil {
		return "", fmt.Errorf("hash initial admin password: %w", err)
	}
	if err := s.db.SetSetting(ctx, model.SettingAdminPasswordHash, hash); err != nil {
		return "", fmt.Errorf("store admin password hash: %w", err)
	}
	if err := s.db.SetSetting(ctx, model.SettingMustChangePassword, mustChange); err != nil {
		return "", fmt.Errorf("store must_change_password: %w", err)
	}
	return generated, nil
}

// Login authenticates the single administrator, enforces per-IP rate limiting,
// and creates a persisted session.
func (s *Service) Login(ctx context.Context, ip, userAgent, password string) (string, *model.Session, bool, time.Duration, error) {
	if allowed, retryAfter := s.limiter.Allow(ip); !allowed {
		return "", nil, false, retryAfter, ErrRateLimited
	}

	storedHash, err := s.db.GetSetting(ctx, model.SettingAdminPasswordHash)
	if err != nil {
		return "", nil, false, 0, fmt.Errorf("load admin password hash: %w", err)
	}

	ok, err := VerifyPassword(password, storedHash)
	if err != nil || !ok {
		locked, retryAfter := s.limiter.RecordFailure(ip)
		_, _ = s.db.CreateAuditEvent(ctx, &model.AuditEvent{
			EventType: "auth.login_failed",
			Level:     model.AuditLevelWarn,
			Message:   "Administrator login failed",
			ActorIP:   ip,
		})
		if locked {
			return "", nil, false, retryAfter, ErrRateLimited
		}
		return "", nil, false, 0, ErrInvalidCredentials
	}

	s.limiter.Reset(ip)

	rawToken, tokenHash, csrfToken, err := GenerateSessionTokens()
	if err != nil {
		return "", nil, false, 0, fmt.Errorf("generate session tokens: %w", err)
	}

	now := time.Now().UTC()
	sess := &model.Session{
		ID:         tokenHash,
		CSRFToken:  csrfToken,
		IP:         ip,
		UserAgent:  userAgent,
		ExpiresAt:  now.Add(SessionTTL),
		CreatedAt:  now,
		LastSeenAt: now,
	}
	if err := s.db.CreateSession(ctx, sess); err != nil {
		return "", nil, false, 0, fmt.Errorf("persist session: %w", err)
	}

	_, _ = s.db.DeleteExpiredSessions(ctx, now)
	_, _ = s.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType: "auth.login",
		Level:     model.AuditLevelInfo,
		Message:   "Administrator logged in",
		ActorIP:   ip,
	})

	mustChange := s.MustChangePassword(ctx)
	return rawToken, sess, mustChange, 0, nil
}

// Logout revokes the session associated with rawToken.
func (s *Service) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}
	return s.db.DeleteSession(ctx, HashSessionToken(rawToken))
}

// ValidateSession verifies a raw cookie token against SQLite and returns the
// active Session and whether password change is currently required.
func (s *Service) ValidateSession(ctx context.Context, rawToken string) (*model.Session, bool, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, false, ErrSessionInvalid
	}
	tokenHash := HashSessionToken(rawToken)
	sess, err := s.db.GetSession(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, false, ErrSessionInvalid
		}
		return nil, false, err
	}

	now := time.Now().UTC()
	if !sess.ExpiresAt.After(now) {
		_ = s.db.DeleteSession(ctx, tokenHash)
		return nil, false, ErrSessionInvalid
	}

	if now.Sub(sess.LastSeenAt) > time.Minute {
		_ = s.db.TouchSession(ctx, tokenHash, now)
		sess.LastSeenAt = now
	}

	return sess, s.MustChangePassword(ctx), nil
}

// MustChangePassword returns true if the administrator must change password before accessing protected resources.
func (s *Service) MustChangePassword(ctx context.Context) bool {
	v, err := s.db.GetSetting(ctx, model.SettingMustChangePassword)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(v), "true")
}

// ChangePassword verifies currentPassword, updates the stored Argon2id hash,
// clears must_change_password, and invalidates all other active sessions.
func (s *Service) ChangePassword(ctx context.Context, currentSessionID, currentPassword, newPassword, actorIP string) error {
	if len(newPassword) < MinPasswordLength {
		return ErrWeakPassword
	}
	if currentPassword == newPassword {
		return ErrSamePassword
	}

	storedHash, err := s.db.GetSetting(ctx, model.SettingAdminPasswordHash)
	if err != nil {
		return fmt.Errorf("load admin password hash: %w", err)
	}
	ok, err := VerifyPassword(currentPassword, storedHash)
	if err != nil || !ok {
		return ErrInvalidCredentials
	}

	newHash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}
	if err := s.db.SetSetting(ctx, model.SettingAdminPasswordHash, newHash); err != nil {
		return fmt.Errorf("save new password hash: %w", err)
	}
	if err := s.db.SetSetting(ctx, model.SettingMustChangePassword, "false"); err != nil {
		return fmt.Errorf("clear must_change_password: %w", err)
	}
	if currentSessionID != "" {
		_ = s.db.DeleteOtherSessions(ctx, currentSessionID)
	}

	_, _ = s.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType: "auth.password_changed",
		Level:     model.AuditLevelInfo,
		Message:   "Administrator password changed",
		ActorIP:   actorIP,
	})
	return nil
}

// ExtractClientIP resolves the client IP from RemoteAddr or proxy headers when trustProxy is true.
// When trustProxy is true, X-Forwarded-For is inspected from rightmost to leftmost to pick the
// rightmost valid IP appended by the trusted proxy, preventing clients from spoofing X-Real-IP
// or prepending fake leftmost X-Forwarded-For entries to bypass rate limiting.
func ExtractClientIP(r *http.Request, trustProxy bool) string {
	if r == nil {
		return ""
	}
	if trustProxy {
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				candidate := strings.TrimSpace(parts[i])
				if ip := net.ParseIP(candidate); ip != nil {
					return ip.String()
				}
			}
		}
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			if ip := net.ParseIP(xri); ip != nil {
				return ip.String()
			}
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
