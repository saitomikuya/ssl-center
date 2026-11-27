package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"ssl-center/internal/auth"
	"ssl-center/internal/crypto"
	"ssl-center/internal/model"
)

type ctxKey string

const (
	ctxSessionKey    ctxKey = "ssl_center_session"
	ctxMustChangeKey ctxKey = "ssl_center_must_change_pwd"
	ctxClientIPKey   ctxKey = "ssl_center_client_ip"
)

// SessionFromContext retrieves the authenticated session injected by RequireAuth.
func SessionFromContext(ctx context.Context) (*model.Session, bool) {
	sess, ok := ctx.Value(ctxSessionKey).(*model.Session)
	return sess, ok && sess != nil
}

// MustChangePasswordFromContext reports whether the admin must change password.
func MustChangePasswordFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(ctxMustChangeKey).(bool)
	return v
}

// ClientIPFromContext retrieves the resolved client IP from context.
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(ctxClientIPKey).(string)
	return ip
}

// MaintenanceCoordinatorImpl implements model.MaintenanceCoordinator.
type MaintenanceCoordinatorImpl struct {
	mu          sync.Mutex
	active      atomic.Bool
	pauseHooks  []func()
	resumeHooks []func()
}

// NewMaintenanceCoordinator constructs a MaintenanceCoordinator.
func NewMaintenanceCoordinator() *MaintenanceCoordinatorImpl {
	return &MaintenanceCoordinatorImpl{}
}

// IsActive returns true when global maintenance mode is engaged.
func (m *MaintenanceCoordinatorImpl) IsActive() bool {
	return m.active.Load()
}

// RegisterSchedulerHook registers pause/resume callbacks invoked around backup restore.
func (m *MaintenanceCoordinatorImpl) RegisterSchedulerHook(pause, resume func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pause != nil {
		m.pauseHooks = append(m.pauseHooks, pause)
	}
	if resume != nil {
		m.resumeHooks = append(m.resumeHooks, resume)
	}
}

// BeginMaintenance acquires the maintenance lock, pauses schedulers, and marks maintenance active.
func (m *MaintenanceCoordinatorImpl) BeginMaintenance(ctx context.Context) error {
	if !m.mu.TryLock() {
		return errors.New("maintenance operation already in progress")
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}
	m.active.Store(true)
	for _, fn := range m.pauseHooks {
		fn()
	}
	return nil
}

// EndMaintenance clears maintenance mode, resumes schedulers, and releases the lock.
func (m *MaintenanceCoordinatorImpl) EndMaintenance() {
	m.active.Store(false)
	for _, fn := range m.resumeHooks {
		fn()
	}
	m.mu.Unlock()
}

// Middleware rejects mutating HTTP requests with 503 MAINTENANCE_IN_PROGRESS while active.
func (m *MaintenanceCoordinatorImpl) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.IsActive() && isMutatingMethod(r.Method) {
				Fail(w, http.StatusServiceUnavailable, CodeMaintenanceInProgress, "System maintenance in progress; try again shortly", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Recoverer catches panics, redacts any leaked secret material, and returns 500 JSON.
func Recoverer(redactor *crypto.SecretRedactor, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					msg := fmt.Sprintf("panic: %v\n%s", rec, debug.Stack())
					if redactor != nil {
						msg = redactor.Redact(msg)
					}
					if logger != nil {
						logger.Error("http panic recovered", "path", r.URL.Path, "error", msg)
					}
					Fail(w, http.StatusInternalServerError, CodeInternalError, "Internal server error", nil)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Flush() {
	if flusher, ok := sr.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
}

// RequestLogger logs HTTP requests with secret redaction.
func RequestLogger(redactor *crypto.SecretRedactor, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if logger == nil {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			path := r.URL.Path
			if redactor != nil {
				path = redactor.Redact(path)
			}
			logger.Info("http request",
				"method", r.Method,
				"path", path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// RequireAuth validates the session cookie and injects Session + MustChangePassword + ClientIP into context.
func RequireAuth(authSvc *auth.Service, trustProxy bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(auth.SessionCookieName)
			if err != nil || cookie.Value == "" {
				Fail(w, http.StatusUnauthorized, CodeUnauthorized, "Authentication required", nil)
				return
			}
			sess, mustChange, err := authSvc.ValidateSession(r.Context(), cookie.Value)
			if err != nil {
				Fail(w, http.StatusUnauthorized, CodeUnauthorized, "Session invalid or expired", nil)
				return
			}

			ip := auth.ExtractClientIP(r, trustProxy)
			ctx := context.WithValue(r.Context(), ctxSessionKey, sess)
			ctx = context.WithValue(ctx, ctxMustChangeKey, mustChange)
			ctx = context.WithValue(ctx, ctxClientIPKey, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePasswordChanged blocks access to normal API routes until the initial password has been changed.
func RequirePasswordChanged() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/auth/me", "/api/v1/auth/change-password", "/api/v1/auth/logout":
				next.ServeHTTP(w, r)
				return
			}
			if MustChangePasswordFromContext(r.Context()) {
				Fail(w, http.StatusForbidden, CodePasswordChangeRequired, "Initial password must be changed before continuing", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireCSRF validates X-CSRF-Token against the authenticated session's CSRF token on mutating methods.
func RequireCSRF() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isMutatingMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			sess, ok := SessionFromContext(r.Context())
			if !ok {
				Fail(w, http.StatusUnauthorized, CodeUnauthorized, "Authentication required", nil)
				return
			}
			provided := r.Header.Get("X-CSRF-Token")
			if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(sess.CSRFToken)) != 1 {
				Fail(w, http.StatusForbidden, CodeCSRFInvalid, "Missing or invalid CSRF token", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
