package api

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
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

var gzipWriterPool = sync.Pool{
	New: func() any {
		return gzip.NewWriter(io.Discard)
	},
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
	passthrough bool
}

func (g *gzipResponseWriter) shouldBypass(status int) bool {
	if status < 200 || status == http.StatusNoContent || status == http.StatusNotModified || status == http.StatusPartialContent {
		return true
	}
	h := g.ResponseWriter.Header()
	if h.Get("Content-Encoding") != "" || h.Get("Content-Range") != "" {
		return true
	}
	ct := strings.ToLower(h.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "text/event-stream"),
		strings.Contains(ct, "application/zip"),
		strings.Contains(ct, "application/gzip"),
		strings.Contains(ct, "application/x-gzip"),
		strings.HasPrefix(ct, "image/") && !strings.Contains(ct, "image/svg+xml"):
		return true
	}
	return false
}

func (g *gzipResponseWriter) initCompression(status int) {
	if g.wroteHeader {
		return
	}
	g.wroteHeader = true
	if g.shouldBypass(status) {
		g.passthrough = true
		return
	}
	h := g.ResponseWriter.Header()
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	h.Add("Vary", "Accept-Encoding")
	gz := gzipWriterPool.Get().(*gzip.Writer)
	gz.Reset(g.ResponseWriter)
	g.gz = gz
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.wroteHeader {
		return
	}
	g.initCompression(code)
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	if !g.wroteHeader {
		if g.ResponseWriter.Header().Get("Content-Type") == "" {
			g.ResponseWriter.Header().Set("Content-Type", http.DetectContentType(p))
		}
		g.WriteHeader(http.StatusOK)
	}
	if g.passthrough || g.gz == nil {
		return g.ResponseWriter.Write(p)
	}
	return g.gz.Write(p)
}

func (g *gzipResponseWriter) Flush() {
	if g.gz != nil {
		_ = g.gz.Flush()
	}
	if flusher, ok := g.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (g *gzipResponseWriter) Unwrap() http.ResponseWriter {
	return g.ResponseWriter
}

func (g *gzipResponseWriter) close() {
	if g.gz != nil {
		_ = g.gz.Close()
		g.gz.Reset(io.Discard)
		gzipWriterPool.Put(g.gz)
		g.gz = nil
	}
}

// GzipMiddleware compresses JSON and text/JS/CSS responses when the client accepts gzip,
// while bypassing SSE streams, binary downloads, and already-encoded payloads.
func GzipMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead ||
				!strings.Contains(strings.ToLower(r.Header.Get("Accept-Encoding")), "gzip") ||
				strings.HasSuffix(r.URL.Path, "/stream") ||
				strings.HasSuffix(r.URL.Path, "/bundle.zip") ||
				r.URL.Path == "/api/v1/backup/export" {
				next.ServeHTTP(w, r)
				return
			}
			grw := &gzipResponseWriter{ResponseWriter: w}
			defer grw.close()
			next.ServeHTTP(grw, r)
		})
	}
}
