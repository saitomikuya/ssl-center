package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"ssl-center/internal/auth"
	"ssl-center/internal/config"
	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

func setupTestAuthRouter(t *testing.T, initForce bool) (http.Handler, *MaintenanceCoordinatorImpl) {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	cfg := &config.Config{
		DataDir:         dir,
		InitPassword:    "initial-admin-pass",
		InitForceChange: initForce,
		CookieSecure:    config.CookieSecureAuto,
		TrustProxy:      false,
	}
	limiter := auth.NewRateLimiter(3, 5*time.Minute, 5*time.Minute)
	authSvc := auth.NewService(d, cfg, limiter)
	if _, err := authSvc.BootstrapAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}

	maint := NewMaintenanceCoordinator()
	redactor := crypto.NewSecretRedactor()
	ah := NewAuthHandler(authSvc, cfg)

	r := chi.NewRouter()
	r.Use(Recoverer(redactor, nil))
	r.Use(maint.Middleware())

	r.Get("/api/v1/health", ah.Health)
	r.Post("/api/v1/auth/login", ah.Login)

	r.Group(func(pr chi.Router) {
		pr.Use(RequireAuth(authSvc, cfg.TrustProxy))
		pr.Use(RequireCSRF())
		pr.Use(RequirePasswordChanged())

		pr.Get("/api/v1/auth/me", ah.Me)
		pr.Post("/api/v1/auth/logout", ah.Logout)
		pr.Post("/api/v1/auth/change-password", ah.ChangePassword)

		pr.Get("/api/v1/protected", func(w http.ResponseWriter, r *http.Request) {
			OK(w, map[string]string{"access": "granted"})
		})
		pr.Post("/api/v1/protected", func(w http.ResponseWriter, r *http.Request) {
			OK(w, map[string]string{"mutated": "yes"})
		})
	})

	return r, maint
}

func decodeEnvelope(t *testing.T, body []byte) Envelope {
	t.Helper()
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope %q: %v", string(body), err)
	}
	return env
}

func TestAuthMiddlewareFlowAndStatusCodes(t *testing.T) {
	router, maint := setupTestAuthRouter(t, true)

	// 1. Public health check
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", rec.Code)
	}

	// 2. Protected route without auth -> 401
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", rec.Code)
	}

	// 3. Rate limiting (429 RATE_LIMITED) on repeated bad logins
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"password":"wrong"}`))
		req.RemoteAddr = "198.51.100.77:5555"
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if i < 2 && rec.Code != http.StatusUnauthorized {
			t.Fatalf("bad login %d = %d, want 401", i, rec.Code)
		}
		if i == 2 {
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("3rd bad login = %d, want 429", rec.Code)
			}
			env := decodeEnvelope(t, rec.Body.Bytes())
			if env.Error == nil || env.Error.Code != CodeRateLimited {
				t.Fatalf("expected RATE_LIMITED, got %+v", env.Error)
			}
		}
	}

	// 4. Valid login from fresh IP
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"password":"initial-admin-pass"}`))
	loginReq.RemoteAddr = "198.51.100.88:5555"
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, loginReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid login status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected session cookie: %+v", sessionCookie)
	}
	var loginData model.AuthMeResponse
	env := decodeEnvelope(t, rec.Body.Bytes())
	b, _ := json.Marshal(env.Data)
	_ = json.Unmarshal(b, &loginData)
	if !loginData.MustChangePassword || loginData.CSRFToken == "" {
		t.Fatalf("unexpected login data: %+v", loginData)
	}

	// 5. Protected endpoint blocked with 403 PASSWORD_CHANGE_REQUIRED before password change
	protReq := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	protReq.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, protReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("protected before pwd change = %d, want 403", rec.Code)
	}
	env = decodeEnvelope(t, rec.Body.Bytes())
	if env.Error == nil || env.Error.Code != CodePasswordChangeRequired {
		t.Fatalf("expected PASSWORD_CHANGE_REQUIRED, got %+v", env.Error)
	}

	// 6. Mutating request without CSRF -> 403 CSRF_INVALID
	chgNoCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewBufferString(`{"current_password":"initial-admin-pass","new_password":"new-strong-password-1"}`))
	chgNoCSRF.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, chgNoCSRF)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("change-password without CSRF = %d, want 403", rec.Code)
	}
	env = decodeEnvelope(t, rec.Body.Bytes())
	if env.Error == nil || env.Error.Code != CodeCSRFInvalid {
		t.Fatalf("expected CSRF_INVALID, got %+v", env.Error)
	}

	// 7. Change password with CSRF succeeds and unlocks protected endpoint
	chgReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewBufferString(`{"current_password":"initial-admin-pass","new_password":"new-strong-password-1"}`))
	chgReq.AddCookie(sessionCookie)
	chgReq.Header.Set("X-CSRF-Token", loginData.CSRFToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, chgReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password = %d, body=%s", rec.Code, rec.Body.String())
	}

	protReq2 := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	protReq2.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, protReq2)
	if rec.Code != http.StatusOK {
		t.Fatalf("protected after pwd change = %d, want 200", rec.Code)
	}

	// 8. Maintenance lock returns 503 MAINTENANCE_IN_PROGRESS on mutating routes
	paused := false
	resumed := false
	maint.RegisterSchedulerHook(func() { paused = true }, func() { resumed = true })
	if err := maint.BeginMaintenance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !paused {
		t.Fatal("expected pause hook invoked")
	}
	mutReq := httptest.NewRequest(http.MethodPost, "/api/v1/protected", nil)
	mutReq.AddCookie(sessionCookie)
	mutReq.Header.Set("X-CSRF-Token", loginData.CSRFToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, mutReq)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("mutating during maintenance = %d, want 503", rec.Code)
	}
	env = decodeEnvelope(t, rec.Body.Bytes())
	if env.Error == nil || env.Error.Code != CodeMaintenanceInProgress {
		t.Fatalf("expected MAINTENANCE_IN_PROGRESS, got %+v", env.Error)
	}
	maint.EndMaintenance()
	if !resumed {
		t.Fatal("expected resume hook invoked")
	}

	// 9. Logout invalidates session
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	logoutReq.Header.Set("X-CSRF-Token", loginData.CSRFToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, logoutReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", rec.Code)
	}

	meAfterLogout := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meAfterLogout.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, meAfterLogout)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/auth/me after logout = %d, want 401", rec.Code)
	}
}

func TestMapDBErrorStatusCodes(t *testing.T) {
	rec := httptest.NewRecorder()
	MapDBError(rec, db.ErrInvalidReference)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ErrInvalidReference status = %d, want 400", rec.Code)
	}
	if env := decodeEnvelope(t, rec.Body.Bytes()); env.Error == nil || env.Error.Code != CodeBadRequest {
		t.Fatalf("ErrInvalidReference code = %+v, want BAD_REQUEST", env.Error)
	}

	rec2 := httptest.NewRecorder()
	MapDBError(rec2, db.ErrResourceInUse)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("ErrResourceInUse status = %d, want 409", rec2.Code)
	}
	if env := decodeEnvelope(t, rec2.Body.Bytes()); env.Error == nil || env.Error.Code != CodeResourceInUse {
		t.Fatalf("ErrResourceInUse code = %+v, want RESOURCE_IN_USE", env.Error)
	}
}
