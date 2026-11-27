package api

import (
	"errors"
	"fmt"
	"math"
	"net/http"

	"ssl-center/internal/auth"
	"ssl-center/internal/config"
	"ssl-center/internal/model"
)

// AuthHandler serves /api/v1/health and /api/v1/auth/* endpoints.
type AuthHandler struct {
	authSvc *auth.Service
	cfg     *config.Config
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(authSvc *auth.Service, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authSvc: authSvc,
		cfg:     cfg,
	}
}

// Health handles GET /api/v1/health (unauthenticated).
func (h *AuthHandler) Health(w http.ResponseWriter, r *http.Request) {
	OK(w, map[string]any{
		"status": "ok",
	})
}

// Login handles POST /api/v1/auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}
	if req.Password == "" {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Password is required", nil)
		return
	}

	ip := auth.ExtractClientIP(r, h.cfg.TrustProxy)
	rawToken, sess, mustChange, retryAfter, err := h.authSvc.Login(r.Context(), ip, r.UserAgent(), req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			secs := int(math.Ceil(retryAfter.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
			Fail(w, http.StatusTooManyRequests, CodeRateLimited, "Too many failed login attempts; please try again later", map[string]any{
				"retry_after_seconds": secs,
			})
		case errors.Is(err, auth.ErrInvalidCredentials):
			Fail(w, http.StatusUnauthorized, CodeUnauthorized, "Invalid administrator password", nil)
		default:
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Authentication failed", nil)
		}
		return
	}

	auth.SetSessionCookie(w, r, h.cfg.CookieSecure, rawToken, auth.SessionTTL)
	OK(w, model.AuthMeResponse{
		Authenticated:      true,
		MustChangePassword: mustChange,
		CSRFToken:          sess.CSRFToken,
		IP:                 ip,
	})
}

// Logout handles POST /api/v1/auth/logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(auth.SessionCookieName); err == nil && cookie.Value != "" {
		_ = h.authSvc.Logout(r.Context(), cookie.Value)
	}
	auth.ClearSessionCookie(w, r, h.cfg.CookieSecure)
	OK(w, map[string]any{
		"logged_out": true,
	})
}

// Me handles GET /api/v1/auth/me.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		Fail(w, http.StatusUnauthorized, CodeUnauthorized, "Authentication required", nil)
		return
	}
	OK(w, model.AuthMeResponse{
		Authenticated:      true,
		MustChangePassword: MustChangePasswordFromContext(r.Context()),
		CSRFToken:          sess.CSRFToken,
		IP:                 ClientIPFromContext(r.Context()),
	})
}

// ChangePassword handles POST /api/v1/auth/change-password.
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		Fail(w, http.StatusUnauthorized, CodeUnauthorized, "Authentication required", nil)
		return
	}

	var req model.ChangePasswordRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "current_password and new_password are required", nil)
		return
	}

	err := h.authSvc.ChangePassword(r.Context(), sess.ID, req.CurrentPassword, req.NewPassword, ClientIPFromContext(r.Context()))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			Fail(w, http.StatusUnauthorized, CodeUnauthorized, "Current password is incorrect", nil)
		case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrSamePassword):
			Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		default:
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to update password", nil)
		}
		return
	}

	OK(w, map[string]any{
		"password_changed": true,
	})
}
