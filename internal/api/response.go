package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"ssl-center/internal/db"
)

const maxJSONBodyBytes = 2 << 20 // 2 MiB

// Standardized API error codes frozen across Phase 1-3.
const (
	CodeUnauthorized           = "UNAUTHORIZED"
	CodePasswordChangeRequired = "PASSWORD_CHANGE_REQUIRED"
	CodeCSRFInvalid            = "CSRF_INVALID"
	CodeRateLimited            = "RATE_LIMITED"
	CodeMaintenanceInProgress  = "MAINTENANCE_IN_PROGRESS"
	CodeBadRequest             = "BAD_REQUEST"
	CodeNotFound               = "NOT_FOUND"
	CodeConflict               = "CONFLICT"
	CodeResourceInUse          = "RESOURCE_IN_USE"
	CodeLocalHostProtected     = "LOCAL_HOST_PROTECTED"
	CodeCaddyfileConflict      = "CADDYFILE_CONFLICT"
	CodeCaddyValidateFailed    = "CADDY_VALIDATE_FAILED"
	CodeInternalError          = "INTERNAL_ERROR"
)

// Envelope is the unified JSON response wrapper for all /api/v1 endpoints.
type Envelope struct {
	OK    bool       `json:"ok"`
	Data  any        `json:"data,omitempty"`
	Error *ErrorBody `json:"error,omitempty"`
}

// ErrorBody carries structured error details inside Envelope.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// OK writes a 200 JSON success envelope.
func OK(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: data})
}

// Created writes a 201 JSON success envelope.
func Created(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusCreated, Envelope{OK: true, Data: data})
}

// Accepted writes a 202 JSON success envelope.
func Accepted(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusAccepted, Envelope{OK: true, Data: data})
}

// Fail writes an error envelope with the given HTTP status and error code.
func Fail(w http.ResponseWriter, status int, code, message string, details any) {
	WriteJSON(w, status, Envelope{
		OK: false,
		Error: &ErrorBody{
			Code:    code,
			Message: message,
			Details: details,
		},
	})
}

// WriteJSON serializes payload as JSON with Content-Type application/json.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// BindJSON decodes a JSON request body into dst with size protection.
func BindJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty request body")
	}
	limited := io.LimitReader(r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(limited)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

// URLParamInt64 parses a numeric chi URL parameter.
func URLParamInt64(r *http.Request, key string) (int64, error) {
	raw := chi.URLParam(r, key)
	if raw == "" {
		return 0, errors.New("missing URL parameter " + key)
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, errors.New("invalid numeric parameter " + key)
	}
	return v, nil
}

// MapDBError translates sentinel repository errors into standard HTTP responses.
func MapDBError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrNotFound):
		Fail(w, http.StatusNotFound, CodeNotFound, "Resource not found", nil)
	case errors.Is(err, db.ErrInvalidReference):
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Referenced parent resource does not exist", nil)
	case errors.Is(err, db.ErrLocalHostProtected):
		Fail(w, http.StatusForbidden, CodeLocalHostProtected, "Built-in Local host cannot be deleted", nil)
	case errors.Is(err, db.ErrResourceInUse):
		Fail(w, http.StatusConflict, CodeResourceInUse, "Resource is referenced by existing records", nil)
	case errors.Is(err, db.ErrConflict):
		Fail(w, http.StatusConflict, CodeConflict, "Resource already exists or conflicts", nil)
	default:
		Fail(w, http.StatusInternalServerError, CodeInternalError, err.Error(), nil)
	}
}
