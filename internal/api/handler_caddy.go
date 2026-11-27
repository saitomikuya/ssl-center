package api

import (
	"errors"
	"net/http"
	"os"
	"strconv"

	"ssl-center/internal/caddy"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// CaddyHandler serves /api/v1/hosts/{id}/caddy/* endpoints.
type CaddyHandler struct {
	mgr *caddy.Manager
}

// NewCaddyHandler constructs a CaddyHandler.
func NewCaddyHandler(mgr *caddy.Manager) *CaddyHandler {
	return &CaddyHandler{mgr: mgr}
}

// GetCaddyfile handles GET /api/v1/hosts/{id}/caddy/caddyfile.
func (h *CaddyHandler) GetCaddyfile(w http.ResponseWriter, r *http.Request) {
	hostID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	res, err := h.mgr.GetCaddyfile(r.Context(), hostID)
	if err != nil {
		mapCaddyError(w, err)
		return
	}
	OK(w, res)
}

// SaveCaddyfile handles PUT /api/v1/hosts/{id}/caddy/caddyfile.
func (h *CaddyHandler) SaveCaddyfile(w http.ResponseWriter, r *http.Request) {
	hostID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	var req model.SaveCaddyfileRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	res, err := h.mgr.SaveCaddyfile(r.Context(), hostID, req, ClientIPFromContext(r.Context()))
	if err != nil {
		mapCaddyError(w, err)
		return
	}
	OK(w, res)
}

// Format handles POST /api/v1/hosts/{id}/caddy/format.
func (h *CaddyHandler) Format(w http.ResponseWriter, r *http.Request) {
	hostID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	var req model.CaddyFormatRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	formatted, err := h.mgr.Format(r.Context(), hostID, req.Content)
	if err != nil {
		mapCaddyError(w, err)
		return
	}
	OK(w, model.CaddyFormatResponse{Content: formatted})
}

// Validate handles POST /api/v1/hosts/{id}/caddy/validate.
func (h *CaddyHandler) Validate(w http.ResponseWriter, r *http.Request) {
	hostID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	var req model.CaddyValidateRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	res, err := h.mgr.Validate(r.Context(), hostID, req.Content)
	if err != nil {
		mapCaddyError(w, err)
		return
	}
	OK(w, res)
}

// Reload handles POST /api/v1/hosts/{id}/caddy/reload.
func (h *CaddyHandler) Reload(w http.ResponseWriter, r *http.Request) {
	hostID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}

	res, err := h.mgr.ReloadOnly(r.Context(), hostID, ClientIPFromContext(r.Context()))
	if err != nil {
		mapCaddyError(w, err)
		return
	}
	OK(w, res)
}

// Snapshots handles GET /api/v1/hosts/{id}/caddy/snapshots.
func (h *CaddyHandler) Snapshots(w http.ResponseWriter, r *http.Request) {
	hostID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, convErr := strconv.Atoi(raw); convErr == nil && n > 0 {
			if n > 200 {
				n = 200
			}
			limit = n
		}
	}

	list, err := h.mgr.Snapshots(r.Context(), hostID, limit)
	if err != nil {
		mapCaddyError(w, err)
		return
	}
	OK(w, list)
}

// SnapshotDiff handles GET /api/v1/hosts/{id}/caddy/snapshots/{snapId}/diff.
func (h *CaddyHandler) SnapshotDiff(w http.ResponseWriter, r *http.Request) {
	hostID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	snapID, err := URLParamInt64(r, "snapId")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}

	diff, err := h.mgr.SnapshotDiff(r.Context(), hostID, snapID)
	if err != nil {
		mapCaddyError(w, err)
		return
	}
	OK(w, diff)
}

// Rollback handles POST /api/v1/hosts/{id}/caddy/snapshots/{snapId}/rollback.
func (h *CaddyHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	hostID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	snapID, err := URLParamInt64(r, "snapId")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}

	res, err := h.mgr.Rollback(r.Context(), hostID, snapID, ClientIPFromContext(r.Context()))
	if err != nil {
		mapCaddyError(w, err)
		return
	}
	OK(w, res)
}

// ContainerInfo handles GET /api/v1/hosts/{id}/caddy/container.
func (h *CaddyHandler) ContainerInfo(w http.ResponseWriter, r *http.Request) {
	hostID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	tail := 100
	if raw := r.URL.Query().Get("tail"); raw != "" {
		if n, convErr := strconv.Atoi(raw); convErr == nil && n > 0 {
			tail = n
		}
	}

	info, err := h.mgr.ContainerInfo(r.Context(), hostID, tail)
	if err != nil {
		mapCaddyError(w, err)
		return
	}
	OK(w, info)
}

func mapCaddyError(w http.ResponseWriter, err error) {
	var ce *caddy.ConflictError
	var ve *caddy.ValidateError
	switch {
	case errors.As(err, &ce):
		Fail(w, http.StatusConflict, CodeCaddyfileConflict, ce.Error(), ce.Details)
	case errors.As(err, &ve):
		Fail(w, http.StatusUnprocessableEntity, CodeCaddyValidateFailed, ve.Error(), ve.Details)
	case errors.Is(err, db.ErrNotFound):
		Fail(w, http.StatusNotFound, CodeNotFound, "Resource not found", nil)
	case errors.Is(err, os.ErrNotExist):
		Fail(w, http.StatusNotFound, CodeNotFound, err.Error(), nil)
	case errors.Is(err, caddy.ErrCaddyDisabled), errors.Is(err, caddy.ErrSnapshotHostMismatch):
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
	default:
		Fail(w, http.StatusInternalServerError, CodeInternalError, err.Error(), nil)
	}
}
