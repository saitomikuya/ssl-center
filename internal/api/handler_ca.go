package api

import (
	"errors"
	"net/http"

	"ssl-center/internal/acme"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// CAHandler serves /api/v1/ca-accounts endpoints.
type CAHandler struct {
	caSvc *acme.CAService
}

// NewCAHandler constructs a CAHandler.
func NewCAHandler(caSvc *acme.CAService) *CAHandler {
	return &CAHandler{caSvc: caSvc}
}

// List handles GET /api/v1/ca-accounts.
func (h *CAHandler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.caSvc.ListAccounts(r.Context())
	if err != nil {
		MapDBError(w, err)
		return
	}
	if items == nil {
		items = make([]model.CAAccountDTO, 0)
	}
	OK(w, items)
}

// Create handles POST /api/v1/ca-accounts.
func (h *CAHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.CreateCARequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	dto, err := h.caSvc.CreateAccount(r.Context(), &req, ClientIPFromContext(r.Context()))
	if err != nil {
		mapCAError(w, err)
		return
	}
	Created(w, dto)
}

// Update handles PUT /api/v1/ca-accounts/{id}.
func (h *CAHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	var req model.UpdateCARequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	dto, err := h.caSvc.UpdateAccount(r.Context(), id, req, ClientIPFromContext(r.Context()))
	if err != nil {
		mapCAError(w, err)
		return
	}
	OK(w, dto)
}

// Delete handles DELETE /api/v1/ca-accounts/{id}.
func (h *CAHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	if err := h.caSvc.DeleteAccount(r.Context(), id, ClientIPFromContext(r.Context())); err != nil {
		mapCAError(w, err)
		return
	}
	OK(w, map[string]any{"deleted": true})
}

// SetDefault handles POST /api/v1/ca-accounts/{id}/default.
func (h *CAHandler) SetDefault(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	dto, err := h.caSvc.SetDefault(r.Context(), id, ClientIPFromContext(r.Context()))
	if err != nil {
		mapCAError(w, err)
		return
	}
	OK(w, dto)
}

// ExportKey handles POST /api/v1/ca-accounts/{id}/export-key.
func (h *CAHandler) ExportKey(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	resp, err := h.caSvc.ExportKey(r.Context(), id, ClientIPFromContext(r.Context()))
	if err != nil {
		mapCAError(w, err)
		return
	}
	OK(w, resp)
}

func mapCAError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, acme.ErrInvalidCAInput),
		errors.Is(err, acme.ErrCARegistration),
		errors.Is(err, acme.ErrCAKeyValidation):
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
	case errors.Is(err, db.ErrNotFound),
		errors.Is(err, db.ErrConflict),
		errors.Is(err, db.ErrResourceInUse),
		errors.Is(err, db.ErrInvalidReference):
		MapDBError(w, err)
	default:
		Fail(w, http.StatusInternalServerError, CodeInternalError, err.Error(), nil)
	}
}
