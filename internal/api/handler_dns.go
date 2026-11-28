package api

import (
	"errors"
	"net/http"

	"ssl-center/internal/acme"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// DNSHandler serves /api/v1/dns-credentials endpoints.
type DNSHandler struct {
	dnsSvc *acme.DNSService
}

// NewDNSHandler constructs a DNSHandler.
func NewDNSHandler(dnsSvc *acme.DNSService) *DNSHandler {
	return &DNSHandler{dnsSvc: dnsSvc}
}

// List handles GET /api/v1/dns-credentials.
func (h *DNSHandler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.dnsSvc.ListCredentials(r.Context())
	if err != nil {
		MapDBError(w, err)
		return
	}
	if items == nil {
		items = make([]model.DNSCredentialDTO, 0)
	}
	OK(w, items)
}

// Create handles POST /api/v1/dns-credentials.
func (h *DNSHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.CreateDNSRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	dto, err := h.dnsSvc.CreateCredential(r.Context(), req, ClientIPFromContext(r.Context()))
	if err != nil {
		mapDNSError(w, err)
		return
	}
	Created(w, dto)
}

// Update handles PUT /api/v1/dns-credentials/{id}.
func (h *DNSHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	var req model.UpdateDNSRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	dto, err := h.dnsSvc.UpdateCredential(r.Context(), id, req, ClientIPFromContext(r.Context()))
	if err != nil {
		mapDNSError(w, err)
		return
	}
	OK(w, dto)
}

// Delete handles DELETE /api/v1/dns-credentials/{id}.
func (h *DNSHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	if err := h.dnsSvc.DeleteCredential(r.Context(), id, ClientIPFromContext(r.Context())); err != nil {
		mapDNSError(w, err)
		return
	}
	OK(w, map[string]any{"deleted": true})
}

// Test handles POST /api/v1/dns-credentials/{id}/test.
func (h *DNSHandler) Test(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	resp, err := h.dnsSvc.TestCredential(r.Context(), id)
	if err != nil {
		mapDNSError(w, err)
		return
	}
	if resp.Zones == nil {
		resp.Zones = make([]model.DNSZone, 0)
	}
	OK(w, resp)
}

// TestAdhoc handles POST /api/v1/dns-credentials/test for pre-save connectivity testing.
func (h *DNSHandler) TestAdhoc(w http.ResponseWriter, r *http.Request) {
	var req model.TestDNSAdhocRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}
	resp, err := h.dnsSvc.TestAdhoc(r.Context(), req)
	if err != nil {
		mapDNSError(w, err)
		return
	}
	if resp.Zones == nil {
		resp.Zones = make([]model.DNSZone, 0)
	}
	OK(w, resp)
}

// Zones handles GET /api/v1/dns-credentials/{id}/zones?domain=*.example.com.
func (h *DNSHandler) Zones(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	domain := r.URL.Query().Get("domain")
	resp, err := h.dnsSvc.ListZonesForDomain(r.Context(), id, domain)
	if err != nil {
		mapDNSError(w, err)
		return
	}
	if resp.Zones == nil {
		resp.Zones = make([]model.DNSZone, 0)
	}
	OK(w, resp)
}

func mapDNSError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, acme.ErrInvalidDNSInput):
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
