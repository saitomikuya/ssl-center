package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
	"ssl-center/internal/notify"
)

// WebhookHandler serves /api/v1/webhooks* endpoints.
type WebhookHandler struct {
	db       *db.DB
	cipher   *crypto.Cipher
	redactor *crypto.SecretRedactor
	notifier model.Notifier
}

// NewWebhookHandler constructs a WebhookHandler.
func NewWebhookHandler(database *db.DB, cipher *crypto.Cipher, redactor *crypto.SecretRedactor, notifier model.Notifier) *WebhookHandler {
	return &WebhookHandler{
		db:       database,
		cipher:   cipher,
		redactor: redactor,
		notifier: notifier,
	}
}

// List handles GET /api/v1/webhooks.
func (h *WebhookHandler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.db.ListWebhooks(r.Context())
	if err != nil {
		MapDBError(w, err)
		return
	}
	out := make([]model.WebhookDTO, 0, len(items))
	for i := range items {
		out = append(out, h.toDTO(&items[i]))
	}
	OK(w, out)
}

// Create handles POST /api/v1/webhooks.
func (h *WebhookHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.CreateWebhookRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.URL = strings.TrimSpace(req.URL)
	if req.Name == "" {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Webhook name is required", nil)
		return
	}
	if !isValidWebhookURL(req.URL) {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Valid http:// or https:// webhook URL is required", nil)
		return
	}

	events := req.Events
	if len(events) == 0 {
		events = append([]string(nil), model.DefaultWebhookEvents...)
	} else if !validateWebhookEvents(events) {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid webhook event name", nil)
		return
	}
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encode events", nil)
		return
	}

	var headersEnc string
	var newSecrets []string
	if len(req.Headers) > 0 {
		hdrBytes, err := json.Marshal(req.Headers)
		if err != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid headers map", nil)
			return
		}
		headersEnc, err = h.cipher.Encrypt(string(hdrBytes), notify.AADWebhookHeaders)
		if err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt webhook headers", nil)
			return
		}
		for _, v := range req.Headers {
			if v != "" {
				newSecrets = append(newSecrets, v)
			}
		}
	}

	var secretEnc string
	if req.Secret != "" {
		secretEnc, err = h.cipher.Encrypt(req.Secret, notify.AADWebhookSecret)
		if err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt webhook secret", nil)
			return
		}
		newSecrets = append(newSecrets, req.Secret)
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	wh := &model.Webhook{
		Name:       req.Name,
		URL:        req.URL,
		HeadersEnc: headersEnc,
		SecretEnc:  secretEnc,
		EventsJSON: string(eventsJSON),
		Enabled:    enabled,
	}
	if _, err := h.db.CreateWebhook(r.Context(), wh); err != nil {
		MapDBError(w, err)
		return
	}

	if h.redactor != nil && len(newSecrets) > 0 {
		h.redactor.Add(newSecrets...)
	}

	_, _ = h.db.CreateAuditEvent(r.Context(), &model.AuditEvent{
		EventType:  "webhook.created",
		Level:      model.AuditLevelInfo,
		TargetType: "webhook",
		TargetID:   &wh.ID,
		TargetName: wh.Name,
		Message:    "Created webhook " + wh.Name,
		ActorIP:    ClientIPFromContext(r.Context()),
	})

	Created(w, h.toDTO(wh))
}

// Update handles PUT /api/v1/webhooks/{id}.
func (h *WebhookHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}

	existing, err := h.db.GetWebhook(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}

	var req model.UpdateWebhookRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Webhook name must not be empty", nil)
			return
		}
		existing.Name = name
	}
	if req.URL != nil {
		u := strings.TrimSpace(*req.URL)
		if !isValidWebhookURL(u) {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Valid http:// or https:// webhook URL is required", nil)
			return
		}
		existing.URL = u
	}
	if req.Events != nil {
		if len(req.Events) == 0 || !validateWebhookEvents(req.Events) {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Events must be a non-empty list of valid webhook events", nil)
			return
		}
		b, err := json.Marshal(req.Events)
		if err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encode events", nil)
			return
		}
		existing.EventsJSON = string(b)
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	var oldSecrets []string
	var newSecrets []string

	// Partial secret update semantics: preserve headers when omitted or empty.
	if len(req.Headers) > 0 {
		hasNonEmpty := false
		for _, v := range req.Headers {
			if v != "" {
				hasNonEmpty = true
				break
			}
		}
		if hasNonEmpty {
			oldHdrs := h.decryptHeadersMap(existing.HeadersEnc)
			merged := make(map[string]string, len(req.Headers))
			for k, v := range req.Headers {
				if v != "" {
					merged[k] = v
				} else if oldVal, ok := oldHdrs[k]; ok && oldVal != "" {
					merged[k] = oldVal
				}
			}
			for _, v := range oldHdrs {
				if v != "" {
					oldSecrets = append(oldSecrets, v)
				}
			}
			for _, v := range merged {
				if v != "" {
					newSecrets = append(newSecrets, v)
				}
			}
			hdrBytes, err := json.Marshal(merged)
			if err != nil {
				Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid headers map", nil)
				return
			}
			enc, err := h.cipher.Encrypt(string(hdrBytes), notify.AADWebhookHeaders)
			if err != nil {
				Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt webhook headers", nil)
				return
			}
			existing.HeadersEnc = enc
		}
	}

	if req.Secret != nil && *req.Secret != "" {
		if existing.SecretEnc != "" {
			if oldSec, decErr := h.cipher.Decrypt(existing.SecretEnc, notify.AADWebhookSecret); decErr == nil && oldSec != "" {
				oldSecrets = append(oldSecrets, oldSec)
			}
		}
		enc, err := h.cipher.Encrypt(*req.Secret, notify.AADWebhookSecret)
		if err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt webhook secret", nil)
			return
		}
		existing.SecretEnc = enc
		newSecrets = append(newSecrets, *req.Secret)
	}

	if err := h.db.UpdateWebhook(r.Context(), existing); err != nil {
		MapDBError(w, err)
		return
	}

	if h.redactor != nil {
		if len(oldSecrets) > 0 {
			h.redactor.Remove(oldSecrets...)
		}
		if len(newSecrets) > 0 {
			h.redactor.Add(newSecrets...)
		}
	}

	_, _ = h.db.CreateAuditEvent(r.Context(), &model.AuditEvent{
		EventType:  "webhook.updated",
		Level:      model.AuditLevelInfo,
		TargetType: "webhook",
		TargetID:   &existing.ID,
		TargetName: existing.Name,
		Message:    "Updated webhook " + existing.Name,
		ActorIP:    ClientIPFromContext(r.Context()),
	})

	OK(w, h.toDTO(existing))
}

// Delete handles DELETE /api/v1/webhooks/{id}.
func (h *WebhookHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}

	existing, err := h.db.GetWebhook(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}

	var oldSecrets []string
	for _, v := range h.decryptHeadersMap(existing.HeadersEnc) {
		if v != "" {
			oldSecrets = append(oldSecrets, v)
		}
	}
	if existing.SecretEnc != "" && h.cipher != nil {
		if sec, decErr := h.cipher.Decrypt(existing.SecretEnc, notify.AADWebhookSecret); decErr == nil && sec != "" {
			oldSecrets = append(oldSecrets, sec)
		}
	}

	if err := h.db.DeleteWebhook(r.Context(), id); err != nil {
		MapDBError(w, err)
		return
	}

	if h.redactor != nil && len(oldSecrets) > 0 {
		h.redactor.Remove(oldSecrets...)
	}

	_, _ = h.db.CreateAuditEvent(r.Context(), &model.AuditEvent{
		EventType:  "webhook.deleted",
		Level:      model.AuditLevelInfo,
		TargetType: "webhook",
		TargetID:   &existing.ID,
		TargetName: existing.Name,
		Message:    "Deleted webhook " + existing.Name,
		ActorIP:    ClientIPFromContext(r.Context()),
	})

	OK(w, map[string]any{"deleted": true})
}

// Test handles POST /api/v1/webhooks/{id}/test.
func (h *WebhookHandler) Test(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}

	if _, err := h.db.GetWebhook(r.Context(), id); err != nil {
		MapDBError(w, err)
		return
	}
	if h.notifier == nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Notifier service is not configured", nil)
		return
	}

	var statusCode int
	var sendErr error
	if wn, ok := h.notifier.(*notify.WebhookNotifier); ok {
		statusCode, sendErr = wn.SendTestWithStatus(r.Context(), id)
	} else {
		sendErr = h.notifier.SendTest(r.Context(), id)
		if updated, getErr := h.db.GetWebhook(r.Context(), id); getErr == nil && updated.LastStatusCode != nil {
			statusCode = *updated.LastStatusCode
		}
	}

	if sendErr != nil {
		OK(w, map[string]any{
			"ok":          false,
			"status_code": statusCode,
			"error":       sendErr.Error(),
		})
		return
	}
	OK(w, map[string]any{
		"ok":          true,
		"status_code": statusCode,
	})
}

func (h *WebhookHandler) toDTO(w *model.Webhook) model.WebhookDTO {
	headerKeys := make([]string, 0)
	if hdrs := h.decryptHeadersMap(w.HeadersEnc); len(hdrs) > 0 {
		for k := range hdrs {
			headerKeys = append(headerKeys, k)
		}
		sort.Strings(headerKeys)
	}

	events := make([]string, 0)
	if w.EventsJSON != "" {
		_ = json.Unmarshal([]byte(w.EventsJSON), &events)
		if events == nil {
			events = make([]string, 0)
		}
	}

	return model.WebhookDTO{
		ID:              w.ID,
		Name:            w.Name,
		URL:             w.URL,
		HeaderKeys:      headerKeys,
		HasSecret:       w.SecretEnc != "",
		Events:          events,
		Enabled:         w.Enabled,
		LastStatusCode:  w.LastStatusCode,
		LastError:       w.LastError,
		LastTriggeredAt: w.LastTriggeredAt,
		CreatedAt:       w.CreatedAt,
		UpdatedAt:       w.UpdatedAt,
	}
}

func (h *WebhookHandler) decryptHeadersMap(enc string) map[string]string {
	if enc == "" || h.cipher == nil {
		return nil
	}
	plain, err := h.cipher.Decrypt(enc, notify.AADWebhookHeaders)
	if err != nil || plain == "" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(plain), &m); err != nil {
		return nil
	}
	return m
}

func isValidWebhookURL(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}

func validateWebhookEvents(events []string) bool {
	for _, ev := range events {
		if !notify.IsValidWebhookEvent(ev) {
			return false
		}
	}
	return true
}

// Compile-time check for errors import if needed.
var _ = errors.Is
