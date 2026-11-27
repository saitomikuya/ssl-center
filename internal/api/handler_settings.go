package api

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// SettingsHandler serves /api/v1/settings and /api/v1/settings/prune-logs.
type SettingsHandler struct {
	db           *db.DB
	reloader     model.ScheduleReloader
	pruneTrigger model.LogPruneTrigger
}

// NewSettingsHandler constructs a SettingsHandler.
func NewSettingsHandler(database *db.DB, reloader model.ScheduleReloader, pruneTrigger model.LogPruneTrigger) *SettingsHandler {
	return &SettingsHandler{
		db:           database,
		reloader:     reloader,
		pruneTrigger: pruneTrigger,
	}
}

// Get handles GET /api/v1/settings.
func (h *SettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	dto, err := h.db.GetSettingsDTO(r.Context())
	if err != nil {
		MapDBError(w, err)
		return
	}
	OK(w, dto)
}

// Update handles PUT /api/v1/settings.
func (h *SettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req model.UpdateSettingsRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	if req.InspectTime != nil {
		t := strings.TrimSpace(*req.InspectTime)
		if len(t) != 5 {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "inspect_time must be in HH:MM 24-hour format", nil)
			return
		}
		if _, err := time.Parse("15:04", t); err != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "inspect_time must be in HH:MM 24-hour format", nil)
			return
		}
		req.InspectTime = &t
	}
	if req.RenewBeforeDays != nil && (*req.RenewBeforeDays < 1 || *req.RenewBeforeDays > 365) {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "renew_before_days must be between 1 and 365", nil)
		return
	}
	if req.ExpiringWarnDays != nil && (*req.ExpiringWarnDays < 1 || *req.ExpiringWarnDays > 365) {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "expiring_warn_days must be between 1 and 365", nil)
		return
	}
	if req.LogRetentionDays != nil && (*req.LogRetentionDays < 1 || *req.LogRetentionDays > 3650) {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "log_retention_days must be between 1 and 3650", nil)
		return
	}
	if req.LogMaxRows != nil && (*req.LogMaxRows < 100 || *req.LogMaxRows > 1000000) {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "log_max_rows must be between 100 and 1000000", nil)
		return
	}

	oldSettings, err := h.db.GetSettingsDTO(r.Context())
	if err != nil {
		MapDBError(w, err)
		return
	}

	if err := h.db.UpdateSettings(r.Context(), req); err != nil {
		MapDBError(w, err)
		return
	}

	updated, err := h.db.GetSettingsDTO(r.Context())
	if err != nil {
		MapDBError(w, err)
		return
	}

	if h.reloader != nil && req.InspectTime != nil && *req.InspectTime != oldSettings.InspectTime {
		_ = h.reloader.ReloadSchedule(r.Context())
	}

	_, _ = h.db.CreateAuditEvent(r.Context(), &model.AuditEvent{
		EventType:  "settings.updated",
		Level:      model.AuditLevelInfo,
		TargetType: "settings",
		TargetName: "global",
		Message:    "Updated system settings",
		ActorIP:    ClientIPFromContext(r.Context()),
	})

	OK(w, updated)
}

type pruneLogsRequest struct {
	RetentionDays *int `json:"retention_days,omitempty"`
	MaxRows       *int `json:"max_rows,omitempty"`
}

// PruneLogs handles POST /api/v1/settings/prune-logs.
func (h *SettingsHandler) PruneLogs(w http.ResponseWriter, r *http.Request) {
	var req pruneLogsRequest
	if r.Body != nil {
		if err := BindJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
			return
		}
	}

	if req.RetentionDays != nil && *req.RetentionDays < 1 {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "retention_days must be >= 1", nil)
		return
	}
	if req.MaxRows != nil && *req.MaxRows < 1 {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "max_rows must be >= 1", nil)
		return
	}

	var (
		res *model.PruneResult
		err error
	)
	if req.RetentionDays == nil && req.MaxRows == nil && h.pruneTrigger != nil {
		res, err = h.pruneTrigger.PruneNow(r.Context())
	} else {
		settings, getErr := h.db.GetSettingsDTO(r.Context())
		if getErr != nil {
			MapDBError(w, getErr)
			return
		}
		retentionDays := settings.LogRetentionDays
		maxRows := settings.LogMaxRows
		if req.RetentionDays != nil {
			retentionDays = *req.RetentionDays
		}
		if req.MaxRows != nil {
			maxRows = *req.MaxRows
		}
		res, err = h.db.PruneLogs(r.Context(), retentionDays, maxRows)
	}
	if err != nil {
		MapDBError(w, err)
		return
	}

	_, _ = h.db.CreateAuditEvent(r.Context(), &model.AuditEvent{
		EventType:  "settings.logs_pruned",
		Level:      model.AuditLevelInfo,
		TargetType: "settings",
		TargetName: "logs",
		Message:    "Pruned historical logs",
		ActorIP:    ClientIPFromContext(r.Context()),
	})

	OK(w, res)
}
