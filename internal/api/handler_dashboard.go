package api

import (
	"net/http"

	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// DashboardHandler serves GET /api/v1/dashboard.
type DashboardHandler struct {
	db *db.DB
}

// NewDashboardHandler constructs a DashboardHandler.
func NewDashboardHandler(database *db.DB) *DashboardHandler {
	return &DashboardHandler{db: database}
}

// Get handles GET /api/v1/dashboard.
func (h *DashboardHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	certStats, hostStats, deployStats, err := h.db.GetDashboardCounts(ctx)
	if err != nil {
		MapDBError(w, err)
		return
	}

	recentEvents, err := h.db.ListRecentAuditEvents(ctx, 30)
	if err != nil {
		MapDBError(w, err)
		return
	}
	if recentEvents == nil {
		recentEvents = make([]model.AuditEvent, 0)
	}

	cas, err := h.db.ListCAAccounts(ctx)
	if err != nil {
		MapDBError(w, err)
		return
	}
	dnss, err := h.db.ListDNSCredentials(ctx)
	if err != nil {
		MapDBError(w, err)
		return
	}

	checklist := []model.ChecklistItem{
		{
			Key:   "ca_account",
			Title: "配置 CA 签发账户",
			Done:  len(cas) > 0,
			Href:  "/credentials",
		},
		{
			Key:   "dns_credential",
			Title: "配置 DNS 解析凭据",
			Done:  len(dnss) > 0,
			Href:  "/credentials",
		},
		{
			Key:   "host",
			Title: "接入主机或测试本机 Caddy",
			Done:  hostStats.Total > 1 || hostStats.Reachable > 0,
			Href:  "/hosts",
		},
		{
			Key:   "certificate",
			Title: "创建并签发首张证书",
			Done:  certStats.Valid > 0 || certStats.Expiring > 0,
			Href:  "/certificates",
		},
		{
			Key:   "deployment",
			Title: "绑定自动化部署目标",
			Done:  deployStats.Total > 0,
			Href:  "/hosts",
		},
	}

	OK(w, model.DashboardResponse{
		CertStats:       certStats,
		HostStats:       hostStats,
		DeploymentStats: deployStats,
		RecentEvents:    recentEvents,
		Checklist:       checklist,
	})
}
