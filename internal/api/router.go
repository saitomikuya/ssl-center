package api

import (
	"bytes"
	"io/fs"
	"log/slog"
	"net/http"
	pathpkg "path"
	"strings"

	"github.com/go-chi/chi/v5"

	"ssl-center/internal/acme"
	"ssl-center/internal/auth"
	"ssl-center/internal/backup"
	"ssl-center/internal/caddy"
	"ssl-center/internal/config"
	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
	"ssl-center/internal/web"
)

// RouterDeps holds all wired services required to construct the HTTP router.
type RouterDeps struct {
	Config       *config.Config
	DB           *db.DB
	Cipher       *crypto.Cipher
	Redactor     *crypto.SecretRedactor
	Logger       *slog.Logger
	Auth         *auth.Service
	Maint        model.MaintenanceCoordinator
	Broker       model.CertJobBroker
	Notifier     model.Notifier
	Transport    model.RemoteTransport
	DeployEngine model.DeployTrigger
	CAService    *acme.CAService
	DNSService   *acme.DNSService
	Issuer       *acme.Issuer
	Scheduler    model.ScheduleReloader
	PruneTrigger model.LogPruneTrigger
	CaddyManager *caddy.Manager
	BackupSvc    *backup.Service
	WebFS        fs.FS
}

// NewRouter constructs the full assembled HTTP router for /api/v1 and the embedded SPA.
func NewRouter(deps RouterDeps) http.Handler {
	r := chi.NewRouter()

	r.Use(Recoverer(deps.Redactor, deps.Logger))
	r.Use(RequestLogger(deps.Redactor, deps.Logger))
	r.Use(GzipMiddleware())
	if deps.Maint != nil {
		r.Use(deps.Maint.Middleware())
	}

	authHandler := NewAuthHandler(deps.Auth, deps.Config)
	dashHandler := NewDashboardHandler(deps.DB)
	caHandler := NewCAHandler(deps.CAService)
	dnsHandler := NewDNSHandler(deps.DNSService)
	certHandler := NewCertHandler(deps.DB, deps.Config, deps.Issuer)
	sseHandler := NewSSEHandler(deps.DB, deps.Broker)
	hostHandler := NewHostHandler(deps.DB, deps.Cipher, deps.Redactor, deps.Transport)
	deployHandler := NewDeployHandler(deps.DB, deps.DeployEngine)
	caddyHandler := NewCaddyHandler(deps.CaddyManager)
	webhookHandler := NewWebhookHandler(deps.DB, deps.Cipher, deps.Redactor, deps.Notifier)
	settingsHandler := NewSettingsHandler(deps.DB, deps.Scheduler, deps.PruneTrigger)
	if deps.Config != nil {
		settingsHandler.SetTimezone(deps.Config.Location().String())
	}
	backupHandler := NewBackupHandler(deps.BackupSvc, deps.Config)

	trustProxy := deps.Config != nil && deps.Config.TrustProxy

	r.Route("/api/v1", func(apiRouter chi.Router) {
		// Public endpoints
		apiRouter.Get("/health", authHandler.Health)
		apiRouter.Post("/auth/login", authHandler.Login)

		// Authenticated endpoints
		apiRouter.Group(func(pr chi.Router) {
			pr.Use(RequireAuth(deps.Auth, trustProxy))
			pr.Use(RequireCSRF())
			pr.Use(RequirePasswordChanged())

			// Auth (exempted from RequirePasswordChanged inside middleware)
			pr.Get("/auth/me", authHandler.Me)
			pr.Post("/auth/logout", authHandler.Logout)
			pr.Post("/auth/change-password", authHandler.ChangePassword)

			// Dashboard
			pr.Get("/dashboard", dashHandler.Get)

			// CA Accounts
			pr.Route("/ca-accounts", func(cr chi.Router) {
				cr.Get("/", caHandler.List)
				cr.Post("/", caHandler.Create)
				cr.Put("/{id}", caHandler.Update)
				cr.Delete("/{id}", caHandler.Delete)
				cr.Post("/{id}/default", caHandler.SetDefault)
				cr.Post("/{id}/export-key", caHandler.ExportKey)
			})

			// DNS Credentials
			pr.Route("/dns-credentials", func(dr chi.Router) {
				dr.Get("/", dnsHandler.List)
				dr.Post("/", dnsHandler.Create)
				dr.Post("/test", dnsHandler.TestAdhoc)
				dr.Put("/{id}", dnsHandler.Update)
				dr.Delete("/{id}", dnsHandler.Delete)
				dr.Post("/{id}/test", dnsHandler.Test)
				dr.Get("/{id}/zones", dnsHandler.Zones)
			})

			// Certificates & Issuance Jobs
			pr.Route("/certificates", func(cr chi.Router) {
				cr.Get("/", certHandler.List)
				cr.Post("/", certHandler.Create)
				cr.Get("/{id}", certHandler.Get)
				cr.Put("/{id}", certHandler.Update)
				cr.Delete("/{id}", certHandler.Delete)
				cr.Post("/{id}/issue", certHandler.Issue)
				cr.Get("/{id}/jobs", certHandler.ListJobs)
				cr.Post("/{id}/pem", certHandler.GetPEM)
				cr.Get("/{id}/bundle.zip", certHandler.DownloadBundle)
				cr.Get("/{id}/deployments", deployHandler.ListCertDeployments)
				cr.Post("/{id}/deployments", deployHandler.CreateDeployment)
			})

			pr.Route("/cert-jobs/{jobId}", func(jr chi.Router) {
				jr.Get("/", certHandler.GetJob)
				jr.Get("/stream", sseHandler.StreamCertJob)
			})

			// Hosts & Caddy Management
			pr.Route("/hosts", func(hr chi.Router) {
				hr.Get("/", hostHandler.ListHosts)
				hr.Post("/", hostHandler.CreateHost)
				hr.Post("/probe", hostHandler.ProbeHost)
				hr.Get("/{id}", hostHandler.GetHost)
				hr.Put("/{id}", hostHandler.UpdateHost)
				hr.Delete("/{id}", hostHandler.DeleteHost)
				hr.Post("/{id}/test", hostHandler.TestHost)
				hr.Post("/{id}/discover-caddy", hostHandler.DiscoverCaddy)
				hr.Post("/{id}/reset-host-key", hostHandler.ResetHostKey)
				hr.Get("/{id}/deployments", hostHandler.ListHostDeployments)

				hr.Route("/{id}/caddy", func(cdr chi.Router) {
					cdr.Get("/caddyfile", caddyHandler.GetCaddyfile)
					cdr.Put("/caddyfile", caddyHandler.SaveCaddyfile)
					cdr.Post("/format", caddyHandler.Format)
					cdr.Post("/validate", caddyHandler.Validate)
					cdr.Post("/reload", caddyHandler.Reload)
					cdr.Get("/snapshots", caddyHandler.Snapshots)
					cdr.Get("/snapshots/{snapId}/diff", caddyHandler.SnapshotDiff)
					cdr.Post("/snapshots/{snapId}/rollback", caddyHandler.Rollback)
					cdr.Get("/container", caddyHandler.ContainerInfo)
				})
			})

			// Deployments
			pr.Route("/deployments/{id}", func(dr chi.Router) {
				dr.Put("/", deployHandler.UpdateDeployment)
				dr.Delete("/", deployHandler.DeleteDeployment)
				dr.Post("/push", deployHandler.PushDeployment)
				dr.Get("/logs", deployHandler.ListDeploymentLogs)
			})

			// Webhooks
			pr.Route("/webhooks", func(wr chi.Router) {
				wr.Get("/", webhookHandler.List)
				wr.Post("/", webhookHandler.Create)
				wr.Put("/{id}", webhookHandler.Update)
				wr.Delete("/{id}", webhookHandler.Delete)
				wr.Post("/{id}/test", webhookHandler.Test)
			})

			// Settings & Log Maintenance
			pr.Route("/settings", func(sr chi.Router) {
				sr.Get("/", settingsHandler.Get)
				sr.Put("/", settingsHandler.Update)
				sr.Post("/prune-logs", settingsHandler.PruneLogs)
			})

			// Backup & Restore
			pr.Route("/backup", func(br chi.Router) {
				br.Post("/export", backupHandler.Export)
				br.Post("/restore", backupHandler.Restore)
			})
		})
	})

	webFS := deps.WebFS
	if webFS == nil {
		webFS = web.DistFS()
	}
	spaHandler := newSPAHandler(webFS)

	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		if isAPIPath(r.URL.Path) {
			Fail(w, http.StatusMethodNotAllowed, CodeBadRequest, "Method not allowed", nil)
			return
		}
		Fail(w, http.StatusMethodNotAllowed, CodeBadRequest, "Method not allowed", nil)
	})

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if isAPIPath(r.URL.Path) {
			Fail(w, http.StatusNotFound, CodeNotFound, "API endpoint not found", nil)
			return
		}
		spaHandler.ServeHTTP(w, r)
	})

	return r
}

func isAPIPath(p string) bool {
	return p == "/api" || strings.HasPrefix(p, "/api/")
}

func newSPAHandler(webFS fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			Fail(w, http.StatusMethodNotAllowed, CodeBadRequest, "Method not allowed", nil)
			return
		}

		clean := strings.TrimPrefix(pathpkg.Clean("/"+r.URL.Path), "/")
		if clean == "favicon.ico" {
			if info, err := fs.Stat(webFS, "favicon.svg"); err == nil && !info.IsDir() {
				w.Header().Set("Content-Type", "image/svg+xml")
				w.Header().Set("Cache-Control", "public, max-age=86400")
				http.ServeFileFS(w, r, webFS, "favicon.svg")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if clean != "" && clean != "." && clean != "index.html" {
			if info, err := fs.Stat(webFS, clean); err == nil && !info.IsDir() {
				if strings.HasPrefix(clean, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.ServeFileFS(w, r, webFS, clean)
				return
			}
		}

		indexBytes, err := fs.ReadFile(webFS, "index.html")
		if err != nil {
			http.Error(w, "Frontend assets not available", http.StatusInternalServerError)
			return
		}
		info, err := fs.Stat(webFS, "index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		if err == nil {
			http.ServeContent(w, r, "index.html", info.ModTime(), bytes.NewReader(indexBytes))
			return
		}
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(indexBytes)
		}
	})
}
