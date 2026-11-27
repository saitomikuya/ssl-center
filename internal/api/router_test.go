package api

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssl-center/internal/acme"
	"ssl-center/internal/auth"
	"ssl-center/internal/backup"
	"ssl-center/internal/caddy"
	"ssl-center/internal/config"
	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/deploy"
	"ssl-center/internal/model"
	"ssl-center/internal/notify"
)

func TestFullAssembledRouterEndToEnd(t *testing.T) {
	dataDir := t.TempDir()
	cfg := &config.Config{
		DataDir:         dataDir,
		ListenAddr:      "127.0.0.1:0",
		InitForceChange: true,
		CookieSecure:    config.CookieSecureAuto,
		TrustProxy:      false,
		LogLevel:        "info",
		TZ:              "UTC",
	}
	if err := cfg.EnsureDataDirs(); err != nil {
		t.Fatalf("EnsureDataDirs: %v", err)
	}

	key, created, err := crypto.LoadOrCreateMasterKey(cfg.MasterKeyPath())
	if err != nil || !created {
		t.Fatalf("LoadOrCreateMasterKey: created=%v err=%v", created, err)
	}
	cipher, err := crypto.NewCipher(key)
	crypto.ZeroBytes(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	redactor := crypto.NewSecretRedactor()

	database, err := db.Open(cfg.DBPath())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	authSvc := auth.NewService(database, cfg, nil)
	ctx := context.Background()
	genPass, err := authSvc.BootstrapAdmin(ctx)
	if err != nil || genPass == "" {
		t.Fatalf("BootstrapAdmin: pass=%q err=%v", genPass, err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	maint := NewMaintenanceCoordinator()
	broker := NewCertJobBroker()
	notifier := notify.NewWebhookNotifier(database, cipher, redactor)
	transport := deploy.NewTransport(database, cipher, redactor, logger)
	deployEngine := deploy.NewEngine(database, transport, notifier, redactor, logger)
	caSvc := acme.NewCAService(database, cipher, redactor)
	dnsSvc := acme.NewDNSService(database, cipher, redactor)
	issuer := acme.NewIssuer(database, cfg, caSvc, dnsSvc, redactor, broker, deployEngine, notifier)
	scheduler := acme.NewScheduler(database, cfg, issuer, notifier, maint)
	caddyMgr := caddy.NewManager(database, transport, notifier, redactor)
	backupSvc := backup.NewService(cfg, database, cipher, redactor, maint, scheduler)

	router := NewRouter(RouterDeps{
		Config:       cfg,
		DB:           database,
		Cipher:       cipher,
		Redactor:     redactor,
		Logger:       logger,
		Auth:         authSvc,
		Maint:        maint,
		Broker:       broker,
		Notifier:     notifier,
		Transport:    transport,
		DeployEngine: deployEngine,
		CAService:    caSvc,
		DNSService:   dnsSvc,
		Issuer:       issuer,
		Scheduler:    scheduler,
		CaddyManager: caddyMgr,
		BackupSvc:    backupSvc,
	})

	// 1. Embedded SPA routes (root and Vue client-side fallback routes)
	for _, p := range []string{"/", "/certificates", "/hosts", "/settings"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("SPA GET %s status=%d, want 200", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Fatalf("SPA GET %s Content-Type=%q, want text/html", p, ct)
		}
		if !strings.Contains(strings.ToLower(rec.Body.String()), "<html") {
			t.Fatalf("SPA GET %s body missing <html", p)
		}
	}

	// 2. Unknown /api/* returns structured JSON 404 NOT_FOUND
	for _, p := range []string{"/api", "/api/unknown", "/api/v1/no-such-endpoint"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s status=%d, want 404", p, rec.Code)
		}
		env := decodeEnvelope(t, rec.Body.Bytes())
		if env.OK || env.Error == nil || env.Error.Code != CodeNotFound {
			t.Fatalf("GET %s body=%s, want NOT_FOUND envelope", p, rec.Body.String())
		}
	}

	// 3. Public health endpoint
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health status=%d, want 200", rec.Code)
	}

	// 4. Login with generated initial password
	rec = httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(fmt.Sprintf(`{"password":%q}`, genPass)))
	loginReq.RemoteAddr = "127.0.0.1:43210"
	router.ServeHTTP(rec, loginReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rec.Code, rec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("missing session cookie after login")
	}
	var loginResp model.AuthMeResponse
	mustDecodeData(t, rec.Body.Bytes(), &loginResp)
	if !loginResp.MustChangePassword || loginResp.CSRFToken == "" {
		t.Fatalf("unexpected loginResp: %+v", loginResp)
	}

	doAuth := func(method, path, body string, withCSRF bool) *httptest.ResponseRecorder {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = bytes.NewBufferString(body)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.RemoteAddr = "127.0.0.1:43210"
		req.AddCookie(sessionCookie)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if withCSRF {
			req.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// 5. Dashboard blocked by 403 PASSWORD_CHANGE_REQUIRED before changing password
	rec = doAuth(http.MethodGet, "/api/v1/dashboard", "", false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("dashboard before pwd change = %d, want 403", rec.Code)
	}
	if env := decodeEnvelope(t, rec.Body.Bytes()); env.Error == nil || env.Error.Code != CodePasswordChangeRequired {
		t.Fatalf("expected PASSWORD_CHANGE_REQUIRED, got %+v", env.Error)
	}

	// 6. Change password requires CSRF, then succeeds
	rec = doAuth(http.MethodPost, "/api/v1/auth/change-password", fmt.Sprintf(`{"current_password":%q,"new_password":"NewStrongPassword1!"}`, genPass), false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("change-password without CSRF = %d, want 403", rec.Code)
	}
	rec = doAuth(http.MethodPost, "/api/v1/auth/change-password", fmt.Sprintf(`{"current_password":%q,"new_password":"NewStrongPassword1!"}`, genPass), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password = %d, body=%s", rec.Code, rec.Body.String())
	}

	// 7. Dashboard works after password change
	rec = doAuth(http.MethodGet, "/api/v1/dashboard", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard after pwd change = %d, body=%s", rec.Code, rec.Body.String())
	}

	// 8. DNS Credentials CRUD
	rec = doAuth(http.MethodPost, "/api/v1/dns-credentials", `{"name":"CF Test","provider":"cloudflare","api_token":"cf-secret-token-xyz"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create DNS status=%d body=%s", rec.Code, rec.Body.String())
	}
	var dnsDTO model.DNSCredentialDTO
	mustDecodeData(t, rec.Body.Bytes(), &dnsDTO)

	// 9. Seed CA directly for cert CRUD (and verify GET /ca-accounts)
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)}))
	caEnc, err := cipher.Encrypt(caPEM, "ca_accounts:acme_key_enc")
	if err != nil {
		t.Fatal(err)
	}
	caRec := &model.CAAccount{
		Name:         "Test CA",
		Provider:     model.CAProviderLetsEncrypt,
		Environment:  model.CAEnvStaging,
		Email:        "ops@example.com",
		DirectoryURL: acme.LetsEncryptStagingURL,
		AccountURI:   "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1",
		ACMEKeyEnc:   caEnc,
		IsDefault:    true,
		Status:       model.CAStatusActive,
	}
	if _, err := database.CreateCAAccount(ctx, caRec); err != nil {
		t.Fatal(err)
	}
	rec = doAuth(http.MethodGet, "/api/v1/ca-accounts", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("list CA status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 10. Hosts: Local exists and cannot be deleted (403 LOCAL_HOST_PROTECTED); SSH host CRUD works
	rec = doAuth(http.MethodGet, "/api/v1/hosts", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("list hosts status=%d body=%s", rec.Code, rec.Body.String())
	}
	var hosts []model.HostDTO
	mustDecodeData(t, rec.Body.Bytes(), &hosts)
	if len(hosts) == 0 || !hosts[0].IsLocal {
		t.Fatalf("expected built-in Local host, got %+v", hosts)
	}
	localHostID := hosts[0].ID

	rec = doAuth(http.MethodDelete, fmt.Sprintf("/api/v1/hosts/%d", localHostID), "", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete local host status=%d, want 403", rec.Code)
	}
	if env := decodeEnvelope(t, rec.Body.Bytes()); env.Error == nil || env.Error.Code != CodeLocalHostProtected {
		t.Fatalf("expected LOCAL_HOST_PROTECTED, got %+v", env.Error)
	}

	rec = doAuth(http.MethodPost, "/api/v1/hosts", `{"name":"edge-1","mode":"ssh","host":"10.0.0.10","port":22,"username":"root","auth_type":"password","ssh_password":"ssh-secret-password-999"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create ssh host status=%d body=%s", rec.Code, rec.Body.String())
	}
	var sshHost model.HostDTO
	mustDecodeData(t, rec.Body.Bytes(), &sshHost)

	// 11. Certificate + Deployment CRUD
	rec = doAuth(http.MethodPost, "/api/v1/certificates", fmt.Sprintf(`{"name":"Example Wildcard","domain":"*.example.com","sans":["example.com","*.example.com"],"ca_account_id":%d,"dns_credential_id":%d,"key_type":"EC256","renew_before_days":30,"auto_renew":true}`, caRec.ID, dnsDTO.ID), true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cert status=%d body=%s", rec.Code, rec.Body.String())
	}
	var certDTO model.CertificateDTO
	mustDecodeData(t, rec.Body.Bytes(), &certDTO)

	rec = doAuth(http.MethodPost, fmt.Sprintf("/api/v1/certificates/%d/deployments", certDTO.ID), fmt.Sprintf(`{"host_id":%d,"template":"caddy_docker"}`, sshHost.ID), true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create deployment status=%d body=%s", rec.Code, rec.Body.String())
	}
	var depDTO model.DeploymentDTO
	mustDecodeData(t, rec.Body.Bytes(), &depDTO)
	if !strings.Contains(depDTO.ReloadCommand, "--force") {
		t.Fatalf("expected --force in reload command, got %q", depDTO.ReloadCommand)
	}

	// 12. Caddy local Caddyfile read via router
	localCaddyfile := filepath.Join(dataDir, "local-Caddyfile")
	if err := os.WriteFile(localCaddyfile, []byte("example.com {\n\trespond \"ok\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	localHostModel, err := database.GetHost(ctx, localHostID)
	if err != nil {
		t.Fatal(err)
	}
	localHostModel.CaddyEnabled = true
	localHostModel.CaddyHostCaddyfile = localCaddyfile
	if err := database.UpdateHost(ctx, localHostModel); err != nil {
		t.Fatal(err)
	}
	rec = doAuth(http.MethodGet, fmt.Sprintf("/api/v1/hosts/%d/caddy/caddyfile", localHostID), "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("get local caddyfile status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 13. Webhooks CRUD
	rec = doAuth(http.MethodPost, "/api/v1/webhooks", `{"name":"Ops Hook","url":"https://hooks.example.com/notify","secret":"wh-secret-123456"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create webhook status=%d body=%s", rec.Code, rec.Body.String())
	}
	var whDTO model.WebhookDTO
	mustDecodeData(t, rec.Body.Bytes(), &whDTO)

	// 14. Settings get/update/prune-logs
	rec = doAuth(http.MethodGet, "/api/v1/settings", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("get settings status=%d", rec.Code)
	}
	rec = doAuth(http.MethodPut, "/api/v1/settings", `{"inspect_time":"04:30","log_retention_days":14}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("update settings status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = doAuth(http.MethodPost, "/api/v1/settings/prune-logs", `{}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("prune logs status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 15. SSE streaming over real httptest.Server (proves RequestLogger preserves http.Flusher)
	job := &model.CertJob{
		CertificateID: certDTO.ID,
		TriggerType:   model.TriggerManual,
		Status:        model.JobStatusRunning,
		CurrentStage:  model.StageCreateOrder,
		StagesJSON:    `[{"stage":"create_order","label":"创建订单","status":"running"}]`,
		Logs:          "[info] started\n",
	}
	if _, err := database.CreateCertJob(ctx, job); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(router)
	defer ts.Close()

	sseReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/cert-jobs/%d/stream", ts.URL, job.ID), nil)
	if err != nil {
		t.Fatal(err)
	}
	sseReq.AddCookie(sessionCookie)
	sseResp, err := ts.Client().Do(sseReq)
	if err != nil {
		t.Fatalf("SSE request failed: %v", err)
	}
	defer sseResp.Body.Close()
	if sseResp.StatusCode != http.StatusOK || !strings.Contains(sseResp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("unexpected SSE response: status=%d ct=%q", sseResp.StatusCode, sseResp.Header.Get("Content-Type"))
	}

	// Read initial replayed stage frame before publishing done event to verify streaming flush works live!
	reader := bufio.NewReader(sseResp.Body)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "event: ") {
		t.Fatalf("expected immediate SSE event frame without buffering, got %q err=%v", line, err)
	}
	broker.Publish(job.ID, model.CertJobSSEEvent{
		Type:         "done",
		Status:       model.JobStatusSuccess,
		CurrentStage: model.StageTriggerDeploy,
	})
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read remaining SSE stream: %v", err)
	}
	if !strings.Contains(string(rest), "event: done") {
		t.Fatalf("expected event: done in SSE stream, got %q", string(rest))
	}

	// 16. Backup export -> restore -> relogin_required -> old cookie 401 -> re-login succeeds
	rec = doAuth(http.MethodPost, "/api/v1/backup/export", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("backup export status=%d body=%s", rec.Code, rec.Body.String())
	}
	archiveBytes := rec.Body.Bytes()
	verifyTarGzContains(t, archiveBytes, "manifest.json", "master.key", "app.db")

	var mpBuf bytes.Buffer
	mw := multipart.NewWriter(&mpBuf)
	fw, err := mw.CreateFormFile("file", "backup.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(archiveBytes); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	restoreReq := httptest.NewRequest(http.MethodPost, "/api/v1/backup/restore", &mpBuf)
	restoreReq.RemoteAddr = "127.0.0.1:43210"
	restoreReq.AddCookie(sessionCookie)
	restoreReq.Header.Set("Content-Type", mw.FormDataContentType())
	restoreReq.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, restoreReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("backup restore status=%d body=%s", rec.Code, rec.Body.String())
	}
	var restoreResp model.RestoreResult
	mustDecodeData(t, rec.Body.Bytes(), &restoreResp)
	if !restoreResp.ReloginRequired {
		t.Fatalf("expected relogin_required=true, got %+v", restoreResp)
	}

	// Old session must now be 401
	rec = doAuth(http.MethodGet, "/api/v1/dashboard", "", false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after restore, got %d", rec.Code)
	}

	// Re-login with restored password succeeds
	rec = httptest.NewRecorder()
	reloginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"password":"NewStrongPassword1!"}`))
	reloginReq.RemoteAddr = "127.0.0.1:43210"
	router.ServeHTTP(rec, reloginReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-login after restore status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func mustDecodeData(t *testing.T, body []byte, dst any) {
	t.Helper()
	env := decodeEnvelope(t, body)
	if !env.OK {
		t.Fatalf("expected ok=true envelope, got %s", string(body))
	}
	raw, err := json.Marshal(env.Data)
	if err != nil {
		t.Fatalf("marshal data: %v", err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal data into %T: %v", dst, err)
	}
}

func verifyTarGzContains(t *testing.T, data []byte, required ...string) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()

	seen := make(map[string]bool)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		seen[hdr.Name] = true
	}
	for _, name := range required {
		if !seen[name] {
			t.Fatalf("backup archive missing %q (found: %v)", name, seen)
		}
	}
}
