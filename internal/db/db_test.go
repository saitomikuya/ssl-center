package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ssl-center/internal/model"
)

func openTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "app.db")
	d, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open(%s): %v", dbPath, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, dir
}

func TestSchema12TablesPragmasAndLocalHost(t *testing.T) {
	d, _ := openTestDB(t)
	ctx := context.Background()

	d.mu.RLock()
	sqlDB, err := d.conn()
	d.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}

	rows, err := sqlDB.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	_ = rows.Close()

	want := []string{
		"audit_events", "ca_accounts", "caddy_snapshots", "cert_jobs",
		"certificates", "deploy_logs", "deployments", "dns_credentials",
		"hosts", "sessions", "settings", "webhooks",
	}
	if len(tables) != len(want) {
		t.Fatalf("table count = %d (%v), want %d (%v)", len(tables), tables, len(want), want)
	}
	for i := range want {
		if tables[i] != want[i] {
			t.Fatalf("table[%d] = %q, want %q", i, tables[i], want[i])
		}
	}

	var journalMode string
	var fk, userVer int
	_ = sqlDB.QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&journalMode)
	_ = sqlDB.QueryRowContext(ctx, "PRAGMA foreign_keys;").Scan(&fk)
	_ = sqlDB.QueryRowContext(ctx, "PRAGMA user_version;").Scan(&userVer)
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}
	if fk != 1 {
		t.Fatalf("foreign_keys = %d, want 1", fk)
	}
	if userVer != 1 {
		t.Fatalf("user_version = %d, want 1", userVer)
	}

	// Default settings check
	settings, err := d.GetSettingsDTO(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.InspectTime != "03:00" || settings.RenewBeforeDays != 30 || settings.LogMaxRows != 5000 {
		t.Fatalf("unexpected default settings: %+v", settings)
	}

	// Seeded Local host check and undeletable guard
	local, err := d.GetLocalHost(ctx)
	if err != nil {
		t.Fatalf("GetLocalHost: %v", err)
	}
	if !local.IsLocal || local.Mode != model.HostModeLocal || local.Name != "Local" {
		t.Fatalf("unexpected Local host: %+v", local)
	}
	if err := d.DeleteHost(ctx, local.ID); !errors.Is(err, ErrLocalHostProtected) {
		t.Fatalf("DeleteHost(Local) = %v, want ErrLocalHostProtected", err)
	}
}

func TestAll12TableCRUDAndConstraints(t *testing.T) {
	d, _ := openTestDB(t)
	ctx := context.Background()

	// 1. Settings
	if err := d.SetSetting(ctx, "custom_key", "custom_val"); err != nil {
		t.Fatal(err)
	}
	val, err := d.GetSetting(ctx, "custom_key")
	if err != nil || val != "custom_val" {
		t.Fatalf("GetSetting = (%q, %v)", val, err)
	}

	// 2. Sessions
	sess := &model.Session{
		ID:        "sess_hash_123",
		CSRFToken: "csrf_123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := d.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	gotSess, err := d.GetSession(ctx, sess.ID)
	if err != nil || gotSess.CSRFToken != "csrf_123" {
		t.Fatalf("GetSession = (%+v, %v)", gotSess, err)
	}

	// 3. CA Accounts
	ca1 := &model.CAAccount{
		Name:         "LE Staging",
		Provider:     model.CAProviderLetsEncrypt,
		Environment:  model.CAEnvStaging,
		Email:        "admin@example.com",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		ACMEKeyEnc:   "v1:encrypted_key",
		IsDefault:    true,
	}
	if _, err := d.CreateCAAccount(ctx, ca1); err != nil {
		t.Fatal(err)
	}
	ca2 := &model.CAAccount{
		Name:         "GTS Prod",
		Provider:     model.CAProviderGTS,
		Environment:  model.CAEnvProduction,
		Email:        "admin@example.com",
		DirectoryURL: "https://dv.acme-v02.api.pki.goog/directory",
		ACMEKeyEnc:   "v1:encrypted_key_2",
		IsDefault:    true, // should atomically demote ca1
	}
	if _, err := d.CreateCAAccount(ctx, ca2); err != nil {
		t.Fatal(err)
	}
	defCA, err := d.GetDefaultCAAccount(ctx)
	if err != nil || defCA.ID != ca2.ID {
		t.Fatalf("GetDefaultCAAccount = (%+v, %v), want ca2 ID %d", defCA, err, ca2.ID)
	}

	// 4. DNS Credentials
	dns := &model.DNSCredential{
		Name:      "Main CF",
		Provider:  model.DNSProviderCloudflare,
		ConfigEnc: "v1:cf_enc",
	}
	if _, err := d.CreateDNSCredential(ctx, dns); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateDNSTestResult(ctx, dns.ID, true, "ok", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	// 5. Certificates
	cert := &model.Certificate{
		Name:            "Wildcard",
		Domain:          "*.example.com",
		SANsJSON:        `["example.com","*.example.com"]`,
		CAAccountID:     ca2.ID,
		DNSCredentialID: dns.ID,
		KeyType:         model.KeyTypeEC256,
		RenewBeforeDays: 30,
		AutoRenew:       true,
	}
	if _, err := d.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}
	// FK restrict on CA/DNS in use
	if err := d.DeleteCAAccount(ctx, ca2.ID); !errors.Is(err, ErrResourceInUse) {
		t.Fatalf("DeleteCAAccount in use = %v, want ErrResourceInUse", err)
	}
	if err := d.DeleteDNSCredential(ctx, dns.ID); !errors.Is(err, ErrResourceInUse) {
		t.Fatalf("DeleteDNSCredential in use = %v, want ErrResourceInUse", err)
	}

	// 6. Hosts
	remote := &model.Host{
		Name:         "Edge-1",
		Mode:         model.HostModeSSH,
		Host:         "10.0.0.10",
		Port:         22,
		Username:     "root",
		AuthType:     model.HostAuthKey,
		CaddyEnabled: true,
	}
	if _, err := d.CreateHost(ctx, remote); err != nil {
		t.Fatal(err)
	}

	// 7. Deployments
	dep := &model.Deployment{
		CertificateID:    cert.ID,
		HostID:           remote.ID,
		Name:             "Edge-1 Caddy",
		Template:         model.DeployTemplateCaddyDocker,
		Enabled:          true,
		FullchainPath:    "/opt/caddy/certs/example.com/fullchain.pem",
		PrivkeyPath:      "/opt/caddy/certs/example.com/privkey.pem",
		ReloadMode:       model.ReloadModeDockerExec,
		ReloadCommand:    model.DefaultCaddyReloadCmd("caddy", "/etc/caddy/Caddyfile"),
		TLSVerifyEnabled: true,
	}
	if _, err := d.CreateDeployment(ctx, dep); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteHost(ctx, remote.ID); !errors.Is(err, ErrResourceInUse) {
		t.Fatalf("DeleteHost with deployment = %v, want ErrResourceInUse", err)
	}

	// 8. CertJobs
	job := &model.CertJob{
		CertificateID: cert.ID,
		TriggerType:   model.TriggerManual,
		Status:        model.JobStatusRunning,
		CurrentStage:  model.StageCreateOrder,
	}
	if _, err := d.CreateCertJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendCertJobLog(ctx, job.ID, "stage 1 ok\n"); err != nil {
		t.Fatal(err)
	}

	// 9. DeployLogs
	exit0 := 0
	dl := &model.DeployLog{
		DeploymentID:  dep.ID,
		CertificateID: cert.ID,
		HostID:        remote.ID,
		CertJobID:     &job.ID,
		TriggerType:   model.TriggerManual,
		Status:        model.JobStatusSuccess,
		ExitCode:      &exit0,
		Stdout:        "reloaded",
		TLSVerified:   true,
	}
	if _, err := d.CreateDeployLog(ctx, dl); err != nil {
		t.Fatal(err)
	}

	// 10. CaddySnapshots
	snap := &model.CaddySnapshot{
		HostID:   remote.ID,
		Content:  "example.com {\n  respond \"ok\"\n}\n",
		SHA256:   "abc123",
		Action:   model.CaddyActionPublish,
		Summary:  "initial",
		ReloadOK: true,
	}
	if _, err := d.CreateCaddySnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if snap.Version != 1 {
		t.Fatalf("snap.Version = %d, want 1", snap.Version)
	}

	// 11. Webhooks
	wh := &model.Webhook{
		Name:       "Ops Alert",
		URL:        "https://hooks.example.com/notify",
		HeadersEnc: "v1:hdr",
		SecretEnc:  "v1:sec",
		Enabled:    true,
	}
	if _, err := d.CreateWebhook(ctx, wh); err != nil {
		t.Fatal(err)
	}

	// 12. AuditEvents
	evt := &model.AuditEvent{
		EventType:  "cert.created",
		Level:      model.AuditLevelInfo,
		TargetType: "certificate",
		TargetID:   &cert.ID,
		TargetName: cert.Domain,
		Message:    "created wildcard cert",
		ActorIP:    "127.0.0.1",
	}
	if _, err := d.CreateAuditEvent(ctx, evt); err != nil {
		t.Fatal(err)
	}

	cs, hs, ds, err := d.GetDashboardCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Total != 1 || hs.Total != 2 || ds.Total != 1 {
		t.Fatalf("unexpected counts: cert=%+v host=%+v deploy=%+v", cs, hs, ds)
	}
}

func TestPruneExportAndSwapDB(t *testing.T) {
	d, dir := openTestDB(t)
	ctx := context.Background()

	// Seed dependencies for logs
	ca := &model.CAAccount{Name: "CA", Provider: model.CAProviderLetsEncrypt, Environment: model.CAEnvStaging, Email: "a@b.com", DirectoryURL: "https://x", ACMEKeyEnc: "v1:k"}
	_, _ = d.CreateCAAccount(ctx, ca)
	dns := &model.DNSCredential{Name: "DNS", Provider: model.DNSProviderCloudflare, ConfigEnc: "v1:d"}
	_, _ = d.CreateDNSCredential(ctx, dns)
	cert := &model.Certificate{Domain: "a.example.com", CAAccountID: ca.ID, DNSCredentialID: dns.ID}
	_, _ = d.CreateCertificate(ctx, cert)

	// Old finished job, running old job (must NOT be deleted), and recent jobs
	oldTime := time.Now().UTC().AddDate(0, 0, -45)
	_, err := d.CreateCertJob(ctx, &model.CertJob{CertificateID: cert.ID, TriggerType: model.TriggerManual, Status: model.JobStatusSuccess, StartedAt: oldTime})
	if err != nil {
		t.Fatal(err)
	}
	runningOld := &model.CertJob{CertificateID: cert.ID, TriggerType: model.TriggerManual, Status: model.JobStatusRunning, StartedAt: oldTime}
	if _, err := d.CreateCertJob(ctx, runningOld); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_, _ = d.CreateAuditEvent(ctx, &model.AuditEvent{EventType: "test", Message: "msg", CreatedAt: time.Now().UTC()})
	}
	_, _ = d.CreateAuditEvent(ctx, &model.AuditEvent{EventType: "old", Message: "old", CreatedAt: oldTime})

	pruneRes, err := d.PruneLogs(ctx, 30, 2)
	if err != nil {
		t.Fatalf("PruneLogs: %v", err)
	}
	if pruneRes.CertJobsDeleted != 1 || pruneRes.AuditEventsDeleted != 3 {
		t.Fatalf("unexpected prune result: %+v", pruneRes)
	}
	if _, err := d.GetCertJob(ctx, runningOld.ID); err != nil {
		t.Fatalf("running job should not be pruned: %v", err)
	}

	// Create live session, export via ExportVacuumInto, ensure sessions cleared in export but kept in live DB
	liveSess := &model.Session{ID: "live_sess_1", CSRFToken: "csrf", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := d.CreateSession(ctx, liveSess); err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(dir, "export.db")
	if err := d.ExportVacuumInto(ctx, exportPath); err != nil {
		t.Fatalf("ExportVacuumInto: %v", err)
	}

	// Live session must still exist
	if _, err := d.GetSession(ctx, liveSess.ID); err != nil {
		t.Fatalf("live session lost after export: %v", err)
	}

	// Exported DB must have 0 sessions and preserve certificate
	expSQL, err := sql.Open("sqlite", exportPath)
	if err != nil {
		t.Fatal(err)
	}
	var expSessCount, expCertCount int
	_ = expSQL.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&expSessCount)
	_ = expSQL.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&expCertCount)
	_ = expSQL.Close()
	if expSessCount != 0 || expCertCount != 1 {
		t.Fatalf("exported db sessions=%d certs=%d, want 0, 1", expSessCount, expCertCount)
	}

	// Test SwapDB replacing live DB with exported DB
	if err := d.SwapDB(func(dbPath string) error {
		data, err := os.ReadFile(exportPath)
		if err != nil {
			return err
		}
		return os.WriteFile(dbPath, data, 0o600)
	}); err != nil {
		t.Fatalf("SwapDB: %v", err)
	}

	if _, err := d.GetSession(ctx, liveSess.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected live session cleared after SwapDB to export, got %v", err)
	}
	if _, err := d.GetCertificate(ctx, cert.ID); err != nil {
		t.Fatalf("certificate missing after SwapDB: %v", err)
	}
	if err := d.CheckIntegrity(ctx); err != nil {
		t.Fatalf("CheckIntegrity after SwapDB: %v", err)
	}

	// SwapDB with corrupt/invalid replacement file must fail and keep original DB open, intact, and readable
	if err := d.SwapDB(func(dbPath string) error {
		return os.WriteFile(dbPath, []byte("corrupt-not-sqlite-bytes"), 0o600)
	}); err == nil {
		t.Fatal("expected SwapDB with corrupt bytes to fail")
	}
	if err := d.CheckIntegrity(ctx); err != nil {
		t.Fatalf("CheckIntegrity after failed corrupt SwapDB: %v", err)
	}
	if gotCert, err := d.GetCertificate(ctx, cert.ID); err != nil || gotCert.Domain != cert.Domain {
		t.Fatalf("original DB lost data after corrupt SwapDB: (%+v, %v)", gotCert, err)
	}

	// SwapDB with valid SQLite file lacking 12-table schema (user_version=1, 1 table) must fail and rollback
	badSchemaPath := filepath.Join(dir, "bad_schema.db")
	badSQL, err := sql.Open("sqlite", badSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = badSQL.Exec("CREATE TABLE only_one (id INTEGER PRIMARY KEY); PRAGMA user_version = 1;")
	_ = badSQL.Close()
	if err := d.SwapDB(func(dbPath string) error {
		data, readErr := os.ReadFile(badSchemaPath)
		if readErr != nil {
			return readErr
		}
		return os.WriteFile(dbPath, data, 0o600)
	}); err == nil {
		t.Fatal("expected SwapDB with incomplete schema to fail")
	}
	if err := d.CheckIntegrity(ctx); err != nil {
		t.Fatalf("CheckIntegrity after failed bad-schema SwapDB: %v", err)
	}
	if gotCert, err := d.GetCertificate(ctx, cert.ID); err != nil || gotCert.Domain != cert.Domain {
		t.Fatalf("original DB lost data after bad-schema SwapDB: (%+v, %v)", gotCert, err)
	}
}

func TestFKErrorMappingAndEmptyListSlices(t *testing.T) {
	d, _ := openTestDB(t)
	ctx := context.Background()

	// Empty list methods must return non-nil slices that serialize to JSON []
	cas, err := d.ListCAAccounts(ctx)
	if err != nil || cas == nil || len(cas) != 0 {
		t.Fatalf("ListCAAccounts empty = (%#v, %v)", cas, err)
	}
	if raw, _ := json.Marshal(cas); string(raw) != "[]" {
		t.Fatalf("ListCAAccounts JSON = %s, want []", string(raw))
	}
	dnss, err := d.ListDNSCredentials(ctx)
	if err != nil || dnss == nil {
		t.Fatalf("ListDNSCredentials empty = (%#v, %v)", dnss, err)
	}
	certs, err := d.ListCertificates(ctx)
	if err != nil || certs == nil {
		t.Fatalf("ListCertificates empty = (%#v, %v)", certs, err)
	}
	deps, err := d.ListAllDeployments(ctx)
	if err != nil || deps == nil {
		t.Fatalf("ListAllDeployments empty = (%#v, %v)", deps, err)
	}
	jobs, err := d.ListCertJobsByCertificate(ctx, 1, 10)
	if err != nil || jobs == nil {
		t.Fatalf("ListCertJobsByCertificate empty = (%#v, %v)", jobs, err)
	}
	logs, err := d.ListDeployLogsByDeployment(ctx, 1, 10)
	if err != nil || logs == nil {
		t.Fatalf("ListDeployLogsByDeployment empty = (%#v, %v)", logs, err)
	}
	snaps, err := d.ListCaddySnapshotsByHost(ctx, 1, 10)
	if err != nil || snaps == nil {
		t.Fatalf("ListCaddySnapshotsByHost empty = (%#v, %v)", snaps, err)
	}
	whs, err := d.ListWebhooks(ctx)
	if err != nil || whs == nil {
		t.Fatalf("ListWebhooks empty = (%#v, %v)", whs, err)
	}
	evts, err := d.ListRecentAuditEvents(ctx, 10)
	if err != nil || evts == nil {
		t.Fatalf("ListRecentAuditEvents empty = (%#v, %v)", evts, err)
	}

	// Create valid CA and DNS
	ca := &model.CAAccount{Name: "CA", Provider: model.CAProviderLetsEncrypt, Environment: model.CAEnvStaging, Email: "a@b.com", DirectoryURL: "https://x", ACMEKeyEnc: "v1:k"}
	if _, err := d.CreateCAAccount(ctx, ca); err != nil {
		t.Fatal(err)
	}
	dns := &model.DNSCredential{Name: "DNS", Provider: model.DNSProviderCloudflare, ConfigEnc: "v1:d"}
	if _, err := d.CreateDNSCredential(ctx, dns); err != nil {
		t.Fatal(err)
	}

	// CreateCertificate with non-existent ca_account_id must return ErrInvalidReference (NOT ErrResourceInUse)
	_, err = d.CreateCertificate(ctx, &model.Certificate{
		Domain:          "bad-ca.example.com",
		CAAccountID:     99999,
		DNSCredentialID: dns.ID,
	})
	if !errors.Is(err, ErrInvalidReference) || errors.Is(err, ErrResourceInUse) {
		t.Fatalf("CreateCertificate invalid ca_account_id = %v, want ErrInvalidReference", err)
	}

	// Create valid certificate, then DeleteCAAccount must return ErrResourceInUse
	cert := &model.Certificate{
		Domain:          "good.example.com",
		CAAccountID:     ca.ID,
		DNSCredentialID: dns.ID,
	}
	if _, err := d.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteCAAccount(ctx, ca.ID); !errors.Is(err, ErrResourceInUse) {
		t.Fatalf("DeleteCAAccount in use = %v, want ErrResourceInUse", err)
	}
}

func TestOpenRepairsStaleLocalHostCheckStatus(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "app.db")
	d, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open initial: %v", err)
	}

	ctx := context.Background()
	localHost, err := d.GetLocalHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateHostCheckResult(ctx, localHost.ID, true, "Local host OK; Docker unavailable", model.CaddyStatusUnknown, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	got, err := reopened.GetLocalHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastCheckOK == nil || *got.LastCheckOK {
		t.Fatalf("expected stale Local last_check_ok=1 to be repaired to 0, got %v", got.LastCheckOK)
	}

	_, hs, _, err := reopened.GetDashboardCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hs.Reachable != 0 || hs.Unreachable != 1 {
		t.Fatalf("expected dashboard reachable=0 unreachable=1 after repair, got %+v", hs)
	}
}
