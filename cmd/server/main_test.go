package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ssl-center/internal/config"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

func TestInitAppAndLogPrunerAndGracefulRun(t *testing.T) {
	dataDir := t.TempDir()
	cfg := &config.Config{
		DataDir:      dataDir,
		ListenAddr:   "127.0.0.1:0",
		InitPassword: "TestInitPassword123!",
		CookieSecure: config.CookieSecureAuto,
		LogLevel:     "info",
		TZ:           "UTC",
	}

	ctx := context.Background()
	app, err := initApp(ctx, cfg)
	if err != nil {
		t.Fatalf("initApp: %v", err)
	}

	// Verify master.key was created with 0600 permissions
	info, err := os.Stat(filepath.Join(dataDir, "master.key"))
	if err != nil {
		t.Fatalf("stat master.key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("master.key perm = %o, want 0600", info.Mode().Perm())
	}

	// Seed an old audit event and verify PruneNow respects settings & maintenance pause
	oldTime := time.Now().UTC().AddDate(0, 0, -45)
	if _, err := app.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType: "test.old",
		Level:     model.AuditLevelInfo,
		Message:   "old event",
		CreatedAt: oldTime,
	}); err != nil {
		t.Fatalf("CreateAuditEvent: %v", err)
	}

	res, err := app.pruner.PruneNow(ctx)
	if err != nil {
		t.Fatalf("PruneNow: %v", err)
	}
	if res.AuditEventsDeleted < 1 {
		t.Fatalf("expected old audit event pruned, got %+v", res)
	}

	// Maintenance lock blocks PruneNow
	if err := app.pruner.maint.BeginMaintenance(ctx); err != nil {
		t.Fatalf("BeginMaintenance: %v", err)
	}
	if _, err := app.pruner.PruneNow(ctx); err == nil {
		t.Fatal("expected PruneNow error while maintenance active")
	}
	app.pruner.maint.EndMaintenance()

	// Verify runDailyLogPruner exits cleanly on context cancel
	pruneCtx, cancelPrune := context.WithCancel(ctx)
	donePrune := make(chan struct{})
	go func() {
		defer close(donePrune)
		runDailyLogPruner(pruneCtx, app.pruner, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	time.Sleep(35 * time.Millisecond)
	cancelPrune()
	select {
	case <-donePrune:
	case <-time.After(2 * time.Second):
		t.Fatal("runDailyLogPruner did not exit on cancel")
	}
	_ = app.db.Close()

	// Verify run() starts HTTP server and shuts down cleanly on ctx cancel
	// Find an ephemeral free port first
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probeLn.Addr().String()
	_ = probeLn.Close()

	runCfg := &config.Config{
		DataDir:      t.TempDir(),
		ListenAddr:   addr,
		InitPassword: "RunPassword123!",
		CookieSecure: config.CookieSecureAuto,
		LogLevel:     "warn",
		TZ:           "UTC",
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- run(runCtx, runCfg)
	}()

	var healthy bool
	client := &http.Client{Timeout: time.Second}
	for i := 0; i < 40; i++ {
		resp, err := client.Get("http://" + addr + "/api/v1/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healthy {
		cancelRun()
		<-runDone
		t.Fatal("server did not become healthy")
	}

	cancelRun()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down cleanly")
	}

	// Verify DB is readable on restart
	reopened, err := db.Open(runCfg.DBPath())
	if err != nil {
		t.Fatalf("reopen db after shutdown: %v", err)
	}
	_ = reopened.Close()
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestGracefulShutdownWithOpenSSEStream(t *testing.T) {
	var logBuf syncBuffer
	prevLogOut := logOutput
	logOutput = &logBuf
	t.Cleanup(func() {
		logOutput = prevLogOut
	})

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probeLn.Addr().String()
	_ = probeLn.Close()

	runCfg := &config.Config{
		DataDir:         t.TempDir(),
		ListenAddr:      addr,
		InitPassword:    "SSETestPassword123!",
		InitForceChange: false,
		CookieSecure:    config.CookieSecureAuto,
		LogLevel:        "info",
		TZ:              "UTC",
	}

	// Seed a running cert_jobs row before starting run(...)
	seedCtx := context.Background()
	seedDB, err := db.Open(runCfg.DBPath())
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	caID, err := seedDB.CreateCAAccount(seedCtx, &model.CAAccount{
		Name:         "test-le",
		Provider:     model.CAProviderLetsEncrypt,
		Environment:  model.CAEnvStaging,
		Email:        "admin@example.com",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		IsDefault:    true,
		Status:       model.CAStatusActive,
	})
	if err != nil {
		_ = seedDB.Close()
		t.Fatalf("CreateCAAccount: %v", err)
	}
	dnsID, err := seedDB.CreateDNSCredential(seedCtx, &model.DNSCredential{
		Name:     "test-cf",
		Provider: model.DNSProviderCloudflare,
	})
	if err != nil {
		_ = seedDB.Close()
		t.Fatalf("CreateDNSCredential: %v", err)
	}
	certID, err := seedDB.CreateCertificate(seedCtx, &model.Certificate{
		Name:            "sse-test",
		Domain:          "sse-shutdown.example.com",
		CAAccountID:     caID,
		DNSCredentialID: dnsID,
		KeyType:         model.KeyTypeEC256,
		AutoRenew:       false,
		Status:          model.CertStatusIssuing,
	})
	if err != nil {
		_ = seedDB.Close()
		t.Fatalf("CreateCertificate: %v", err)
	}
	jobID, err := seedDB.CreateCertJob(seedCtx, &model.CertJob{
		CertificateID: certID,
		TriggerType:   model.TriggerManual,
		Status:        model.JobStatusRunning,
		CurrentStage:  model.StageCreateOrder,
		StagesJSON:    `[{"stage":"create_order","label":"创建订单","status":"running"}]`,
		Logs:          "[info] sse shutdown regression probe\n",
	})
	if err != nil {
		_ = seedDB.Close()
		t.Fatalf("CreateCertJob: %v", err)
	}
	if err := seedDB.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- run(runCtx, runCfg)
	}()

	apiClient := &http.Client{Timeout: 2 * time.Second}
	var healthy bool
	for i := 0; i < 40; i++ {
		resp, err := apiClient.Get("http://" + addr + "/api/v1/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healthy {
		cancelRun()
		<-runDone
		t.Fatal("server did not become healthy")
	}

	loginResp, err := apiClient.Post(
		"http://"+addr+"/api/v1/auth/login",
		"application/json",
		strings.NewReader(`{"password":"SSETestPassword123!"}`),
	)
	if err != nil {
		cancelRun()
		<-runDone
		t.Fatalf("login request failed: %v", err)
	}
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		cancelRun()
		<-runDone
		t.Fatalf("login status = %d, want 200", loginResp.StatusCode)
	}
	var sessionCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Value != "" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		cancelRun()
		<-runDone
		t.Fatal("login response missing session cookie")
	}

	// Open a live SSE stream that will block waiting on r.Context().Done()
	sseClient := &http.Client{}
	sseReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/api/v1/cert-jobs/%d/stream", addr, jobID), nil)
	if err != nil {
		cancelRun()
		<-runDone
		t.Fatalf("NewRequest SSE: %v", err)
	}
	sseReq.AddCookie(sessionCookie)
	sseResp, err := sseClient.Do(sseReq)
	if err != nil {
		cancelRun()
		<-runDone
		t.Fatalf("SSE request failed: %v", err)
	}
	defer sseResp.Body.Close()
	if sseResp.StatusCode != http.StatusOK || !strings.Contains(sseResp.Header.Get("Content-Type"), "text/event-stream") {
		cancelRun()
		<-runDone
		t.Fatalf("unexpected SSE response: status=%d content-type=%q", sseResp.StatusCode, sseResp.Header.Get("Content-Type"))
	}

	reader := bufio.NewReader(sseResp.Body)
	firstLine, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(firstLine, "event: stage") {
		cancelRun()
		<-runDone
		t.Fatalf("expected initial event: stage frame, got %q err=%v", firstLine, err)
	}

	// Simulate SIGTERM while the SSE stream is actively open and blocking
	shutdownStart := time.Now()
	cancelRun()

	select {
	case err := <-runDone:
		elapsed := time.Since(shutdownStart)
		if err != nil {
			t.Fatalf("run returned error on shutdown: %v", err)
		}
		if elapsed >= 2*time.Second {
			t.Fatalf("shutdown took %v (>= 2s), expected immediate unblock", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run(...) did not shut down within 2s while SSE stream was open")
	}

	// Drain remaining SSE stream to confirm connection terminated cleanly
	_, _ = io.ReadAll(reader)

	logs := logBuf.String()
	if strings.Contains(logs, "context deadline exceeded") {
		t.Fatalf("unexpected context deadline exceeded in shutdown logs:\n%s", logs)
	}
	if strings.Contains(logs, "http server graceful shutdown error") {
		t.Fatalf("unexpected http server graceful shutdown error in logs:\n%s", logs)
	}
	if !strings.Contains(logs, "ssl-center shutdown complete") {
		t.Fatalf("expected shutdown complete log, got:\n%s", logs)
	}
}
