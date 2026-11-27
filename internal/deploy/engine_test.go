package deploy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/deploy"
	"ssl-center/internal/model"
)

type spyNotifier struct {
	mu     sync.Mutex
	events []model.WebhookEvent
}

func (n *spyNotifier) Emit(ctx context.Context, evt model.WebhookEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, evt)
	return nil
}

func (n *spyNotifier) SendTest(ctx context.Context, webhookID int64) error {
	return nil
}

func (n *spyNotifier) Events() []model.WebhookEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]model.WebhookEvent, len(n.events))
	copy(out, n.events)
	return out
}

func (n *spyNotifier) Reset() {
	n.mu.Lock()
	n.events = nil
	n.mu.Unlock()
}

func seedCertWithFiles(t *testing.T, database *db.DB, cipher *crypto.Cipher, domain string, certPEM []byte, privPEM []byte, fp string) *model.Certificate {
	t.Helper()
	ctx := context.Background()

	caKeyEnc, err := cipher.Encrypt("fake-acme-key", "ca_accounts:acme_key_enc")
	if err != nil {
		t.Fatal(err)
	}
	ca := &model.CAAccount{
		Name:         "ca-" + domain + "-" + t.Name(),
		Provider:     model.CAProviderLetsEncrypt,
		Environment:  model.CAEnvStaging,
		Email:        "ops@example.com",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		ACMEKeyEnc:   caKeyEnc,
		Status:       model.CAStatusActive,
	}
	if _, err := database.CreateCAAccount(ctx, ca); err != nil {
		t.Fatal(err)
	}

	dnsEnc, err := cipher.Encrypt(`{"api_token":"cf-token-123456"}`, "dns_credentials:config_enc")
	if err != nil {
		t.Fatal(err)
	}
	dns := &model.DNSCredential{
		Name:      "dns-" + domain + "-" + t.Name(),
		Provider:  model.DNSProviderCloudflare,
		ConfigEnc: dnsEnc,
	}
	if _, err := database.CreateDNSCredential(ctx, dns); err != nil {
		t.Fatal(err)
	}

	certDir := filepath.Join(t.TempDir(), "cert_1")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if certPEM == nil || privPEM == nil {
		certPEM, privPEM, fp = generateSelfSignedCertPEM(t, domain)
	}
	if fp == "" {
		var err error
		fp, err = model.ParseLeafFingerprintSHA256(certPEM)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "issuer.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	cert := &model.Certificate{
		Name:              domain,
		Domain:            domain,
		SANsJSON:          `["` + domain + `"]`,
		CAAccountID:       ca.ID,
		DNSCredentialID:   dns.ID,
		KeyType:           model.KeyTypeEC256,
		Status:            model.CertStatusValid,
		FingerprintSHA256: fp,
		CertDir:           certDir,
	}
	if _, err := database.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}
	cert.FingerprintSHA256 = fp
	cert.Status = model.CertStatusValid
	if err := database.UpdateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}
	return cert
}

func generateSelfSignedCertPEM(t *testing.T, cn string) (certPEM, keyPEM []byte, fp string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn, "example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	fp = strings.ToLower(hex.EncodeToString(sum[:]))
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, fp
}

func tlsServerCertPEMAndFP(t *testing.T, ts *httptest.Server) (certPEM []byte, fp string) {
	t.Helper()
	leaf := ts.Certificate()
	sum := sha256.Sum256(leaf.Raw)
	fp = strings.ToLower(hex.EncodeToString(sum[:]))
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	return certPEM, fp
}

func splitHostPortInt(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(addr, "https://"))
	if err != nil {
		t.Fatalf("split host port %q: %v", addr, err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, p
}

func TestTLSVerify_MatchAndMismatch(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)
	notifier := &spyNotifier{}
	tr := deploy.NewTransport(database, cipher, redactor, nil)
	engine := deploy.NewEngine(database, tr, notifier, redactor, nil)

	// Start TLS server #1 (matching cert) and TLS server #2 (different cert)
	tsMatch := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tsMatch.Close()

	otherCertPEM, otherKeyPEM, mismatchFP := generateSelfSignedCertPEM(t, "other.example.com")
	otherTLSCert, err := tls.X509KeyPair(otherCertPEM, otherKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tsMismatch := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	tsMismatch.TLS = &tls.Config{Certificates: []tls.Certificate{otherTLSCert}}
	tsMismatch.StartTLS()
	defer tsMismatch.Close()

	matchPEM, matchFP := tlsServerCertPEMAndFP(t, tsMatch)
	_, privPEM, _ := generateSelfSignedCertPEM(t, "app.example.com")

	cert := seedCertWithFiles(t, database, cipher, "app.example.com", matchPEM, privPEM, matchFP)

	privSSH, pubSSH := generateClientSSHKeyPair(t, "")
	sshSrv := newMockSSHServer(t, pubSSH, "")
	sshSrv.SetExecHandler(func(cmd string, stdin []byte) (string, string, int) {
		return "reloaded", "", 0
	})
	host := createSSHTestHost(t, database, cipher, sshSrv, model.HostAuthKey, privSSH, "", "", model.HostKeyPolicyTOFU, "")

	certOutDir := filepath.Join(t.TempDir(), "remote-certs")
	matchHost, matchPort := splitHostPortInt(t, tsMatch.URL)

	dep := &model.Deployment{
		CertificateID:    cert.ID,
		HostID:           host.ID,
		Name:             "edge-match",
		Template:         model.DeployTemplateCaddyDocker,
		Enabled:          true,
		FullchainPath:    filepath.Join(certOutDir, "fullchain.pem"),
		PrivkeyPath:      filepath.Join(certOutDir, "privkey.pem"),
		IssuerPath:       filepath.Join(certOutDir, "issuer.pem"),
		CertFileMode:     "0644",
		KeyFileMode:      "0600",
		ReloadMode:       model.ReloadModeDockerExec,
		ReloadCommand:    model.DefaultCaddyReloadCmd("caddy", "/etc/caddy/Caddyfile"),
		TLSVerifyEnabled: true,
		TLSVerifyHost:    matchHost,
		TLSVerifyPort:    matchPort,
		TLSVerifySNI:     "example.com",
	}
	if _, err := database.CreateDeployment(ctx, dep); err != nil {
		t.Fatal(err)
	}

	// 1. Matching TLS fingerprint -> PASS
	logEntry, err := engine.DeployTarget(ctx, dep.ID, model.TriggerManual)
	if err != nil {
		t.Fatalf("expected DeployTarget to pass, got err=%v log=%+v", err, logEntry)
	}
	if logEntry.Status != model.JobStatusSuccess || !logEntry.TLSVerified || logEntry.TLSObservedFP != matchFP {
		t.Fatalf("unexpected success DeployLog: %+v", logEntry)
	}

	// Verify caddy_docker --force command ran
	cmds := sshSrv.ExecutedCommands()
	if len(cmds) != 1 || !strings.Contains(cmds[0], "--force") || !strings.Contains(cmds[0], "caddy reload") {
		t.Fatalf("expected caddy reload --force command, got %v", cmds)
	}

	// 2. Mismatched TLS fingerprint -> FAIL + deploy.failed webhook emitted
	notifier.Reset()
	mismatchHost, mismatchPort := splitHostPortInt(t, tsMismatch.URL)
	dep.TLSVerifyHost = mismatchHost
	dep.TLSVerifyPort = mismatchPort
	if err := database.UpdateDeployment(ctx, dep); err != nil {
		t.Fatal(err)
	}

	failLog, err := engine.DeployTarget(ctx, dep.ID, model.TriggerManual)
	if err == nil {
		t.Fatal("expected DeployTarget to fail on TLS fingerprint mismatch")
	}
	if failLog == nil || failLog.Status != model.JobStatusFailed || failLog.TLSVerified {
		t.Fatalf("expected failed DeployLog, got %+v", failLog)
	}
	if failLog.TLSObservedFP != mismatchFP {
		t.Fatalf("observed fp = %q, want %q", failLog.TLSObservedFP, mismatchFP)
	}

	updatedDep, err := database.GetDeployment(ctx, dep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedDep.LastStatus != model.JobStatusFailed {
		t.Fatalf("deployment last_status = %q, want failed", updatedDep.LastStatus)
	}

	events := notifier.Events()
	if len(events) != 1 || events[0].Event != model.WebhookEventDeployFailed {
		t.Fatalf("expected 1 deploy.failed event, got %+v", events)
	}
}

func TestFanoutCertificate_PerTargetIsolation(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)
	notifier := &spyNotifier{}
	tr := deploy.NewTransport(database, cipher, redactor, nil)
	engine := deploy.NewEngine(database, tr, notifier, redactor, nil)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	matchPEM, matchFP := tlsServerCertPEMAndFP(t, ts)
	_, privPEM, _ := generateSelfSignedCertPEM(t, "multi.example.com")
	cert := seedCertWithFiles(t, database, cipher, "multi.example.com", matchPEM, privPEM, matchFP)

	priv1, pub1 := generateClientSSHKeyPair(t, "")
	srvGood := newMockSSHServer(t, pub1, "")
	srvGood.SetExecHandler(func(cmd string, stdin []byte) (string, string, int) {
		return "ok", "", 0
	})
	hostGood := createSSHTestHost(t, database, cipher, srvGood, model.HostAuthKey, priv1, "", "", model.HostKeyPolicyTOFU, "")

	priv2, pub2 := generateClientSSHKeyPair(t, "")
	srvFail := newMockSSHServer(t, pub2, "")
	failExit := 1
	srvFail.SetExecHandler(func(cmd string, stdin []byte) (string, string, int) {
		return "", "reload failed: boom", failExit
	})
	hostFail := createSSHTestHost(t, database, cipher, srvFail, model.HostAuthKey, priv2, "", "", model.HostKeyPolicyTOFU, "")

	goodDir := filepath.Join(t.TempDir(), "good")
	failDir := filepath.Join(t.TempDir(), "fail")
	disabledDir := filepath.Join(t.TempDir(), "disabled")

	tlsHost, tlsPort := splitHostPortInt(t, ts.URL)

	depFail := &model.Deployment{
		CertificateID:    cert.ID,
		HostID:           hostFail.ID,
		Name:             "target-fail",
		Template:         model.DeployTemplateCaddyDocker,
		Enabled:          true,
		FullchainPath:    filepath.Join(failDir, "fullchain.pem"),
		PrivkeyPath:      filepath.Join(failDir, "privkey.pem"),
		ReloadMode:       model.ReloadModeDockerExec,
		TLSVerifyEnabled: false,
	}
	depGood := &model.Deployment{
		CertificateID:    cert.ID,
		HostID:           hostGood.ID,
		Name:             "target-good",
		Template:         model.DeployTemplateCaddyDocker,
		Enabled:          true,
		FullchainPath:    filepath.Join(goodDir, "fullchain.pem"),
		PrivkeyPath:      filepath.Join(goodDir, "privkey.pem"),
		ReloadMode:       model.ReloadModeDockerExec,
		TLSVerifyEnabled: true,
		TLSVerifyHost:    tlsHost,
		TLSVerifyPort:    tlsPort,
		TLSVerifySNI:     "example.com",
	}
	depDisabled := &model.Deployment{
		CertificateID:    cert.ID,
		HostID:           hostGood.ID,
		Name:             "target-disabled",
		Template:         model.DeployTemplateCaddyDocker,
		Enabled:          false,
		FullchainPath:    filepath.Join(disabledDir, "fullchain.pem"),
		PrivkeyPath:      filepath.Join(disabledDir, "privkey.pem"),
		ReloadMode:       model.ReloadModeNone,
		TLSVerifyEnabled: false,
	}

	for _, d := range []*model.Deployment{depFail, depGood, depDisabled} {
		if _, err := database.CreateDeployment(ctx, d); err != nil {
			t.Fatal(err)
		}
	}

	err := engine.FanoutCertificate(ctx, cert.ID, model.TriggerAuto, nil)
	if err == nil {
		t.Fatal("expected FanoutCertificate to return error when 1 target fails")
	}

	gotGood, _ := database.GetDeployment(ctx, depGood.ID)
	gotFail, _ := database.GetDeployment(ctx, depFail.ID)
	gotDisabled, _ := database.GetDeployment(ctx, depDisabled.ID)

	if gotGood.LastStatus != model.JobStatusSuccess {
		t.Fatalf("good target status = %q, want success (isolation broken)", gotGood.LastStatus)
	}
	if gotFail.LastStatus != model.JobStatusFailed {
		t.Fatalf("fail target status = %q, want failed", gotFail.LastStatus)
	}
	if gotDisabled.LastStatus != model.JobStatusPending {
		t.Fatalf("disabled target status = %q, want pending", gotDisabled.LastStatus)
	}
	if _, statErr := os.Stat(filepath.Join(disabledDir, "fullchain.pem")); !os.IsNotExist(statErr) {
		t.Fatalf("disabled target should not have written files")
	}

	events := notifier.Events()
	hasFail := false
	hasDeployed := false
	for _, ev := range events {
		if ev.Event == model.WebhookEventDeployFailed {
			hasFail = true
		}
		if ev.Event == model.WebhookEventCertDeployed {
			hasDeployed = true
		}
	}
	if !hasFail || hasDeployed {
		t.Fatalf("expected deploy.failed without cert.deployed, got %+v", events)
	}

	// Fix failing target -> fanout succeeds and emits cert.deployed once
	notifier.Reset()
	failExit = 0
	if err := engine.FanoutCertificate(ctx, cert.ID, model.TriggerAuto, nil); err != nil {
		t.Fatalf("expected full fanout success, got %v", err)
	}
	events2 := notifier.Events()
	if len(events2) != 1 || events2[0].Event != model.WebhookEventCertDeployed {
		t.Fatalf("expected single cert.deployed event, got %+v", events2)
	}
}

func TestCaddyDockerReloadCmdAndContainerValidation(t *testing.T) {
	badNames := []string{
		"",
		"caddy; rm -rf /",
		"caddy$(whoami)",
		"caddy' && id",
		"-leadingdash",
	}
	for _, name := range badNames {
		if err := model.ValidateContainerName(name); err == nil {
			t.Fatalf("expected ValidateContainerName(%q) to fail", name)
		}
	}
	if err := model.ValidateContainerName("caddy-prod_01.edge"); err != nil {
		t.Fatalf("unexpected error for valid container name: %v", err)
	}

	cmd := model.DefaultCaddyReloadCmd("caddy-edge", "/etc/caddy/Caddyfile")
	want := "docker exec 'caddy-edge' caddy reload --config '/etc/caddy/Caddyfile' --force"
	if cmd != want {
		t.Fatalf("DefaultCaddyReloadCmd = %q, want %q", cmd, want)
	}
}

func TestEngine_LocalDirAdminAPIAndWebhookReload(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)
	notifier := &spyNotifier{}
	tr := deploy.NewTransport(database, cipher, redactor, nil)
	engine := deploy.NewEngine(database, tr, notifier, redactor, nil)

	cert := seedCertWithFiles(t, database, cipher, "local.example.com", nil, nil, "")
	localHost, err := database.GetLocalHost(ctx)
	if err != nil {
		t.Fatal(err)
	}

	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte("local.example.com {\n  respond \"ok\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	localHost.CaddyHostCaddyfile = caddyfilePath
	if err := database.UpdateHost(ctx, localHost); err != nil {
		t.Fatal(err)
	}

	var adminContentType, adminBody string
	adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/load" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		adminContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		adminBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer adminSrv.Close()

	var webhookCalled bool
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalled = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhookSrv.Close()

	outDir := t.TempDir()
	depAdmin := &model.Deployment{
		CertificateID:    cert.ID,
		HostID:           localHost.ID,
		Name:             "local-admin-api",
		Template:         model.DeployTemplateLocalDir,
		Enabled:          true,
		FullchainPath:    filepath.Join(outDir, "fullchain.pem"),
		PrivkeyPath:      filepath.Join(outDir, "privkey.pem"),
		ReloadMode:       model.ReloadModeCaddyAdminAPI,
		ReloadWebhookURL: adminSrv.URL + "/load",
		TLSVerifyEnabled: false,
	}
	if _, err := database.CreateDeployment(ctx, depAdmin); err != nil {
		t.Fatal(err)
	}

	log1, err := engine.DeployTarget(ctx, depAdmin.ID, model.TriggerManual)
	if err != nil {
		t.Fatalf("caddy_admin_api deploy failed: %v", err)
	}
	if log1.Status != model.JobStatusSuccess || adminContentType != "text/caddyfile" || !strings.Contains(adminBody, "local.example.com") {
		t.Fatalf("unexpected admin api call: ct=%q body=%q log=%+v", adminContentType, adminBody, log1)
	}

	depHook := &model.Deployment{
		CertificateID:    cert.ID,
		HostID:           localHost.ID,
		Name:             "local-webhook",
		Template:         model.DeployTemplateLocalDir,
		Enabled:          true,
		FullchainPath:    filepath.Join(outDir, "fullchain2.pem"),
		PrivkeyPath:      filepath.Join(outDir, "privkey2.pem"),
		ReloadMode:       model.ReloadModeWebhook,
		ReloadWebhookURL: webhookSrv.URL,
		TLSVerifyEnabled: false,
	}
	if _, err := database.CreateDeployment(ctx, depHook); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.DeployTarget(ctx, depHook.ID, model.TriggerManual); err != nil {
		t.Fatalf("webhook reload deploy failed: %v", err)
	}
	if !webhookCalled {
		t.Fatal("expected webhook reload endpoint to be called")
	}
}
