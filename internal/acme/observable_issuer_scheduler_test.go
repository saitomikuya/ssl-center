package acme

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"ssl-center/internal/model"
)

type testJobBroker struct {
	mu     sync.Mutex
	subs   map[int64][]chan model.CertJobSSEEvent
	events map[int64][]model.CertJobSSEEvent
}

func newTestJobBroker() *testJobBroker {
	return &testJobBroker{
		subs:   make(map[int64][]chan model.CertJobSSEEvent),
		events: make(map[int64][]model.CertJobSSEEvent),
	}
}

func (b *testJobBroker) Publish(jobID int64, evt model.CertJobSSEEvent) {
	b.mu.Lock()
	b.events[jobID] = append(b.events[jobID], evt)
	chs := append([]chan model.CertJobSSEEvent(nil), b.subs[jobID]...)
	b.mu.Unlock()
	for _, ch := range chs {
		select {
		case ch <- evt:
		default:
		}
	}
}

func (b *testJobBroker) Subscribe(ctx context.Context, jobID int64) (<-chan model.CertJobSSEEvent, func()) {
	ch := make(chan model.CertJobSSEEvent, 64)
	b.mu.Lock()
	b.subs[jobID] = append(b.subs[jobID], ch)
	b.mu.Unlock()
	return ch, func() {}
}

func (b *testJobBroker) Events(jobID int64) []model.CertJobSSEEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]model.CertJobSSEEvent, len(b.events[jobID]))
	copy(out, b.events[jobID])
	return out
}

// startMockUDPDNSServer starts a minimal RFC 1035 UDP DNS TXT responder on 127.0.0.1:0.
func startMockUDPDNSServer(t *testing.T, getTXT func(qname string) []string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			pkt := buf[:n]
			qname, qend := parseDNSQName(pkt, 12)
			if qend+4 > n {
				continue
			}
			qtype := binary.BigEndian.Uint16(pkt[qend : qend+2])
			qclass := binary.BigEndian.Uint16(pkt[qend+2 : qend+4])

			var txts []string
			if qtype == 16 { // TXT
				txts = getTXT(strings.ToLower(strings.TrimSuffix(qname, ".")))
			}

			resp := buildDNSTXTResponse(pkt[:12], pkt[12:qend+4], qtype, qclass, txts)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func parseDNSQName(pkt []byte, offset int) (string, int) {
	var labels []string
	i := offset
	for i < len(pkt) {
		l := int(pkt[i])
		i++
		if l == 0 {
			break
		}
		if i+l > len(pkt) {
			break
		}
		labels = append(labels, string(pkt[i:i+l]))
		i += l
	}
	return strings.Join(labels, "."), i
}

func buildDNSTXTResponse(reqHdr, question []byte, qtype, qclass uint16, txts []string) []byte {
	var resp []byte
	resp = append(resp, reqHdr[0], reqHdr[1]) // ID
	resp = append(resp, 0x81, 0x80)           // QR=1, RD=1, RA=1, RCODE=0
	resp = append(resp, 0x00, 0x01)           // QDCOUNT=1
	ansCount := make([]byte, 2)
	binary.BigEndian.PutUint16(ansCount, uint16(len(txts)))
	resp = append(resp, ansCount...) // ANCOUNT
	resp = append(resp, 0, 0, 0, 0)  // NSCOUNT, ARCOUNT
	resp = append(resp, question...)

	for _, txt := range txts {
		// Name pointer to offset 12 (0xC00C).
		resp = append(resp, 0xC0, 0x0C)
		var rrHdr [10]byte
		binary.BigEndian.PutUint16(rrHdr[0:2], qtype)
		binary.BigEndian.PutUint16(rrHdr[2:4], qclass)
		binary.BigEndian.PutUint32(rrHdr[4:8], 60)
		binary.BigEndian.PutUint16(rrHdr[8:10], uint16(1+len(txt)))
		resp = append(resp, rrHdr[:]...)
		resp = append(resp, byte(len(txt)))
		resp = append(resp, []byte(txt)...)
	}
	return resp
}

func TestWaitDNSPropagation_AuthoritativeAndRecursiveUDP(t *testing.T) {
	var ready atomic.Bool
	expected := "acme-prop-token-value-123"
	addr := startMockUDPDNSServer(t, func(qname string) []string {
		if ready.Load() && qname == "_acme-challenge.example.com" {
			return []string{expected}
		}
		return nil
	})

	go func() {
		time.Sleep(120 * time.Millisecond)
		ready.Store(true)
	}()

	var authCalls atomic.Int32
	authCheck := func(fqdn, value string) (bool, error) {
		authCalls.Add(1)
		return ready.Load() && value == expected, nil
	}

	cfg := PropagationConfig{
		RecursiveResolvers:  []string{addr},
		Timeout:             3 * time.Second,
		Interval:            40 * time.Millisecond,
		CheckAuthoritative:  true,
		MinRecursiveSuccess: 1,
	}

	ok, err := WaitDNSPropagation(context.Background(), cfg, "_acme-challenge.example.com.", expected, authCheck, nil)
	if err != nil || !ok {
		t.Fatalf("expected propagation success, got ok=%v err=%v", ok, err)
	}
	if authCalls.Load() < 2 {
		t.Fatalf("expected retries before propagation, authCalls=%d", authCalls.Load())
	}
}

func seedTestCAAndDNS(t *testing.T, env *testEnv, dnsSecret string) (*model.CAAccount, *model.DNSCredential) {
	t.Helper()
	ctx := context.Background()

	priv, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pemStr := string(certcrypto.PEMEncode(priv))
	encCAKey, err := env.cipher.Encrypt(pemStr, aadCAKeyEnc)
	if err != nil {
		t.Fatalf("Encrypt CA key: %v", err)
	}
	env.redactor.Add(pemStr)

	ca := &model.CAAccount{
		Name:         "Test CA",
		Provider:     model.CAProviderLetsEncrypt,
		Environment:  model.CAEnvStaging,
		Email:        "test@example.com",
		DirectoryURL: LetsEncryptStagingURL,
		ACMEKeyEnc:   encCAKey,
		AccountURI:   "https://acme.example/acct/1",
		IsDefault:    true,
		Status:       model.CAStatusActive,
	}
	if _, err := env.db.CreateCAAccount(ctx, ca); err != nil {
		t.Fatalf("CreateCAAccount: %v", err)
	}

	env.redactor.Add(dnsSecret)
	dnsCfgJSON, _ := json.Marshal(model.CloudflareCredConfig{APIToken: dnsSecret})
	encDNS, err := env.cipher.Encrypt(string(dnsCfgJSON), aadDNSConfigEnc)
	if err != nil {
		t.Fatalf("Encrypt DNS config: %v", err)
	}
	cred := &model.DNSCredential{
		Name:      "Test CF",
		Provider:  model.DNSProviderCloudflare,
		ConfigEnc: encDNS,
	}
	if _, err := env.db.CreateDNSCredential(ctx, cred); err != nil {
		t.Fatalf("CreateDNSCredential: %v", err)
	}
	return ca, cred
}

func TestObservableIssuer_6Stages_SSE_Permissions_SingleFlight_And_Redaction(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	const secretToken = "super-secret-cf-token-abc"
	ca, cred := seedTestCAAndDNS(t, env, secretToken)

	// Mock Cloudflare API for Present/CleanUp.
	dnsSrv := startMockCFForIssuer(t, secretToken)
	caSvc := NewCAService(env.db, env.cipher, env.redactor)
	dnsSvc := NewDNSService(env.db, env.cipher, env.redactor,
		WithDNSHTTPClient(dnsSrv.Client()),
		WithCloudflareBaseURL(dnsSrv.URL),
	)

	cert := &model.Certificate{
		Name:            "Wildcard Example",
		Domain:          "*.example.com",
		SANsJSON:        `["example.com","*.example.com"]`,
		CAAccountID:     ca.ID,
		DNSCredentialID: cred.ID,
		KeyType:         model.KeyTypeEC256,
		RenewBeforeDays: 30,
		AutoRenew:       true,
	}
	if _, err := env.db.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	broker := newTestJobBroker()
	deploy := &mockDeployTrigger{}
	notifier := &mockNotifier{}
	fixedNow := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(fixedNow)

	propAddr := startMockUDPDNSServer(t, func(qname string) []string {
		return nil
	})
	_ = propAddr

	var presentCalled, preCheckCalled, cleanUpCalled bool
	orderFn := func(
		ctx context.Context,
		_ *model.CAAccount,
		_ *ACMEUser,
		domains []string,
		keyType certcrypto.KeyType,
		obs *ObservableDNSProvider,
		tracker *StageTracker,
	) (*certificate.Resource, error) {
		tracker.Logf("Simulating ACME order with leaked secret %s", secretToken)
		for _, d := range domains {
			if err := obs.Present(d, "tok-"+d, "keyauth-"+d); err != nil {
				return nil, err
			}
			presentCalled = true
		}
		for _, d := range domains {
			info := dns01.GetChallengeInfo(d, "keyauth-"+d)
			ok, err := obs.PreCheck(d, info.EffectiveFQDN, info.Value, func(fqdn, value string) (bool, error) {
				return true, nil
			})
			if err != nil || !ok {
				if err == nil {
					err = errors.New("precheck failed")
				}
				return nil, err
			}
			preCheckCalled = true
		}
		for _, d := range domains {
			if err := obs.CleanUp(d, "tok-"+d, "keyauth-"+d); err != nil {
				return nil, err
			}
			cleanUpCalled = true
		}
		return generateTestCertResource(t, domains, fixedNow, fixedNow.Add(90*24*time.Hour)), nil
	}

	propCfg := PropagationConfig{
		RecursiveResolvers:  []string{"127.0.0.1:53"},
		Timeout:             2 * time.Second,
		Interval:            10 * time.Millisecond,
		CheckAuthoritative:  true,
		MinRecursiveSuccess: 1,
		LookupTXT: func(ctx context.Context, resolverAddr, fqdn string) ([]string, error) {
			// Return matching TXT values for both domains.
			i1 := dns01.GetChallengeInfo("*.example.com", "keyauth-*.example.com")
			i2 := dns01.GetChallengeInfo("example.com", "keyauth-example.com")
			return []string{i1.Value, i2.Value}, nil
		},
	}

	issuer := NewIssuer(
		env.db, env.cfg, caSvc, dnsSvc, env.redactor, broker, deploy, notifier,
		WithACMEOrderFunc(orderFn),
		WithPropagationConfig(propCfg),
		WithIssuerClock(clk),
	)

	job, err := issuer.IssueSync(ctx, cert.ID, model.TriggerManual)
	if err != nil {
		t.Fatalf("IssueSync: %v", err)
	}
	if !presentCalled || !preCheckCalled || !cleanUpCalled {
		t.Fatalf("expected Present/PreCheck/CleanUp calls, got %v/%v/%v", presentCalled, preCheckCalled, cleanUpCalled)
	}
	if job.Status != model.JobStatusSuccess {
		t.Fatalf("expected job success, got status=%s err=%s", job.Status, job.ErrorMessage)
	}
	if strings.Contains(job.Logs, secretToken) {
		t.Fatalf("expected DNS secret token to be redacted in job logs: %s", job.Logs)
	}
	if !strings.Contains(job.Logs, "***REDACTED***") {
		t.Fatalf("expected ***REDACTED*** marker in logs: %s", job.Logs)
	}

	// Verify all 6 stages are success.
	var stages []model.CertJobStage
	if err := json.Unmarshal([]byte(job.StagesJSON), &stages); err != nil {
		t.Fatalf("unmarshal StagesJSON: %v", err)
	}
	if len(stages) != 6 {
		t.Fatalf("expected 6 stages, got %d", len(stages))
	}
	for i, s := range stages {
		if s.Stage != model.AllCertStages[i] || s.Status != model.JobStatusSuccess {
			t.Fatalf("stage[%d] = %+v, want stage=%s status=success", i, s, model.AllCertStages[i])
		}
	}

	// Verify SSE broker captured stage, log, and terminal done events.
	events := broker.Events(job.ID)
	var hasStage, hasLog, hasDone bool
	for _, e := range events {
		switch e.Type {
		case "stage":
			hasStage = true
		case "log":
			hasLog = true
			if strings.Contains(e.LogLine, secretToken) {
				t.Fatalf("SSE log line leaked secret: %s", e.LogLine)
			}
		case "done":
			hasDone = true
		}
	}
	if !hasStage || !hasLog || !hasDone {
		t.Fatalf("expected stage/log/done SSE events, got stage=%v log=%v done=%v", hasStage, hasLog, hasDone)
	}

	// Verify PEM files & permissions on disk.
	certDir := env.cfg.CertDir(cert.ID)
	checkMode := func(name string, want os.FileMode) []byte {
		p := filepath.Join(certDir, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s perm = %o, want %o", p, info.Mode().Perm(), want)
		}
		b, err := os.ReadFile(p)
		if err != nil || len(b) == 0 {
			t.Fatalf("read %s: err=%v len=%d", p, err, len(b))
		}
		return b
	}
	fullchain := checkMode("fullchain.pem", 0o644)
	_ = checkMode("privkey.pem", 0o600)
	_ = checkMode("issuer.pem", 0o644)

	expectedFP, err := model.ParseLeafFingerprintSHA256(fullchain)
	if err != nil {
		t.Fatalf("ParseLeafFingerprintSHA256: %v", err)
	}

	// Verify DB certificate metadata updated.
	updatedCert, err := env.db.GetCertificate(ctx, cert.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if updatedCert.Status != model.CertStatusValid || updatedCert.FingerprintSHA256 != expectedFP {
		t.Fatalf("unexpected updated cert: status=%s fp=%s wantFP=%s", updatedCert.Status, updatedCert.FingerprintSHA256, expectedFP)
	}

	// Verify DeployTrigger.FanoutCertificate called.
	calls := deploy.Calls()
	if len(calls) != 1 || calls[0].CertID != cert.ID || calls[0].CertJobID == nil || *calls[0].CertJobID != job.ID {
		t.Fatalf("unexpected fanout calls: %+v", calls)
	}

	// Verify single-flight lock rejects concurrent issuance on same cert_id.
	blockCh := make(chan struct{})
	startedCh := make(chan struct{})
	blockingIssuer := NewIssuer(
		env.db, env.cfg, caSvc, dnsSvc, env.redactor, broker, deploy, notifier,
		WithACMEOrderFunc(func(ctx context.Context, _ *model.CAAccount, _ *ACMEUser, domains []string, _ certcrypto.KeyType, _ *ObservableDNSProvider, _ *StageTracker) (*certificate.Resource, error) {
			close(startedCh)
			<-blockCh
			return generateTestCertResource(t, domains, fixedNow, fixedNow.Add(90*24*time.Hour)), nil
		}),
	)
	if _, err := blockingIssuer.StartIssueAsync(ctx, cert.ID, model.TriggerManual); err != nil {
		t.Fatalf("StartIssueAsync first: %v", err)
	}
	<-startedCh
	if _, err := blockingIssuer.StartIssueAsync(ctx, cert.ID, model.TriggerManual); !errors.Is(err, ErrIssuanceInProgress) {
		t.Fatalf("expected ErrIssuanceInProgress on concurrent call, got %v", err)
	}
	close(blockCh)
	blockingIssuer.Wait()
}

func TestScheduler_Backoff_ExpiringSoon_Inspect_And_Maintenance(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	ca, cred := seedTestCAAndDNS(t, env, "cf-token-scheduler-test")
	dnsSrv := startMockCFForIssuer(t, "cf-token-scheduler-test")

	caSvc := NewCAService(env.db, env.cipher, env.redactor)
	dnsSvc := NewDNSService(env.db, env.cipher, env.redactor,
		WithDNSHTTPClient(dnsSrv.Client()),
		WithCloudflareBaseURL(dnsSrv.URL),
	)

	startTime := time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC)
	clk := newFakeClock(startTime)
	notifier := &mockNotifier{}
	deploy := &mockDeployTrigger{}

	// Verify NextInspectTime in Asia/Shanghai.
	shLoc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		shLoc = time.FixedZone("CST", 8*3600)
	}
	env.cfg.TZ = shLoc.String()
	nowSH := time.Date(2026, 11, 26, 4, 0, 0, 0, shLoc)
	nextSH := NextInspectTime(nowSH, "03:00", shLoc)
	if nextSH.Day() != 27 || nextSH.Hour() != 3 || nextSH.Minute() != 0 {
		t.Fatalf("unexpected NextInspectTime: %v", nextSH)
	}

	// 1. Cert due for renewal (unissued, auto_renew=1) -> will fail to test 15m -> 1h -> 6h backoff.
	failCert := &model.Certificate{
		Name:            "Fail Cert",
		Domain:          "fail.example.com",
		SANsJSON:        `["fail.example.com"]`,
		CAAccountID:     ca.ID,
		DNSCredentialID: cred.ID,
		KeyType:         model.KeyTypeEC256,
		RenewBeforeDays: 30,
		AutoRenew:       true,
	}
	if _, err := env.db.CreateCertificate(ctx, failCert); err != nil {
		t.Fatalf("CreateCertificate failCert: %v", err)
	}

	// 2. Valid cert with 60 days left (auto_renew=1) -> must NOT be renewed.
	validNotAfter := startTime.Add(60 * 24 * time.Hour)
	validCert := &model.Certificate{
		Name:              "Valid Cert",
		Domain:            "valid.example.com",
		SANsJSON:          `["valid.example.com"]`,
		CAAccountID:       ca.ID,
		DNSCredentialID:   cred.ID,
		KeyType:           model.KeyTypeEC256,
		RenewBeforeDays:   30,
		AutoRenew:         true,
		Status:            model.CertStatusValid,
		FingerprintSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NotAfter:          &validNotAfter,
	}
	if _, err := env.db.CreateCertificate(ctx, validCert); err != nil {
		t.Fatalf("CreateCertificate validCert: %v", err)
	}
	if err := env.db.UpdateCertificate(ctx, validCert); err != nil {
		t.Fatalf("UpdateCertificate validCert: %v", err)
	}

	// 3. Expiring cert with 5 days left (auto_renew=0) -> must emit cert.expiring_soon ONCE (deduplicated).
	expNotAfter := startTime.Add(5 * 24 * time.Hour)
	expCert := &model.Certificate{
		Name:              "Expiring Cert",
		Domain:            "expiring.example.com",
		SANsJSON:          `["expiring.example.com"]`,
		CAAccountID:       ca.ID,
		DNSCredentialID:   cred.ID,
		KeyType:           model.KeyTypeEC256,
		RenewBeforeDays:   30,
		AutoRenew:         false,
		Status:            model.CertStatusValid,
		FingerprintSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		NotAfter:          &expNotAfter,
	}
	if _, err := env.db.CreateCertificate(ctx, expCert); err != nil {
		t.Fatalf("CreateCertificate expCert: %v", err)
	}
	if err := env.db.UpdateCertificate(ctx, expCert); err != nil {
		t.Fatalf("UpdateCertificate expCert: %v", err)
	}

	var attemptedDomains []string
	var attemptMu sync.Mutex
	issuer := NewIssuer(
		env.db, env.cfg, caSvc, dnsSvc, env.redactor, nil, deploy, notifier,
		WithIssuerClock(clk),
		WithACMEOrderFunc(func(_ context.Context, _ *model.CAAccount, _ *ACMEUser, domains []string, _ certcrypto.KeyType, _ *ObservableDNSProvider, _ *StageTracker) (*certificate.Resource, error) {
			attemptMu.Lock()
			attemptedDomains = append(attemptedDomains, domains[0])
			attemptMu.Unlock()
			return nil, errors.New("simulated ACME CA error")
		}),
	)

	sched := NewScheduler(env.db, env.cfg, issuer, notifier, nil, WithSchedulerClock(clk))

	// Initial inspect: attempts fail.example.com once (-> retry_count=1, +15m), skips valid.example.com,
	// and emits cert.expiring_soon for expiring.example.com.
	if err := sched.InspectOnce(ctx); err != nil {
		t.Fatalf("InspectOnce #1: %v", err)
	}

	attemptMu.Lock()
	if len(attemptedDomains) != 1 || attemptedDomains[0] != "fail.example.com" {
		t.Fatalf("expected only fail.example.com attempted, got %v", attemptedDomains)
	}
	attemptMu.Unlock()

	c1, _ := env.db.GetCertificate(ctx, failCert.ID)
	if c1.RetryCount != 1 || c1.NextRetryAt == nil || !c1.NextRetryAt.Equal(startTime.Add(15*time.Minute)) {
		t.Fatalf("after 1st failure: retry_count=%d next_retry=%v, want 1 and +15m", c1.RetryCount, c1.NextRetryAt)
	}

	// Second InspectOnce shortly after must NOT duplicate cert.expiring_soon and must respect future next_retry_at.
	if err := sched.InspectOnce(ctx); err != nil {
		t.Fatalf("InspectOnce #2: %v", err)
	}
	evts := notifier.Events()
	if len(evts) != 1 || evts[0].Event != model.WebhookEventCertExpiringSoon {
		t.Fatalf("expected exactly 1 cert.expiring_soon event, got %+v", evts)
	}

	// Advance +15m -> retry #1 fails -> next_retry_at = +1h.
	clk.Advance(15 * time.Minute)
	if err := sched.ProcessRetriesOnce(ctx); err != nil {
		t.Fatalf("ProcessRetriesOnce #1: %v", err)
	}
	c1, _ = env.db.GetCertificate(ctx, failCert.ID)
	if c1.RetryCount != 2 || c1.NextRetryAt == nil || !c1.NextRetryAt.Equal(clk.Now().Add(1*time.Hour)) {
		t.Fatalf("after 2nd failure: retry_count=%d next_retry=%v, want 2 and +1h", c1.RetryCount, c1.NextRetryAt)
	}

	// Advance +1h -> retry #2 fails -> next_retry_at = +6h.
	clk.Advance(1 * time.Hour)
	if err := sched.ProcessRetriesOnce(ctx); err != nil {
		t.Fatalf("ProcessRetriesOnce #2: %v", err)
	}
	c1, _ = env.db.GetCertificate(ctx, failCert.ID)
	if c1.RetryCount != 3 || c1.NextRetryAt == nil || !c1.NextRetryAt.Equal(clk.Now().Add(6*time.Hour)) {
		t.Fatalf("after 3rd failure: retry_count=%d next_retry=%v, want 3 and +6h", c1.RetryCount, c1.NextRetryAt)
	}

	// Still no cert.issue_failed emitted before 3rd retry fails.
	for _, e := range notifier.Events() {
		if e.Event == model.WebhookEventCertIssueFailed {
			t.Fatalf("unexpected early cert.issue_failed before 6h retry exhausted")
		}
	}

	// Advance +6h -> retry #3 fails -> stops auto-retry (next_retry_at = nil) and emits cert.issue_failed!
	clk.Advance(6 * time.Hour)
	if err := sched.ProcessRetriesOnce(ctx); err != nil {
		t.Fatalf("ProcessRetriesOnce #3: %v", err)
	}
	c1, _ = env.db.GetCertificate(ctx, failCert.ID)
	if c1.NextRetryAt != nil {
		t.Fatalf("expected next_retry_at=nil after 3 retries exhausted, got %v", c1.NextRetryAt)
	}

	var issueFailedCount int
	for _, e := range notifier.Events() {
		if e.Event == model.WebhookEventCertIssueFailed && e.Certificate != nil && e.Certificate.ID == failCert.ID {
			issueFailedCount++
		}
	}
	if issueFailedCount != 1 {
		t.Fatalf("expected 1 cert.issue_failed webhook after 3 retries exhausted, got %d", issueFailedCount)
	}

	// Verify Pause/Resume halts TriggerInspectNow cleanly.
	sched.Pause()
	if err := sched.TriggerInspectNow(ctx); err == nil {
		t.Fatal("expected TriggerInspectNow error while paused")
	}
	sched.Resume()
	if err := sched.ReloadSchedule(ctx); err != nil {
		t.Fatalf("ReloadSchedule: %v", err)
	}

	// Verify Scheduler.Run lifecycle + ReloadSchedule cleanly stops on context cancel.
	runCtx, cancelRun := context.WithCancel(context.Background())
	doneRun := make(chan struct{})
	go func() {
		defer close(doneRun)
		sched.Run(runCtx)
	}()
	if err := sched.ReloadSchedule(runCtx); err != nil {
		t.Fatalf("ReloadSchedule during Run: %v", err)
	}
	cancelRun()
	select {
	case <-doneRun:
	case <-time.After(2 * time.Second):
		t.Fatal("Scheduler.Run did not exit promptly after context cancel")
	}

	// Verify CleanupCertDir removes <DATA_DIR>/certs/cert_<id>/ artifacts.
	certDir := env.cfg.CertDir(failCert.ID)
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("MkdirAll certDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), []byte("dummy"), 0o644); err != nil {
		t.Fatalf("WriteFile dummy: %v", err)
	}
	failCert.CertDir = certDir
	CleanupCertDir(env.cfg, failCert)
	if _, err := os.Stat(certDir); !os.IsNotExist(err) {
		t.Fatalf("expected certDir %s to be removed, stat err=%v", certDir, err)
	}
}

func startMockCFForIssuer(t *testing.T, expectedToken string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	nextID := 0

	mux := http.NewServeMux()
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+expectedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"example.com"}],"result_info":{"page":1,"per_page":50,"total_pages":1}}`))
	})
	mux.HandleFunc("/zones/z1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		nextID++
		id := nextID
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"success":true,"result":{"id":"rec-%d"}}`, id)
	})
	mux.HandleFunc("/zones/z1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDefaultLookupTXT_ReportsTargetResolverInError(t *testing.T) {
	addr := startMockUDPDNSServer(t, func(qname string) []string {
		return nil
	})
	_, err := defaultLookupTXT(context.Background(), addr, "_acme-challenge.missing.example.com.")
	if err == nil {
		t.Fatal("expected lookup error when mock DNS returns no TXT records")
	}
	if !strings.Contains(err.Error(), addr) {
		t.Fatalf("expected error to reference queried resolver %q, got: %v", addr, err)
	}
}
