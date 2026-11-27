package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	appcrypto "ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// DefaultRecursiveResolvers are the public recursive DNS servers queried during TXT propagation checks.
var DefaultRecursiveResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"223.5.5.5:53",
}

var stageLabels = map[string]string{
	model.StageCreateOrder:     "创建订单",
	model.StageWriteDNSTXT:     "写入 DNS TXT",
	model.StageWaitPropagation: "等待传播",
	model.StageCAValidate:      "CA 校验签发",
	model.StageSaveCert:        "证书落盘",
	model.StageTriggerDeploy:   "触发关联部署",
}

// PropagationConfig configures authoritative and recursive DNS propagation checks.
type PropagationConfig struct {
	RecursiveResolvers  []string
	Timeout             time.Duration
	Interval            time.Duration
	CheckAuthoritative  bool
	MinRecursiveSuccess int
	LookupTXT           func(ctx context.Context, resolverAddr, fqdn string) ([]string, error)
}

func (c PropagationConfig) withDefaults() PropagationConfig {
	out := c
	if len(out.RecursiveResolvers) == 0 {
		out.RecursiveResolvers = append([]string(nil), DefaultRecursiveResolvers...)
	}
	if out.Timeout <= 0 {
		out.Timeout = 120 * time.Second
	}
	if out.Interval <= 0 {
		out.Interval = 3 * time.Second
	}
	if out.LookupTXT == nil {
		out.LookupTXT = defaultLookupTXT
	}
	return out
}

func defaultLookupTXT(ctx context.Context, resolverAddr, fqdn string) ([]string, error) {
	addr := strings.TrimSpace(resolverAddr)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	host := dns01.UnFqdn(fqdn)
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(dialCtx, network, addr)
		},
	}
	return r.LookupTXT(ctx, host)
}

// StageTracker tracks the 6 frozen ACME issuance stages and redacted live logs,
// persisting updates to SQLite and publishing SSE events via CertJobBroker.
type StageTracker struct {
	mu           sync.Mutex
	db           *db.DB
	broker       model.CertJobBroker
	redactor     *appcrypto.SecretRedactor
	job          *model.CertJob
	stages       []model.CertJobStage
	logs         strings.Builder
	redactWriter *appcrypto.RedactingWriter
	lineSink     *jobLineSink
	closed       bool
}

type jobLineSink struct {
	tracker *StageTracker
	buf     bytes.Buffer
}

func (s *jobLineSink) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.buf.Write(p)
	for {
		data := s.buf.Bytes()
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			break
		}
		line := string(data[:idx])
		s.buf.Next(idx + 1)
		s.tracker.emitRedactedLine(line)
	}
	return len(p), nil
}

func (s *jobLineSink) flushRemainder() {
	if s.buf.Len() == 0 {
		return
	}
	line := s.buf.String()
	s.buf.Reset()
	s.tracker.emitRedactedLine(line)
}

// NewStageTracker initializes a StageTracker for an active CertJob starting at create_order.
func NewStageTracker(database *db.DB, broker model.CertJobBroker, redactor *appcrypto.SecretRedactor, job *model.CertJob) *StageTracker {
	now := time.Now().UTC()
	stages := make([]model.CertJobStage, 0, len(model.AllCertStages))
	for _, st := range model.AllCertStages {
		status := model.JobStatusPending
		var startedAt *time.Time
		if st == model.StageCreateOrder {
			status = model.JobStatusRunning
			t := now
			startedAt = &t
		}
		stages = append(stages, model.CertJobStage{
			Stage:     st,
			Label:     stageLabels[st],
			Status:    status,
			StartedAt: startedAt,
		})
	}

	if redactor == nil {
		redactor = appcrypto.NewSecretRedactor()
	}

	t := &StageTracker{
		db:       database,
		broker:   broker,
		redactor: redactor,
		job:      job,
		stages:   stages,
	}
	t.lineSink = &jobLineSink{tracker: t}
	t.redactWriter = redactor.RedactingWriter(t.lineSink)

	if job.Logs != "" {
		t.logs.WriteString(job.Logs)
	}
	t.syncJobFieldsLocked()
	_ = t.db.UpdateCertJob(context.Background(), t.job)
	t.publishLocked("stage", "", "")
	return t
}

// Logf writes a timestamped log line through SecretRedactor to DB and SSE subscribers.
func (t *StageTracker) Logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	msg = strings.TrimRight(msg, "\r\n")
	if msg == "" {
		return
	}
	line := fmt.Sprintf("[%s] %s\n", time.Now().UTC().Format(time.RFC3339), msg)

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	_, _ = io.WriteString(t.redactWriter, line)
}

func (t *StageTracker) emitRedactedLine(line string) {
	// Called while t.mu is held (from Logf or flushClose).
	if line == "" {
		return
	}
	t.logs.WriteString(line)
	t.logs.WriteByte('\n')
	t.job.Logs = t.logs.String()
	_ = t.db.AppendCertJobLog(context.Background(), t.job.ID, line+"\n")

	if t.broker != nil {
		t.broker.Publish(t.job.ID, model.CertJobSSEEvent{
			Type:         "log",
			JobID:        t.job.ID,
			Status:       t.job.Status,
			CurrentStage: t.job.CurrentStage,
			LogLine:      line,
			Timestamp:    time.Now().UTC(),
		})
	}
}

// EnterStage completes any active earlier stage and marks targetStage as running.
func (t *StageTracker) EnterStage(targetStage, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UTC()
	targetIdx := stageIndex(targetStage)
	for i := range t.stages {
		if i < targetIdx && (t.stages[i].Status == model.JobStatusPending || t.stages[i].Status == model.JobStatusRunning) {
			t.stages[i].Status = model.JobStatusSuccess
			if t.stages[i].StartedAt == nil {
				ts := now
				t.stages[i].StartedAt = &ts
			}
			ts := now
			t.stages[i].FinishedAt = &ts
		}
		if i == targetIdx {
			t.stages[i].Status = model.JobStatusRunning
			if t.stages[i].StartedAt == nil {
				ts := now
				t.stages[i].StartedAt = &ts
			}
			if message != "" {
				t.stages[i].Message = t.redactor.Redact(message)
			}
		}
	}
	t.job.CurrentStage = targetStage
	t.syncJobFieldsLocked()
	_ = t.db.UpdateCertJob(context.Background(), t.job)
	t.publishLocked("stage", "", "")
}

// CompleteStage marks targetStage as succeeded.
func (t *StageTracker) CompleteStage(targetStage, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UTC()
	idx := stageIndex(targetStage)
	if idx >= 0 {
		t.stages[idx].Status = model.JobStatusSuccess
		if t.stages[idx].StartedAt == nil {
			ts := now
			t.stages[idx].StartedAt = &ts
		}
		ts := now
		t.stages[idx].FinishedAt = &ts
		if message != "" {
			t.stages[idx].Message = t.redactor.Redact(message)
		}
	}
	t.syncJobFieldsLocked()
	_ = t.db.UpdateCertJob(context.Background(), t.job)
	t.publishLocked("stage", "", "")
}

// Succeed flushes RedactingWriter, marks all stages complete, and emits the terminal "done" SSE event.
func (t *StageTracker) Succeed() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.flushWriterLocked()
	now := time.Now().UTC()
	for i := range t.stages {
		if t.stages[i].Status == model.JobStatusPending || t.stages[i].Status == model.JobStatusRunning {
			t.stages[i].Status = model.JobStatusSuccess
			if t.stages[i].StartedAt == nil {
				ts := now
				t.stages[i].StartedAt = &ts
			}
			ts := now
			t.stages[i].FinishedAt = &ts
		}
	}
	t.job.Status = model.JobStatusSuccess
	t.job.CurrentStage = model.StageTriggerDeploy
	t.job.ErrorMessage = ""
	t.job.FinishedAt = &now
	t.syncJobFieldsLocked()
	_ = t.db.UpdateCertJob(context.Background(), t.job)
	t.publishLocked("stage", "", "")
	t.publishLocked("done", "", "")
}

// Fail flushes RedactingWriter, marks the active stage failed, persists the error, and emits "done".
func (t *StageTracker) Fail(errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.flushWriterLocked()
	redactedErr := t.redactor.Redact(errMsg)
	now := time.Now().UTC()
	marked := false
	for i := range t.stages {
		if t.stages[i].Status == model.JobStatusRunning {
			t.stages[i].Status = model.JobStatusFailed
			ts := now
			t.stages[i].FinishedAt = &ts
			t.stages[i].Message = redactedErr
			t.job.CurrentStage = t.stages[i].Stage
			marked = true
			break
		}
	}
	if !marked {
		idx := stageIndex(t.job.CurrentStage)
		if idx < 0 {
			idx = 0
		}
		t.stages[idx].Status = model.JobStatusFailed
		if t.stages[idx].StartedAt == nil {
			ts := now
			t.stages[idx].StartedAt = &ts
		}
		ts := now
		t.stages[idx].FinishedAt = &ts
		t.stages[idx].Message = redactedErr
	}
	t.job.Status = model.JobStatusFailed
	t.job.ErrorMessage = redactedErr
	t.job.FinishedAt = &now
	t.syncJobFieldsLocked()
	_ = t.db.UpdateCertJob(context.Background(), t.job)
	t.publishLocked("stage", "", redactedErr)
	t.publishLocked("done", "", redactedErr)
}

// StagesSnapshot returns a copy of current stages.
func (t *StageTracker) StagesSnapshot() []model.CertJobStage {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]model.CertJobStage, len(t.stages))
	copy(out, t.stages)
	return out
}

func (t *StageTracker) flushWriterLocked() {
	if t.closed {
		return
	}
	if t.redactWriter != nil {
		_ = t.redactWriter.Flush()
		_ = t.redactWriter.Close()
	}
	if t.lineSink != nil {
		t.lineSink.flushRemainder()
	}
	t.closed = true
}

func (t *StageTracker) syncJobFieldsLocked() {
	b, _ := json.Marshal(t.stages)
	t.job.StagesJSON = string(b)
	t.job.Logs = t.logs.String()
}

func (t *StageTracker) publishLocked(evtType, logLine, errMsg string) {
	if t.broker == nil {
		return
	}
	stagesCopy := make([]model.CertJobStage, len(t.stages))
	copy(stagesCopy, t.stages)
	t.broker.Publish(t.job.ID, model.CertJobSSEEvent{
		Type:         evtType,
		JobID:        t.job.ID,
		Status:       t.job.Status,
		CurrentStage: t.job.CurrentStage,
		Stages:       stagesCopy,
		LogLine:      logLine,
		ErrorMessage: errMsg,
		Timestamp:    time.Now().UTC(),
	})
}

func stageIndex(stage string) int {
	for i, s := range model.AllCertStages {
		if s == stage {
			return i
		}
	}
	return -1
}

// ObservableDNSProvider wraps a challenge.Provider to record write_dns_txt, wait_propagation,
// and ca_validate stage transitions plus redacted logs, and enforces authoritative + recursive DNS checks.
type ObservableDNSProvider struct {
	inner   challenge.Provider
	tracker *StageTracker
	propCfg PropagationConfig

	mu             sync.Mutex
	enteredPresent bool
	enteredWait    bool
}

// NewObservableDNSProvider wraps inner with stage tracking and propagation configuration.
func NewObservableDNSProvider(inner challenge.Provider, tracker *StageTracker, propCfg PropagationConfig) *ObservableDNSProvider {
	return &ObservableDNSProvider{
		inner:   inner,
		tracker: tracker,
		propCfg: propCfg.withDefaults(),
	}
}

// Present delegates TXT record creation and transitions into write_dns_txt.
func (p *ObservableDNSProvider) Present(domain, token, keyAuth string) error {
	p.mu.Lock()
	first := !p.enteredPresent
	p.enteredPresent = true
	p.mu.Unlock()

	if first && p.tracker != nil {
		p.tracker.EnterStage(model.StageWriteDNSTXT, fmt.Sprintf("Writing TXT record for %s", domain))
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)
	if p.tracker != nil {
		p.tracker.Logf("Presenting DNS-01 TXT record: domain=%s fqdn=%s", domain, dns01.UnFqdn(info.EffectiveFQDN))
	}
	if err := p.inner.Present(domain, token, keyAuth); err != nil {
		if p.tracker != nil {
			p.tracker.Logf("Failed to present DNS-01 TXT record for %s: %v", domain, err)
		}
		return err
	}
	if p.tracker != nil {
		p.tracker.Logf("Presented DNS-01 TXT record for %s", dns01.UnFqdn(info.EffectiveFQDN))
	}
	return nil
}

// CleanUp delegates TXT record cleanup and logs the outcome.
func (p *ObservableDNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	if p.tracker != nil {
		p.tracker.Logf("Cleaning up DNS-01 TXT record: domain=%s fqdn=%s", domain, dns01.UnFqdn(info.EffectiveFQDN))
	}
	if err := p.inner.CleanUp(domain, token, keyAuth); err != nil {
		if p.tracker != nil {
			p.tracker.Logf("Failed to clean up DNS-01 TXT record for %s: %v", domain, err)
		}
		return err
	}
	if p.tracker != nil {
		p.tracker.Logf("Cleaned up DNS-01 TXT record for %s", dns01.UnFqdn(info.EffectiveFQDN))
	}
	return nil
}

// Timeout implements challenge.ProviderTimeout.
func (p *ObservableDNSProvider) Timeout() (timeout, interval time.Duration) {
	if pt, ok := p.inner.(challenge.ProviderTimeout); ok {
		return pt.Timeout()
	}
	return p.propCfg.Timeout, p.propCfg.Interval
}

// PreCheck combines authoritative NS checking (via lego's check callback) and recursive DNS resolvers
// (1.1.1.1:53, 8.8.8.8:53, 223.5.5.5:53 by default), transitioning wait_propagation -> ca_validate.
func (p *ObservableDNSProvider) PreCheck(domain, fqdn, value string, authCheck dns01.PreCheckFunc) (bool, error) {
	fqdn = normalizeChallengeFQDN(fqdn)
	p.mu.Lock()
	first := !p.enteredWait
	p.enteredWait = true
	p.mu.Unlock()

	if first && p.tracker != nil {
		p.tracker.EnterStage(model.StageWaitPropagation, fmt.Sprintf("Waiting for DNS propagation of %s", dns01.UnFqdn(fqdn)))
	}

	ok, err := WaitDNSPropagation(context.Background(), p.propCfg, fqdn, value, authCheck, p.tracker)
	if err != nil || !ok {
		return false, err
	}

	if p.tracker != nil {
		p.tracker.EnterStage(model.StageCAValidate, "Requesting CA challenge validation")
		p.tracker.Logf("DNS propagation verified for %s; requesting CA validation", dns01.UnFqdn(fqdn))
	}
	return true, nil
}

// WaitDNSPropagation polls authoritative NS (if enabled and authCheck != nil) and configured
// recursive DNS resolvers until the expected TXT record value is observed or timeout expires.
func WaitDNSPropagation(ctx context.Context, cfg PropagationConfig, fqdn, expectedValue string, authCheck dns01.PreCheckFunc, tracker *StageTracker) (bool, error) {
	cfg = cfg.withDefaults()
	deadline := time.Now().Add(cfg.Timeout)
	requiredRec := cfg.MinRecursiveSuccess
	if requiredRec <= 0 {
		if len(cfg.RecursiveResolvers) <= 2 {
			requiredRec = len(cfg.RecursiveResolvers)
		} else {
			requiredRec = 2
		}
	}

	if tracker != nil {
		tracker.Logf("Checking DNS propagation for %s across authoritative NS and %d recursive resolver(s): %s",
			dns01.UnFqdn(fqdn), len(cfg.RecursiveResolvers), strings.Join(cfg.RecursiveResolvers, ", "))
	}

	attempt := 0
	for {
		attempt++
		authOK := true
		if cfg.CheckAuthoritative && authCheck != nil {
			var err error
			authOK, err = authCheck(fqdn, expectedValue)
			if err != nil {
				authOK = false
				if tracker != nil {
					tracker.Logf("Propagation attempt #%d authoritative NS check error for %s: %v", attempt, dns01.UnFqdn(fqdn), err)
				}
			}
		}

		recSuccess := 0
		for _, resolver := range cfg.RecursiveResolvers {
			qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			txts, err := cfg.LookupTXT(qCtx, resolver, fqdn)
			cancel()
			if err == nil && containsTXTValue(txts, expectedValue) {
				recSuccess++
			} else if tracker != nil {
				if err != nil {
					tracker.Logf("Propagation attempt #%d resolver %s lookup error: %v", attempt, resolver, err)
				} else {
					tracker.Logf("Propagation attempt #%d resolver %s returned %d TXT record(s), waiting for target", attempt, resolver, len(txts))
				}
			}
		}

		if authOK && recSuccess >= requiredRec {
			if tracker != nil {
				tracker.Logf("DNS propagation succeeded for %s (authoritative=%v, recursive=%d/%d)",
					dns01.UnFqdn(fqdn), authOK, recSuccess, len(cfg.RecursiveResolvers))
			}
			return true, nil
		}

		if time.Now().After(deadline) {
			return false, fmt.Errorf("DNS propagation timeout for %s after %s (authoritative=%v, recursive=%d/%d)",
				dns01.UnFqdn(fqdn), cfg.Timeout, authOK, recSuccess, len(cfg.RecursiveResolvers))
		}

		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(cfg.Interval):
		}
	}
}

func containsTXTValue(records []string, target string) bool {
	for _, r := range records {
		if r == target || unquoteTXTValue(r) == target {
			return true
		}
	}
	return false
}
