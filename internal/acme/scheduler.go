package acme

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ssl-center/internal/config"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// SchedulerOption configures optional behavior on Scheduler.
type SchedulerOption func(*Scheduler)

// WithSchedulerClock overrides the clock used by Scheduler.
func WithSchedulerClock(clk model.Clock) SchedulerOption {
	return func(s *Scheduler) {
		if clk != nil {
			s.clock = clk
		}
	}
}

// WithRetryPollInterval overrides how frequently due retries are polled (default 30s).
func WithRetryPollInterval(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d > 0 {
			s.retryInterval = d
		}
	}
}

// Scheduler implements state-driven daily certificate inspection, failure retry polling,
// expiring-soon alerts, MaintenanceCoordinator pause/resume hooks, and model.ScheduleReloader.
type Scheduler struct {
	db            *db.DB
	cfg           *config.Config
	issuer        *Issuer
	notifier      model.Notifier
	clock         model.Clock
	retryInterval time.Duration

	paused atomic.Bool

	mu           sync.Mutex
	runCancels   map[uint64]context.CancelFunc
	nextCancelID uint64
	inflightWg   sync.WaitGroup
	reloadCh     chan struct{}
	inspectNowCh chan chan error
}

// NewScheduler constructs a Scheduler and optionally registers maintenance hooks.
func NewScheduler(
	database *db.DB,
	cfg *config.Config,
	issuer *Issuer,
	notifier model.Notifier,
	maint model.MaintenanceCoordinator,
	opts ...SchedulerOption,
) *Scheduler {
	s := &Scheduler{
		db:            database,
		cfg:           cfg,
		issuer:        issuer,
		notifier:      notifier,
		clock:         realClock{},
		retryInterval: 30 * time.Second,
		runCancels:    make(map[uint64]context.CancelFunc),
		reloadCh:      make(chan struct{}, 1),
		inspectNowCh:  make(chan chan error, 4),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if maint != nil {
		maint.RegisterSchedulerHook(s.Pause, s.Resume)
	}
	return s
}

// Pause halts scheduled inspections/retries and waits for active tasks to finish.
func (s *Scheduler) Pause() {
	s.paused.Store(true)
	s.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.runCancels))
	for _, c := range s.runCancels {
		cancels = append(cancels, c)
	}
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	s.inflightWg.Wait()
	if s.issuer != nil {
		s.issuer.Wait()
	}
}

// Resume re-enables scheduled inspections/retries after maintenance completes.
func (s *Scheduler) Resume() {
	s.paused.Store(false)
	select {
	case s.reloadCh <- struct{}{}:
	default:
	}
}

// ReloadSchedule implements model.ScheduleReloader to apply updated inspect_time immediately.
func (s *Scheduler) ReloadSchedule(ctx context.Context) error {
	select {
	case s.reloadCh <- struct{}{}:
	default:
	}
	return nil
}

// TriggerInspectNow implements model.ScheduleReloader to run an immediate inspection pass.
func (s *Scheduler) TriggerInspectNow(ctx context.Context) error {
	if s.paused.Load() {
		return fmt.Errorf("scheduler paused during maintenance")
	}
	return s.withWorkCtx(ctx, s.InspectOnce)
}

// Run executes the scheduler loop until ctx is canceled.
func (s *Scheduler) Run(ctx context.Context) {
	retryTicker := time.NewTicker(s.retryInterval)
	defer retryTicker.Stop()

	inspectTimer := s.newNextInspectTimer(ctx)
	defer inspectTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.reloadCh:
			if !inspectTimer.Stop() {
				select {
				case <-inspectTimer.C:
				default:
				}
			}
			inspectTimer = s.newNextInspectTimer(ctx)
		case respCh := <-s.inspectNowCh:
			var err error
			if !s.paused.Load() {
				err = s.withWorkCtx(ctx, s.InspectOnce)
			} else {
				err = fmt.Errorf("scheduler paused during maintenance")
			}
			if respCh != nil {
				respCh <- err
			}
		case <-inspectTimer.C:
			if !s.paused.Load() {
				_ = s.withWorkCtx(ctx, s.InspectOnce)
			}
			inspectTimer = s.newNextInspectTimer(ctx)
		case <-retryTicker.C:
			if !s.paused.Load() {
				_ = s.withWorkCtx(ctx, s.ProcessRetriesOnce)
			}
		}
	}
}

func (s *Scheduler) withWorkCtx(parent context.Context, fn func(context.Context) error) error {
	workCtx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	s.nextCancelID++
	id := s.nextCancelID
	if s.runCancels == nil {
		s.runCancels = make(map[uint64]context.CancelFunc)
	}
	s.runCancels[id] = cancel
	s.inflightWg.Add(1)
	s.mu.Unlock()

	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.runCancels, id)
		s.mu.Unlock()
		s.inflightWg.Done()
	}()

	if s.paused.Load() {
		return fmt.Errorf("scheduler paused during maintenance")
	}
	return fn(workCtx)
}

func (s *Scheduler) newNextInspectTimer(ctx context.Context) *time.Timer {
	inspectTime := "03:00"
	if settings, err := s.db.GetSettingsDTO(ctx); err == nil && settings.InspectTime != "" {
		inspectTime = settings.InspectTime
	}
	loc := time.UTC
	if s.cfg != nil {
		loc = s.cfg.Location()
	}
	now := s.clock.Now().In(loc)
	next := NextInspectTime(now, inspectTime, loc)
	delay := next.Sub(now)
	if delay < time.Second {
		delay = time.Second
	}
	return time.NewTimer(delay)
}

// NextInspectTime calculates the next wall-clock occurrence of "HH:MM" in loc strictly after now.
func NextInspectTime(now time.Time, inspectTime string, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	hour, minute := parseHourMinute(inspectTime)
	localNow := now.In(loc)
	candidate := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), hour, minute, 0, 0, loc)
	if !candidate.After(localNow) {
		candidate = candidate.AddDate(0, 0, 1)
	}
	return candidate
}

func parseHourMinute(raw string) (int, int) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) != 2 {
		return 3, 0
	}
	h, errH := strconv.Atoi(parts[0])
	m, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 3, 0
	}
	return h, m
}

// InspectOnce scans all certificates, emits deduplicated cert.expiring_soon warnings,
// and renews only auto_renew=1 certificates that are unissued or within renew_before_days.
func (s *Scheduler) InspectOnce(ctx context.Context) error {
	if s.paused.Load() {
		return nil
	}

	settings, err := s.db.GetSettingsDTO(ctx)
	if err != nil {
		settings = &model.SettingsDTO{
			InspectTime:      "03:00",
			RenewBeforeDays:  30,
			ExpiringWarnDays: 7,
		}
	}
	globalRenewDays := settings.RenewBeforeDays
	if globalRenewDays <= 0 {
		globalRenewDays = 30
	}
	warnDays := settings.ExpiringWarnDays
	if warnDays <= 0 {
		warnDays = 7
	}

	certs, err := s.db.ListCertificates(ctx)
	if err != nil {
		return err
	}

	now := s.clock.Now()
	warnThreshold := time.Duration(warnDays) * 24 * time.Hour

	for i := range certs {
		if ctx.Err() != nil || s.paused.Load() {
			return ctx.Err()
		}
		cert := certs[i]

		// Update expiration status and emit deduplicated expiring_soon alerts.
		if cert.NotAfter != nil {
			remaining := cert.NotAfter.Sub(now)
			if remaining <= 0 {
				if cert.Status != model.CertStatusIssuing && cert.Status != model.CertStatusError && cert.Status != model.CertStatusExpired {
					cert.Status = model.CertStatusExpired
					_ = s.db.UpdateCertificate(ctx, &cert)
				}
			} else if remaining <= warnThreshold {
				statusChanged := false
				if cert.Status != model.CertStatusIssuing && cert.Status != model.CertStatusError && cert.Status != model.CertStatusExpiring {
					cert.Status = model.CertStatusExpiring
					statusChanged = true
				}
				shouldNotify := cert.LastExpiringNotifiedAt == nil
				if shouldNotify {
					ts := now
					cert.LastExpiringNotifiedAt = &ts
					statusChanged = true
				}
				if statusChanged {
					_ = s.db.UpdateCertificate(ctx, &cert)
				}
				if shouldNotify && s.notifier != nil {
					daysLeft := int(remaining.Hours() / 24)
					if daysLeft < 0 {
						daysLeft = 0
					}
					_ = s.notifier.Emit(ctx, model.WebhookEvent{
						Event:   model.WebhookEventCertExpiringSoon,
						Level:   model.AuditLevelWarn,
						Title:   fmt.Sprintf("Certificate expiring soon: %s", cert.Domain),
						Message: fmt.Sprintf("Certificate %s expires in %d day(s) (at %s)", cert.Domain, daysLeft, cert.NotAfter.UTC().Format(time.RFC3339)),
						Certificate: &model.WebhookCertRef{
							ID:     cert.ID,
							Domain: cert.Domain,
						},
						Metadata: map[string]any{
							"days_remaining": daysLeft,
							"not_after":      cert.NotAfter.UTC().Format(time.RFC3339),
						},
					})
				}
			}
		}

		// State-driven renewal check.
		if !cert.AutoRenew {
			continue
		}
		if cert.Status == model.CertStatusIssuing {
			continue
		}

		renewDays := cert.RenewBeforeDays
		if renewDays <= 0 {
			renewDays = globalRenewDays
		}
		renewThreshold := time.Duration(renewDays) * 24 * time.Hour

		needsRenew := cert.NotAfter == nil || cert.FingerprintSHA256 == "" || cert.NotAfter.Sub(now) <= renewThreshold
		if !needsRenew {
			continue
		}

		// Skip if a retry is already scheduled for the future.
		if cert.NextRetryAt != nil && cert.NextRetryAt.After(now) {
			continue
		}

		// If previous day's retry cycle was exhausted (retry_count >= len(backoffs) and next_retry_at == nil),
		// start a fresh retry cycle for today's scheduled inspection.
		if s.issuer != nil && cert.RetryCount >= len(s.issuer.backoffs) && cert.NextRetryAt == nil {
			cert.RetryCount = 0
			_ = s.db.UpdateCertificate(ctx, &cert)
		}

		if s.issuer != nil {
			_, _ = s.issuer.IssueSync(ctx, cert.ID, model.TriggerSchedule)
		}
	}
	return nil
}

// ProcessRetriesOnce checks certificates with next_retry_at <= now and runs retry issuance.
func (s *Scheduler) ProcessRetriesOnce(ctx context.Context) error {
	if s.paused.Load() {
		return nil
	}
	now := s.clock.Now()
	due, err := s.db.ListCertificatesDueForRetry(ctx, now)
	if err != nil {
		return err
	}
	for i := range due {
		if ctx.Err() != nil || s.paused.Load() {
			return ctx.Err()
		}
		if s.issuer != nil {
			_, _ = s.issuer.IssueSync(ctx, due[i].ID, model.TriggerRetry)
		}
	}
	return nil
}
