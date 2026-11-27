package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"ssl-center/internal/acme"
	"ssl-center/internal/api"
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

const (
	defaultLogPruneInterval = 24 * time.Hour
	shutdownGracePeriod     = 8 * time.Second
)

var logOutput io.Writer = os.Stdout

// logPruner implements model.LogPruneTrigger and coordinates scheduled/manual
// log retention cleanup while respecting global maintenance pauses.
type logPruner struct {
	db     *db.DB
	maint  model.MaintenanceCoordinator
	logger *slog.Logger
	mu     sync.Mutex
}

func newLogPruner(database *db.DB, maint model.MaintenanceCoordinator, logger *slog.Logger) *logPruner {
	return &logPruner{
		db:     database,
		maint:  maint,
		logger: logger,
	}
}

// PruneNow executes retention cleanup using the current settings from SQLite.
func (p *logPruner) PruneNow(ctx context.Context) (*model.PruneResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.maint != nil && p.maint.IsActive() {
		return nil, errors.New("log prune skipped: maintenance in progress")
	}

	settings, err := p.db.GetSettingsDTO(ctx)
	if err != nil {
		return nil, err
	}
	return p.db.PruneLogs(ctx, settings.LogRetentionDays, settings.LogMaxRows)
}

func runDailyLogPruner(ctx context.Context, pruner *logPruner, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = defaultLogPruneInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if pruner.maint != nil && pruner.maint.IsActive() {
				continue
			}
			pruneCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			res, err := pruner.PruneNow(pruneCtx)
			cancel()
			if err != nil {
				if ctx.Err() == nil && logger != nil {
					logger.Warn("scheduled log prune failed", "error", err)
				}
				continue
			}
			if logger != nil && (res.TotalDeleted > 0 || res.VacuumRan) {
				logger.Info("scheduled log prune completed",
					"cert_jobs_deleted", res.CertJobsDeleted,
					"deploy_logs_deleted", res.DeployLogsDeleted,
					"audit_events_deleted", res.AuditEventsDeleted,
					"vacuum_ran", res.VacuumRan,
				)
			}
		}
	}
}

type appRuntime struct {
	cfg        *config.Config
	db         *db.DB
	cipher     *crypto.Cipher
	redactor   *crypto.SecretRedactor
	redactOut  *crypto.RedactingWriter
	logger     *slog.Logger
	issuer     *acme.Issuer
	scheduler  *acme.Scheduler
	pruner     *logPruner
	router     http.Handler
}

func initApp(ctx context.Context, cfg *config.Config) (*appRuntime, error) {
	if err := cfg.EnsureDataDirs(); err != nil {
		return nil, fmt.Errorf("ensure data dirs: %w", err)
	}

	out := logOutput
	if out == nil {
		out = os.Stdout
	}
	redactor := crypto.NewSecretRedactor()
	redactOut := redactor.RedactingWriter(out)
	logger := slog.New(slog.NewTextHandler(redactOut, &slog.HandlerOptions{
		Level: parseSlogLevel(cfg.LogLevel),
	}))

	masterKey, keyCreated, err := crypto.LoadOrCreateMasterKey(cfg.MasterKeyPath())
	if err != nil {
		return nil, fmt.Errorf("load/create master key: %w", err)
	}
	cipher, err := crypto.NewCipher(masterKey)
	crypto.ZeroBytes(masterKey)
	if err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}
	if keyCreated {
		logger.Info("generated new AES-256 master key", "path", cfg.MasterKeyPath())
	}

	database, err := db.Open(cfg.DBPath())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	authSvc := auth.NewService(database, cfg, nil)
	if _, err := authSvc.BootstrapAdmin(ctx); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("bootstrap admin: %w", err)
	}

	secrets, err := backup.CollectAllSecrets(ctx, database, cipher)
	if err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("collect secrets for redactor: %w", err)
	}
	redactor.ReplaceAll(secrets)

	maint := api.NewMaintenanceCoordinator()
	broker := api.NewCertJobBroker()
	notifier := notify.NewWebhookNotifier(database, cipher, redactor)
	transport := deploy.NewTransport(database, cipher, redactor, logger)
	deployEngine := deploy.NewEngine(database, transport, notifier, redactor, logger)
	caSvc := acme.NewCAService(database, cipher, redactor)
	dnsSvc := acme.NewDNSService(database, cipher, redactor)
	issuer := acme.NewIssuer(database, cfg, caSvc, dnsSvc, redactor, broker, deployEngine, notifier)
	scheduler := acme.NewScheduler(database, cfg, issuer, notifier, maint)
	caddyMgr := caddy.NewManager(database, transport, notifier, redactor)
	backupSvc := backup.NewService(cfg, database, cipher, redactor, maint, scheduler)
	pruner := newLogPruner(database, maint, logger)

	router := api.NewRouter(api.RouterDeps{
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
		PruneTrigger: pruner,
		CaddyManager: caddyMgr,
		BackupSvc:    backupSvc,
	})

	return &appRuntime{
		cfg:       cfg,
		db:        database,
		cipher:    cipher,
		redactor:  redactor,
		redactOut: redactOut,
		logger:    logger,
		issuer:    issuer,
		scheduler: scheduler,
		pruner:    pruner,
		router:    router,
	}, nil
}

func parseSlogLevel(raw string) slog.Level {
	switch raw {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func run(ctx context.Context, cfg *config.Config) error {
	app, err := initApp(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if app.redactOut != nil {
			_ = app.redactOut.Flush()
		}
	}()

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		_ = app.db.Close()
		return fmt.Errorf("listen %s: %w", cfg.ListenAddr, err)
	}

	bgCtx, cancelBg := context.WithCancel(context.Background())
	var bgWg sync.WaitGroup

	srv := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           app.router,
		BaseContext:       func(net.Listener) context.Context { return bgCtx },
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		app.scheduler.Run(bgCtx)
	}()

	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		runDailyLogPruner(bgCtx, app.pruner, defaultLogPruneInterval, app.logger)
	}()

	serveErrCh := make(chan error, 1)
	go func() {
		app.logger.Info("ssl-center server listening", "addr", ln.Addr().String(), "data_dir", cfg.DataDir, "tz", cfg.TZ)
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrCh <- err
			return
		}
		serveErrCh <- nil
	}()

	var serveErr error
	select {
	case <-ctx.Done():
		app.logger.Info("shutdown signal received")
		// Cancel bgCtx immediately so active SSE handlers (r.Context().Done())
		// exit without stalling srv.Shutdown until shutdownGracePeriod expires.
		cancelBg()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownGracePeriod)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			app.logger.Warn("http server graceful shutdown error", "error", err)
			if errors.Is(err, context.DeadlineExceeded) {
				_ = srv.Close()
			}
		}
		cancelShutdown()
		serveErr = <-serveErrCh
	case serveErr = <-serveErrCh:
		cancelBg()
	}

	bgWg.Wait()
	app.issuer.Wait()

	if err := app.db.Close(); err != nil {
		app.logger.Warn("database close error", "error", err)
	}
	app.logger.Info("ssl-center shutdown complete")
	return serveErr
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "server exited with error: %v\n", err)
		os.Exit(1)
	}
}
