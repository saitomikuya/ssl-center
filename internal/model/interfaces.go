package model

import (
	"context"
	"net/http"
	"time"
)

// ExecResult captures remote or local command execution output.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// HostTestResult describes the result of testing SSH/Local connectivity and Docker/Caddy status.
type HostTestResult struct {
	SSHOK               bool                 `json:"ssh_ok"`
	DockerOK            bool                 `json:"docker_ok"`
	CaddyRunning        bool                 `json:"caddy_running"`
	HostKeyFingerprint  string               `json:"host_key_fingerprint"`
	HostKeyStatus       string               `json:"host_key_status"` // trusted | pinned | changed | insecure | local
	Message             string               `json:"message"`
	CaddyVersion        string               `json:"caddy_version,omitempty"`
	CaddyIssueCode      string               `json:"caddy_issue_code,omitempty"`
	CaddyfileExists     *bool                `json:"caddyfile_exists,omitempty"`
	DetectedContainers  []DetectedContainer  `json:"detected_containers,omitempty"`
	DetectedCaddyConfig *DetectedCaddyConfig `json:"detected_caddy_config,omitempty"`
}

// TransportSessionScoper is optionally implemented by RemoteTransport to reuse
// a single SSH/SFTP connection across multiple operations in one workflow.
type TransportSessionScoper interface {
	WithSession(ctx context.Context, host *Host, fn func(context.Context) error) error
}

// WithTransportSession runs fn inside a pooled/reused transport session when supported.
func WithTransportSession(ctx context.Context, transport RemoteTransport, host *Host, fn func(context.Context) error) error {
	if scoper, ok := transport.(TransportSessionScoper); ok && scoper != nil {
		return scoper.WithSession(ctx, host, fn)
	}
	return fn(ctx)
}

// Notifier dispatches Webhook events asynchronously/with retries and handles test notifications.
// Implemented in Phase 2 by Worker C (internal/notify).
type Notifier interface {
	Emit(ctx context.Context, event WebhookEvent) error
	SendTest(ctx context.Context, webhookID int64) error
}

// DeployTrigger fans out certificate artifacts to enabled deployments or pushes a single target.
// Implemented in Phase 2 by Worker B (internal/deploy).
type DeployTrigger interface {
	FanoutCertificate(ctx context.Context, certID int64, triggerType string, certJobID *int64) error
	DeployTarget(ctx context.Context, deploymentID int64, triggerType string) (*DeployLog, error)
}

// RemoteTransport abstracts SSH/SFTP and Local host file/command operations so deploy and caddy
// share one transport implementation without cross-importing packages.
// Implemented in Phase 2 by Worker B (internal/deploy).
type RemoteTransport interface {
	TestConnection(ctx context.Context, host *Host) (*HostTestResult, error)
	ReadFile(ctx context.Context, host *Host, path string) ([]byte, error)
	WriteFileAtomic(ctx context.Context, host *Host, path string, data []byte, mode uint32) error
	WriteFileInPlace(ctx context.Context, host *Host, path string, data []byte) error
	RemoveFile(ctx context.Context, host *Host, path string) error
	Exec(ctx context.Context, host *Host, cmd string) (*ExecResult, error)
	ExecWithStdin(ctx context.Context, host *Host, cmd string, stdin []byte) (*ExecResult, error)
}

// MaintenanceCoordinator coordinates global maintenance locks during backup restore,
// rejecting mutating HTTP requests with 503 and pausing background schedulers.
// Implemented in Phase 1 (internal/api/middleware.go).
type MaintenanceCoordinator interface {
	Middleware() func(http.Handler) http.Handler
	IsActive() bool
	BeginMaintenance(ctx context.Context) error
	EndMaintenance()
	RegisterSchedulerHook(pause, resume func())
}

// ScheduleReloader lets settings updates dynamically reload scheduler timings or trigger immediate inspection.
// Implemented in Phase 2 by Worker A (internal/acme).
type ScheduleReloader interface {
	ReloadSchedule(ctx context.Context) error
	TriggerInspectNow(ctx context.Context) error
}

// LogPruneTrigger triggers immediate log retention cleanup + checkpoint/vacuum.
type LogPruneTrigger interface {
	PruneNow(ctx context.Context) (*PruneResult, error)
}

// CertJobBroker streams live 6-stage issuance events and logs to SSE subscribers.
// Implemented in Phase 2 by Worker A (internal/acme or internal/api/sse.go).
type CertJobBroker interface {
	Publish(jobID int64, evt CertJobSSEEvent)
	Subscribe(ctx context.Context, jobID int64) (<-chan CertJobSSEEvent, func())
}

// SecretLoader provides decrypted plaintext secrets from the database for SecretRedactor hydration.
type SecretLoader interface {
	CollectAllSecrets(ctx context.Context) ([]string, error)
}

// BackupServiceClock allows deterministic timestamps where needed.
type Clock interface {
	Now() time.Time
}
