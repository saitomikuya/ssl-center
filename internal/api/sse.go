package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// CertJobBrokerImpl implements model.CertJobBroker for live SSE streaming of certificate issuance jobs.
type CertJobBrokerImpl struct {
	mu     sync.RWMutex
	subs   map[int64]map[uint64]chan model.CertJobSSEEvent
	nextID uint64
}

// NewCertJobBroker constructs a thread-safe CertJobBrokerImpl.
func NewCertJobBroker() *CertJobBrokerImpl {
	return &CertJobBrokerImpl{
		subs: make(map[int64]map[uint64]chan model.CertJobSSEEvent),
	}
}

// Publish broadcasts evt to all active subscribers of jobID without blocking publishers.
func (b *CertJobBrokerImpl) Publish(jobID int64, evt model.CertJobSSEEvent) {
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}
	evt.JobID = jobID

	b.mu.RLock()
	jobSubs := b.subs[jobID]
	targets := make([]chan model.CertJobSSEEvent, 0, len(jobSubs))
	for _, ch := range jobSubs {
		targets = append(targets, ch)
	}
	b.mu.RUnlock()

	for _, ch := range targets {
		if evt.Type == "done" {
			// Ensure terminal event is delivered even if channel has old log lines.
			select {
			case ch <- evt:
			default:
				select {
				case <-ch:
				default:
				}
				select {
				case ch <- evt:
				default:
				}
			}
			continue
		}
		select {
		case ch <- evt:
		default:
		}
	}
}

// Subscribe registers a listener channel for jobID and returns an idempotent unsubscribe function.
func (b *CertJobBrokerImpl) Subscribe(ctx context.Context, jobID int64) (<-chan model.CertJobSSEEvent, func()) {
	ch := make(chan model.CertJobSSEEvent, 128)

	b.mu.Lock()
	b.nextID++
	subID := b.nextID
	if b.subs[jobID] == nil {
		b.subs[jobID] = make(map[uint64]chan model.CertJobSSEEvent)
	}
	b.subs[jobID][subID] = ch
	b.mu.Unlock()

	var once sync.Once
	unsub := func() {
		once.Do(func() {
			b.mu.Lock()
			if m, ok := b.subs[jobID]; ok {
				delete(m, subID)
				if len(m) == 0 {
					delete(b.subs, jobID)
				}
			}
			b.mu.Unlock()
		})
	}

	if ctx != nil {
		go func() {
			<-ctx.Done()
			unsub()
		}()
	}

	return ch, unsub
}

// SSEHandler serves GET /api/v1/cert-jobs/{jobId}/stream.
type SSEHandler struct {
	db     *db.DB
	broker model.CertJobBroker
}

// NewSSEHandler constructs an SSEHandler.
func NewSSEHandler(database *db.DB, broker model.CertJobBroker) *SSEHandler {
	return &SSEHandler{
		db:     database,
		broker: broker,
	}
}

// StreamCertJob handles GET /api/v1/cert-jobs/{jobId}/stream (SSE text/event-stream).
func (h *SSEHandler) StreamCertJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := URLParamInt64(r, "jobId")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}

	// Subscribe before DB snapshot so live transitions occurring during replay are not missed.
	var ch <-chan model.CertJobSSEEvent
	var unsub func()
	if h.broker != nil {
		ch, unsub = h.broker.Subscribe(r.Context(), jobID)
		defer unsub()
	}

	job, err := h.db.GetCertJob(r.Context(), jobID)
	if err != nil {
		MapDBError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)
	flush := func() {
		if canFlush {
			flusher.Flush()
		}
	}

	stages := parseJobStages(job.StagesJSON)
	now := time.Now().UTC()

	// Replay current stage snapshot from DB.
	_ = writeSSEEvent(w, model.CertJobSSEEvent{
		Type:         "stage",
		JobID:        job.ID,
		Status:       job.Status,
		CurrentStage: job.CurrentStage,
		Stages:       stages,
		Timestamp:    now,
	})

	// Replay historical log lines from DB.
	replayedLogs := make(map[string]int)
	if job.Logs != "" {
		lines := strings.Split(strings.TrimRight(job.Logs, "\n"), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			replayedLogs[line]++
			_ = writeSSEEvent(w, model.CertJobSSEEvent{
				Type:         "log",
				JobID:        job.ID,
				Status:       job.Status,
				CurrentStage: job.CurrentStage,
				LogLine:      line,
				Timestamp:    now,
			})
		}
	}

	// If job already finished in DB, emit done and close stream cleanly.
	if job.Status == model.JobStatusSuccess || job.Status == model.JobStatusFailed {
		ts := now
		if job.FinishedAt != nil {
			ts = *job.FinishedAt
		}
		_ = writeSSEEvent(w, model.CertJobSSEEvent{
			Type:         "done",
			JobID:        job.ID,
			Status:       job.Status,
			CurrentStage: job.CurrentStage,
			Stages:       stages,
			ErrorMessage: job.ErrorMessage,
			Timestamp:    ts,
		})
		flush()
		return
	}
	flush()

	if ch == nil {
		return
	}

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flush()
		case evt := <-ch:
			if evt.Type == "log" && evt.LogLine != "" {
				if cnt := replayedLogs[evt.LogLine]; cnt > 0 {
					replayedLogs[evt.LogLine] = cnt - 1
					continue
				}
			}
			_ = writeSSEEvent(w, evt)
			flush()
			if evt.Type == "done" {
				return
			}
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, evt model.CertJobSSEEvent) error {
	evtType := evt.Type
	if evtType == "" {
		evtType = "stage"
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evtType, payload)
	return err
}

func parseJobStages(raw string) []model.CertJobStage {
	if strings.TrimSpace(raw) == "" {
		return make([]model.CertJobStage, 0)
	}
	var stages []model.CertJobStage
	if err := json.Unmarshal([]byte(raw), &stages); err != nil || stages == nil {
		return make([]model.CertJobStage, 0)
	}
	return stages
}
