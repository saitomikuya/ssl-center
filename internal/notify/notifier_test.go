package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

func setupNotifyTest(t *testing.T) (*db.DB, *crypto.Cipher, *crypto.SecretRedactor) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	key := make([]byte, crypto.MasterKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	redactor := crypto.NewSecretRedactor()
	return database, cipher, redactor
}

func TestWebhookEmitSignatureHeadersAndPayload(t *testing.T) {
	database, cipher, redactor := setupNotifyTest(t)
	ctx := context.Background()

	secret := "super-hmac-secret-value"
	authToken := "Bearer secret-api-token-123"
	redactor.Add(secret, authToken)

	hdrBytes, _ := json.Marshal(map[string]string{
		"Authorization": authToken,
		"X-Team":        "ops",
	})
	hdrEnc, err := cipher.Encrypt(string(hdrBytes), AADWebhookHeaders)
	if err != nil {
		t.Fatal(err)
	}
	secEnc, err := cipher.Encrypt(secret, AADWebhookSecret)
	if err != nil {
		t.Fatal(err)
	}
	eventsJSON, _ := json.Marshal([]string{model.WebhookEventDeployFailed, model.WebhookEventCaddyReloadFailed})

	var (
		mu          sync.Mutex
		gotRawBody  []byte
		gotHeaders  http.Header
		requestHits int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requestHits++
		gotRawBody = body
		gotHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":true}`))
	}))
	defer srv.Close()

	wh := &model.Webhook{
		Name:       "Primary",
		URL:        srv.URL,
		HeadersEnc: hdrEnc,
		SecretEnc:  secEnc,
		EventsJSON: string(eventsJSON),
		Enabled:    true,
	}
	if _, err := database.CreateWebhook(ctx, wh); err != nil {
		t.Fatal(err)
	}

	// Unsubscribed event should not trigger delivery
	notifier := NewWebhookNotifier(database, cipher, redactor, WithRetryDelays([]time.Duration{5 * time.Millisecond}))
	if err := notifier.Emit(ctx, model.WebhookEvent{
		Event:   model.WebhookEventCertDeployed,
		Level:   model.AuditLevelInfo,
		Title:   "Deployed",
		Message: "ok",
	}); err != nil {
		t.Fatalf("Emit unsubscribed: %v", err)
	}
	mu.Lock()
	if requestHits != 0 {
		t.Fatalf("expected 0 hits for unsubscribed event, got %d", requestHits)
	}
	mu.Unlock()

	// Subscribed event
	err = notifier.Emit(ctx, model.WebhookEvent{
		Event:   model.WebhookEventDeployFailed,
		Level:   model.AuditLevelError,
		Title:   "Certificate deployment failed",
		Message: "TLS fingerprint mismatch on edge-1:443",
		Certificate: &model.WebhookCertRef{
			ID:     1,
			Domain: "*.example.com",
		},
		Host: &model.WebhookHostRef{
			ID:   2,
			Name: "edge-1",
			Host: "10.0.0.10",
		},
		Deployment: &model.WebhookDeployRef{
			ID:   3,
			Name: "edge-1 Caddy",
		},
		Error:    "observed fingerprint aaa != expected bbb with token " + authToken,
		Metadata: map[string]any{"port": 443},
	})
	if err != nil {
		t.Fatalf("Emit subscribed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if requestHits != 1 {
		t.Fatalf("requestHits = %d, want 1", requestHits)
	}
	if got := gotHeaders.Get("Authorization"); got != authToken {
		t.Fatalf("Authorization header = %q, want %q", got, authToken)
	}
	if got := gotHeaders.Get("X-Team"); got != "ops" {
		t.Fatalf("X-Team header = %q, want ops", got)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotRawBody)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig := gotHeaders.Get("X-Webhook-Signature"); gotSig != expectedSig {
		t.Fatalf("X-Webhook-Signature = %q, want %q", gotSig, expectedSig)
	}

	var payload model.WebhookPayload
	if err := json.Unmarshal(gotRawBody, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Event != model.WebhookEventDeployFailed || payload.Level != model.AuditLevelError {
		t.Fatalf("unexpected payload header: %+v", payload)
	}
	if payload.Certificate == nil || payload.Certificate.Domain != "*.example.com" {
		t.Fatalf("unexpected certificate ref: %+v", payload.Certificate)
	}
	if payload.Host == nil || payload.Host.Name != "edge-1" {
		t.Fatalf("unexpected host ref: %+v", payload.Host)
	}
	if payload.Deployment == nil || payload.Deployment.ID != 3 {
		t.Fatalf("unexpected deployment ref: %+v", payload.Deployment)
	}
	if payload.Timestamp.IsZero() {
		t.Fatal("payload timestamp must be non-zero")
	}
	if payload.Error == "" || gotHeaders == nil {
		t.Fatal("expected error field in payload")
	}
	if contains := string(gotRawBody); contains == "" || (len(authToken) > 0 && bytesContains(gotRawBody, []byte(authToken))) {
		t.Fatalf("payload leaked secret token: %s", string(gotRawBody))
	}

	updated, err := database.GetWebhook(ctx, wh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.LastStatusCode == nil || *updated.LastStatusCode != 200 || updated.LastError != "" || updated.LastTriggeredAt == nil {
		t.Fatalf("unexpected DB delivery status: %+v", updated)
	}
}

func TestWebhookRetryBackoff500To200AndSendTest(t *testing.T) {
	database, cipher, redactor := setupNotifyTest(t)
	ctx := context.Background()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("temporary upstream error"))
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("accepted"))
	}))
	defer srv.Close()

	eventsJSON, _ := json.Marshal(model.DefaultWebhookEvents)
	wh := &model.Webhook{
		Name:       "RetryHook",
		URL:        srv.URL,
		EventsJSON: string(eventsJSON),
		Enabled:    true,
	}
	if _, err := database.CreateWebhook(ctx, wh); err != nil {
		t.Fatal(err)
	}

	notifier := NewWebhookNotifier(database, cipher, redactor,
		WithRetryDelays([]time.Duration{5 * time.Millisecond, 10 * time.Millisecond}),
	)

	if err := notifier.Emit(ctx, model.WebhookEvent{
		Event:   model.WebhookEventCertIssueFailed,
		Level:   model.AuditLevelError,
		Title:   "Issue failed",
		Message: "DNS timeout",
	}); err != nil {
		t.Fatalf("expected 3rd attempt to succeed, got: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", attempts.Load())
	}

	got, err := database.GetWebhook(ctx, wh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastStatusCode == nil || *got.LastStatusCode != 202 || got.LastError != "" {
		t.Fatalf("unexpected webhook status after retry success: %+v", got)
	}

	// Test disabled webhook still works via SendTest
	got.Enabled = false
	if err := database.UpdateWebhook(ctx, got); err != nil {
		t.Fatal(err)
	}
	attempts.Store(0)
	srv2Hits := atomic.Int32{}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv2Hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		var p model.WebhookPayload
		if err := json.Unmarshal(body, &p); err != nil || p.Event != "webhook.test" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	got.URL = srv2.URL
	if err := database.UpdateWebhook(ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := notifier.SendTest(ctx, got.ID); err != nil {
		t.Fatalf("SendTest on disabled webhook failed: %v", err)
	}
	if srv2Hits.Load() != 1 {
		t.Fatalf("SendTest hits = %d, want 1", srv2Hits.Load())
	}
}

func TestWebhookExhaustedRetriesRecordsLastError(t *testing.T) {
	database, cipher, redactor := setupNotifyTest(t)
	ctx := context.Background()

	secretLeak := "secret-db-token-999"
	redactor.Add(secretLeak)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream leaked " + secretLeak))
	}))
	defer srv.Close()

	eventsJSON, _ := json.Marshal(model.DefaultWebhookEvents)
	wh := &model.Webhook{
		Name:       "Always502",
		URL:        srv.URL,
		EventsJSON: string(eventsJSON),
		Enabled:    true,
	}
	if _, err := database.CreateWebhook(ctx, wh); err != nil {
		t.Fatal(err)
	}

	notifier := NewWebhookNotifier(database, cipher, redactor,
		WithRetryDelays([]time.Duration{5 * time.Millisecond, 5 * time.Millisecond}),
	)

	err := notifier.Emit(ctx, model.WebhookEvent{
		Event:   model.WebhookEventCaddyReloadFailed,
		Level:   model.AuditLevelError,
		Title:   "Caddy reload failed",
		Message: "exit status 1",
	})
	if err == nil {
		t.Fatal("expected error when all 3 attempts return 502")
	}
	if hits.Load() != 3 {
		t.Fatalf("hits = %d, want 3", hits.Load())
	}

	updated, err := database.GetWebhook(ctx, wh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.LastStatusCode == nil || *updated.LastStatusCode != 502 {
		t.Fatalf("LastStatusCode = %v, want 502", updated.LastStatusCode)
	}
	if updated.LastError == "" || bytesContains([]byte(updated.LastError), []byte(secretLeak)) {
		t.Fatalf("LastError missing or leaked secret: %q", updated.LastError)
	}
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
