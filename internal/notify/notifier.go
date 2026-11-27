package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

const (
	AADWebhookHeaders = "webhooks:headers_enc"
	AADWebhookSecret  = "webhooks:secret_enc"

	defaultHTTPTimeout    = 10 * time.Second
	maxAttempts           = 3
	maxResponseReadBytes  = 4096
)

var defaultRetryDelays = []time.Duration{
	500 * time.Millisecond,
	2 * time.Second,
}

// Option configures a WebhookNotifier.
type Option func(*WebhookNotifier)

// WithHTTPClient overrides the HTTP client used for webhook delivery.
func WithHTTPClient(client *http.Client) Option {
	return func(n *WebhookNotifier) {
		if client != nil {
			n.client = client
		}
	}
}

// WithRetryDelays overrides the backoff delays between retry attempts.
// For 3 total attempts, up to 2 delays are used (between attempt 1->2 and 2->3).
func WithRetryDelays(delays []time.Duration) Option {
	return func(n *WebhookNotifier) {
		n.retryDelays = append([]time.Duration(nil), delays...)
	}
}

// WithClock overrides the clock used for payload timestamps and delivery records.
func WithClock(clock func() time.Time) Option {
	return func(n *WebhookNotifier) {
		if clock != nil {
			n.clock = clock
		}
	}
}

// WebhookNotifier implements model.Notifier by dispatching signed JSON webhook payloads
// with encrypted custom headers and exponential-style retry backoff.
type WebhookNotifier struct {
	db          *db.DB
	cipher      *crypto.Cipher
	redactor    *crypto.SecretRedactor
	client      *http.Client
	retryDelays []time.Duration
	clock       func() time.Time
}

// NewWebhookNotifier constructs a WebhookNotifier.
func NewWebhookNotifier(database *db.DB, cipher *crypto.Cipher, redactor *crypto.SecretRedactor, opts ...Option) *WebhookNotifier {
	n := &WebhookNotifier{
		db:          database,
		cipher:      cipher,
		redactor:    redactor,
		client:      &http.Client{Timeout: defaultHTTPTimeout},
		retryDelays: append([]time.Duration(nil), defaultRetryDelays...),
		clock:       func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		if opt != nil {
			opt(n)
		}
	}
	return n
}

// IsValidWebhookEvent reports whether event is one of the 5 supported V1 webhook events.
func IsValidWebhookEvent(event string) bool {
	for _, e := range model.AllWebhookEvents {
		if e == event {
			return true
		}
	}
	return false
}

// Emit dispatches event to all enabled webhooks subscribed to event.Event.
func (n *WebhookNotifier) Emit(ctx context.Context, event model.WebhookEvent) error {
	webhooks, err := n.db.ListEnabledWebhooks(ctx)
	if err != nil {
		return fmt.Errorf("list enabled webhooks: %w", err)
	}
	if len(webhooks) == 0 {
		return nil
	}

	payload := model.WebhookPayload{
		Event:       event.Event,
		Timestamp:   n.clock().UTC(),
		Level:       event.Level,
		Title:       event.Title,
		Message:     event.Message,
		Certificate: event.Certificate,
		Host:        event.Host,
		Deployment:  event.Deployment,
		Error:       n.redact(event.Error),
		Metadata:    event.Metadata,
	}
	if payload.Level == "" {
		payload.Level = model.AuditLevelInfo
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for i := range webhooks {
		wh := webhooks[i]
		if !webhookSubscribed(wh.EventsJSON, event.Event) {
			continue
		}
		wg.Add(1)
		go func(target model.Webhook) {
			defer wg.Done()
			if _, sendErr := n.deliver(ctx, &target, body); sendErr != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("webhook %d (%s): %w", target.ID, target.Name, sendErr))
				mu.Unlock()
			}
		}(wh)
	}
	wg.Wait()

	return errors.Join(errs...)
}

// SendTest sends a test payload to the specified webhook regardless of its enabled state
// or event subscriptions, satisfying model.Notifier.
func (n *WebhookNotifier) SendTest(ctx context.Context, webhookID int64) error {
	_, err := n.SendTestWithStatus(ctx, webhookID)
	return err
}

// SendTestWithStatus sends a test payload to the specified webhook and returns the
// HTTP status code (if any response was received) and delivery error.
func (n *WebhookNotifier) SendTestWithStatus(ctx context.Context, webhookID int64) (int, error) {
	wh, err := n.db.GetWebhook(ctx, webhookID)
	if err != nil {
		return 0, err
	}

	payload := model.WebhookPayload{
		Event:     "webhook.test",
		Timestamp: n.clock().UTC(),
		Level:     model.AuditLevelInfo,
		Title:     "Webhook connectivity test",
		Message:   fmt.Sprintf("Test notification from ssl-center for webhook %q.", wh.Name),
		Metadata: map[string]any{
			"test":       true,
			"webhook_id": wh.ID,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal test webhook payload: %w", err)
	}
	return n.deliver(ctx, wh, body)
}

func (n *WebhookNotifier) deliver(ctx context.Context, wh *model.Webhook, body []byte) (int, error) {
	headers, err := n.decryptHeaders(wh.HeadersEnc)
	if err != nil {
		errMsg := n.redact(fmt.Sprintf("decrypt webhook headers: %v", err))
		_ = n.db.UpdateWebhookDeliveryResult(ctx, wh.ID, nil, errMsg, n.clock().UTC())
		return 0, errors.New(errMsg)
	}
	secret, err := n.decryptSecret(wh.SecretEnc)
	if err != nil {
		errMsg := n.redact(fmt.Sprintf("decrypt webhook secret: %v", err))
		_ = n.db.UpdateWebhookDeliveryResult(ctx, wh.ID, nil, errMsg, n.clock().UTC())
		return 0, errors.New(errMsg)
	}

	var signature string
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	var (
		lastCode  *int
		lastErr   error
		finalCode int
	)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := n.retryDelay(attempt - 1)
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					lastErr = ctx.Err()
					goto done
				case <-timer.C:
				}
			}
		}

		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
		if reqErr != nil {
			lastErr = fmt.Errorf("build request: %w", reqErr)
			break
		}
		for k, v := range headers {
			if strings.TrimSpace(k) != "" {
				req.Header.Set(k, v)
			}
		}
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "ssl-center-webhook/1.0")
		}
		if signature != "" {
			req.Header.Set("X-Webhook-Signature", signature)
		}

		resp, doErr := n.client.Do(req)
		if doErr != nil {
			lastErr = doErr
			continue
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseReadBytes))
		_ = resp.Body.Close()

		code := resp.StatusCode
		lastCode = &code
		finalCode = code

		if code >= 200 && code < 300 {
			lastErr = nil
			break
		}

		snippet := strings.TrimSpace(string(respBody))
		if snippet != "" {
			lastErr = fmt.Errorf("unexpected HTTP status %d: %s", code, snippet)
		} else {
			lastErr = fmt.Errorf("unexpected HTTP status %d", code)
		}

		// Retry only on 429 or 5xx; 4xx client errors fail fast.
		if code != http.StatusTooManyRequests && code < 500 {
			break
		}
	}

done:
	var errMsg string
	if lastErr != nil {
		errMsg = n.redact(lastErr.Error())
		lastErr = errors.New(errMsg)
	}
	_ = n.db.UpdateWebhookDeliveryResult(ctx, wh.ID, lastCode, errMsg, n.clock().UTC())
	return finalCode, lastErr
}

func (n *WebhookNotifier) retryDelay(idx int) time.Duration {
	if len(n.retryDelays) == 0 {
		return 0
	}
	if idx < len(n.retryDelays) {
		return n.retryDelays[idx]
	}
	return n.retryDelays[len(n.retryDelays)-1]
}

func (n *WebhookNotifier) decryptHeaders(enc string) (map[string]string, error) {
	if enc == "" {
		return nil, nil
	}
	if n.cipher == nil {
		return nil, errors.New("cipher not initialized")
	}
	plain, err := n.cipher.Decrypt(enc, AADWebhookHeaders)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(plain) == "" {
		return nil, nil
	}
	var hdrs map[string]string
	if err := json.Unmarshal([]byte(plain), &hdrs); err != nil {
		return nil, fmt.Errorf("unmarshal headers json: %w", err)
	}
	return hdrs, nil
}

func (n *WebhookNotifier) decryptSecret(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	if n.cipher == nil {
		return "", errors.New("cipher not initialized")
	}
	return n.cipher.Decrypt(enc, AADWebhookSecret)
}

func (n *WebhookNotifier) redact(s string) string {
	if s == "" || n.redactor == nil {
		return s
	}
	return n.redactor.Redact(s)
}

func webhookSubscribed(eventsJSON, targetEvent string) bool {
	if strings.TrimSpace(eventsJSON) == "" {
		return false
	}
	var events []string
	if err := json.Unmarshal([]byte(eventsJSON), &events); err != nil {
		return false
	}
	for _, ev := range events {
		if ev == targetEvent {
			return true
		}
	}
	return false
}
