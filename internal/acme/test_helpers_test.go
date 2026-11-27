package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"

	"ssl-center/internal/config"
	appcrypto "ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

type testEnv struct {
	t        *testing.T
	dir      string
	cfg      *config.Config
	db       *db.DB
	cipher   *appcrypto.Cipher
	redactor *appcrypto.SecretRedactor
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: dir,
		TZ:      "UTC",
	}
	if err := cfg.EnsureDataDirs(); err != nil {
		t.Fatalf("EnsureDataDirs: %v", err)
	}
	key, _, err := appcrypto.LoadOrCreateMasterKey(cfg.MasterKeyPath())
	if err != nil {
		t.Fatalf("LoadOrCreateMasterKey: %v", err)
	}
	cipher, err := appcrypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	database, err := db.Open(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})
	return &testEnv{
		t:        t,
		dir:      dir,
		cfg:      cfg,
		db:       database,
		cipher:   cipher,
		redactor: appcrypto.NewSecretRedactor(),
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t.UTC()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type mockNotifier struct {
	mu     sync.Mutex
	events []model.WebhookEvent
}

func (m *mockNotifier) Emit(_ context.Context, evt model.WebhookEvent) error {
	m.mu.Lock()
	m.events = append(m.events, evt)
	m.mu.Unlock()
	return nil
}

func (m *mockNotifier) SendTest(_ context.Context, _ int64) error {
	return nil
}

func (m *mockNotifier) Events() []model.WebhookEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.WebhookEvent, len(m.events))
	copy(out, m.events)
	return out
}

type fanoutCall struct {
	CertID      int64
	TriggerType string
	CertJobID   *int64
}

type mockDeployTrigger struct {
	mu    sync.Mutex
	calls []fanoutCall
	err   error
}

func (m *mockDeployTrigger) FanoutCertificate(_ context.Context, certID int64, triggerType string, certJobID *int64) error {
	m.mu.Lock()
	m.calls = append(m.calls, fanoutCall{CertID: certID, TriggerType: triggerType, CertJobID: certJobID})
	err := m.err
	m.mu.Unlock()
	return err
}

func (m *mockDeployTrigger) DeployTarget(_ context.Context, _ int64, _ string) (*model.DeployLog, error) {
	return nil, nil
}

func (m *mockDeployTrigger) Calls() []fanoutCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]fanoutCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// generateTestCertResource creates a valid CA + leaf certificate bundle matching domains and validity.
func generateTestCertResource(t *testing.T, domains []string, notBefore, notAfter time.Time) *certificate.Resource {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test ACME Intermediate CA"},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	fullchainPEM := append(append([]byte(nil), leafPEM...), issuerPEM...)
	privPEM := certcrypto.PEMEncode(leafKey)

	return &certificate.Resource{
		Domain:            domains[0],
		Certificate:       fullchainPEM,
		IssuerCertificate: issuerPEM,
		PrivateKey:        privPEM,
	}
}

// mockACMEServer simulates an ACME v2 directory, newNonce, and newAccount endpoints
// (supporting standard registration, EAB registration, and ResolveAccountByKey).
type mockACMEServer struct {
	srv            *httptest.Server
	mu             sync.Mutex
	accounts       map[string]string // key thumbprint -> accountURI
	eabSeen        []string
	nextAccountNum int
	nonceCounter   int
}

func newMockACMEServer(t *testing.T) *mockACMEServer {
	t.Helper()
	m := &mockACMEServer{
		accounts: make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", m.handleDirectory)
	mux.HandleFunc("/new-nonce", m.handleNonce)
	mux.HandleFunc("/new-account", m.handleNewAccount)
	mux.HandleFunc("/account/", m.handleAccount)
	m.srv = httptest.NewTLSServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockACMEServer) URL() string {
	return m.srv.URL + "/directory"
}

func (m *mockACMEServer) nextNonce() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonceCounter++
	return fmt.Sprintf("nonce-%d", m.nonceCounter)
}

func (m *mockACMEServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"newNonce":   m.srv.URL + "/new-nonce",
		"newAccount": m.srv.URL + "/new-account",
		"newOrder":   m.srv.URL + "/new-order",
		"meta": map[string]any{
			"termsOfService": m.srv.URL + "/tos",
		},
	})
}

func (m *mockACMEServer) handleNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nextNonce())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (m *mockACMEServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	protBytes, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var prot struct {
		JWK json.RawMessage `json:"jwk"`
	}
	_ = json.Unmarshal(protBytes, &prot)
	sum := sha256.Sum256(prot.JWK)
	thumb := hex.EncodeToString(sum[:])

	payBytes, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	var payload struct {
		OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
		Contact                []string        `json:"contact"`
		ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
	}
	_ = json.Unmarshal(payBytes, &payload)

	w.Header().Set("Replay-Nonce", m.nextNonce())
	w.Header().Set("Content-Type", "application/json")

	m.mu.Lock()
	defer m.mu.Unlock()

	if payload.OnlyReturnExisting {
		uri, ok := m.accounts[thumb]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":   "urn:ietf:params:acme:error:accountDoesNotExist",
				"detail": "Account does not exist",
				"status": 400,
			})
			return
		}
		w.Header().Set("Location", uri)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "valid",
			"contact": payload.Contact,
		})
		return
	}

	if len(payload.ExternalAccountBinding) > 0 {
		var eabJWS struct {
			Protected string `json:"protected"`
		}
		if json.Unmarshal(payload.ExternalAccountBinding, &eabJWS) == nil && eabJWS.Protected != "" {
			if dec, err := base64.RawURLEncoding.DecodeString(eabJWS.Protected); err == nil {
				m.eabSeen = append(m.eabSeen, string(dec))
			}
		} else {
			m.eabSeen = append(m.eabSeen, string(bytes.TrimSpace(payload.ExternalAccountBinding)))
		}
	}

	uri, ok := m.accounts[thumb]
	if !ok {
		m.nextAccountNum++
		uri = fmt.Sprintf("%s/account/%d", m.srv.URL, m.nextAccountNum)
		m.accounts[thumb] = uri
	}
	w.Header().Set("Location", uri)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "valid",
		"contact": payload.Contact,
	})
}

func (m *mockACMEServer) handleAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nextNonce())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "valid",
	})
}

func (m *mockACMEServer) EABCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.eabSeen)
}

func (m *mockACMEServer) HasEABSubstring(sub string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.eabSeen {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
