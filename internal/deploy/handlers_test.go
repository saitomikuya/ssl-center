package deploy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"ssl-center/internal/api"
	"ssl-center/internal/deploy"
	"ssl-center/internal/model"
)

func setupHostDeployRouter(t *testing.T) (http.Handler, *mockSSHServer, *model.Certificate, *spyNotifier) {
	t.Helper()
	database, cipher, redactor := setupTestDBAndCrypto(t)
	notifier := &spyNotifier{}
	tr := deploy.NewTransport(database, cipher, redactor, nil)
	engine := deploy.NewEngine(database, tr, notifier, redactor, nil)

	hh := api.NewHostHandler(database, cipher, redactor, tr)
	dh := api.NewDeployHandler(database, engine)

	r := chi.NewRouter()
	r.Get("/api/v1/hosts", hh.ListHosts)
	r.Post("/api/v1/hosts", hh.CreateHost)
	r.Get("/api/v1/hosts/{id}", hh.GetHost)
	r.Put("/api/v1/hosts/{id}", hh.UpdateHost)
	r.Delete("/api/v1/hosts/{id}", hh.DeleteHost)
	r.Post("/api/v1/hosts/{id}/test", hh.TestHost)
	r.Post("/api/v1/hosts/{id}/reset-host-key", hh.ResetHostKey)
	r.Get("/api/v1/hosts/{id}/deployments", hh.ListHostDeployments)

	r.Get("/api/v1/certificates/{id}/deployments", dh.ListCertDeployments)
	r.Post("/api/v1/certificates/{id}/deployments", dh.CreateDeployment)
	r.Put("/api/v1/deployments/{id}", dh.UpdateDeployment)
	r.Delete("/api/v1/deployments/{id}", dh.DeleteDeployment)
	r.Post("/api/v1/deployments/{id}/push", dh.PushDeployment)
	r.Get("/api/v1/deployments/{id}/logs", dh.ListDeploymentLogs)

	_, pubKey := generateClientSSHKeyPair(t, "")
	sshSrv := newMockSSHServer(t, pubKey, "initial-ssh-pw-99")
	sshSrv.SetExecHandler(func(cmd string, stdin []byte) (string, string, int) {
		switch {
		case strings.Contains(cmd, "docker info"):
			return "26.1.0\n", "", 0
		case strings.Contains(cmd, "docker inspect"):
			return "true\n", "", 0
		default:
			return "ok\n", "", 0
		}
	})

	cert := seedCertWithFiles(t, database, cipher, "*.example.com", nil, nil, "")
	return r, sshSrv, cert, notifier
}

func doJSONReq(t *testing.T, router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != "" {
		buf = bytes.NewBufferString(body)
	} else {
		buf = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, buf)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeAPIEnvelope(t *testing.T, rec *httptest.ResponseRecorder) api.Envelope {
	t.Helper()
	var env api.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal envelope %q: %v", rec.Body.String(), err)
	}
	return env
}

func TestHostAndDeployHandlers_CRUDPushAndSecurity(t *testing.T) {
	router, sshSrv, cert, _ := setupHostDeployRouter(t)

	// 1. Local host is present and cannot be deleted (403 LOCAL_HOST_PROTECTED)
	rec := doJSONReq(t, router, http.MethodGet, "/api/v1/hosts", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /hosts = %d, body=%s", rec.Code, rec.Body.String())
	}
	env := decodeAPIEnvelope(t, rec)
	var hosts []model.HostDTO
	b, _ := json.Marshal(env.Data)
	_ = json.Unmarshal(b, &hosts)
	if len(hosts) != 1 || !hosts[0].IsLocal {
		t.Fatalf("expected 1 Local host, got %+v", hosts)
	}

	rec = doJSONReq(t, router, http.MethodDelete, "/api/v1/hosts/"+strconv.FormatInt(hosts[0].ID, 10), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE Local host = %d, want 403", rec.Code)
	}
	env = decodeAPIEnvelope(t, rec)
	if env.Error == nil || env.Error.Code != api.CodeLocalHostProtected {
		t.Fatalf("expected LOCAL_HOST_PROTECTED, got %+v", env.Error)
	}

	// 2. Reject invalid Caddy container name on POST /hosts
	rec = doJSONReq(t, router, http.MethodPost, "/api/v1/hosts", `{
		"name":"bad-container",
		"mode":"ssh",
		"host":"127.0.0.1",
		"port":22,
		"username":"root",
		"auth_type":"password",
		"ssh_password":"secret-pw",
		"caddy_container":"caddy;id"
	}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid container name status = %d, want 400", rec.Code)
	}

	// 3. Create valid SSH host; verify secrets are never returned
	remoteCertDir := filepath.Join(t.TempDir(), "caddy-certs")
	createBody, _ := json.Marshal(map[string]any{
		"name":                "edge-1",
		"mode":                "ssh",
		"host":                sshSrv.addr,
		"port":                sshSrv.port,
		"username":            "root",
		"auth_type":           "password",
		"ssh_password":        "initial-ssh-pw-99",
		"host_key_policy":     "tofu",
		"caddy_enabled":       true,
		"caddy_container":     "caddy-edge",
		"caddy_host_cert_dir": remoteCertDir,
	})
	rec = doJSONReq(t, router, http.MethodPost, "/api/v1/hosts", string(createBody))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /hosts = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "initial-ssh-pw-99") {
		t.Fatalf("plaintext password leaked in response: %s", rec.Body.String())
	}
	env = decodeAPIEnvelope(t, rec)
	var createdHost model.HostDTO
	b, _ = json.Marshal(env.Data)
	_ = json.Unmarshal(b, &createdHost)
	if !createdHost.HasPassword || createdHost.HasPrivateKey {
		t.Fatalf("unexpected secret flags: %+v", createdHost)
	}

	// 4. PUT /hosts/{id} with empty ssh_password preserves existing secret
	rec = doJSONReq(t, router, http.MethodPut, "/api/v1/hosts/"+strconv.FormatInt(createdHost.ID, 10), `{"name":"edge-1-renamed","ssh_password":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /hosts = %d, body=%s", rec.Code, rec.Body.String())
	}

	// 5. Test connection (pins TOFU host key) & Reset host key
	hostURL := "/api/v1/hosts/" + strconv.FormatInt(createdHost.ID, 10)
	rec = doJSONReq(t, router, http.MethodPost, hostURL+"/test", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /hosts/{id}/test = %d, body=%s", rec.Code, rec.Body.String())
	}
	env = decodeAPIEnvelope(t, rec)
	var testRes model.HostTestResult
	b, _ = json.Marshal(env.Data)
	_ = json.Unmarshal(b, &testRes)
	if !testRes.SSHOK || testRes.HostKeyStatus != "pinned" || !testRes.CaddyRunning {
		t.Fatalf("unexpected test result: %+v", testRes)
	}

	rec = doJSONReq(t, router, http.MethodPost, hostURL+"/reset-host-key", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /hosts/{id}/reset-host-key = %d", rec.Code)
	}
	env = decodeAPIEnvelope(t, rec)
	var resetHost model.HostDTO
	b, _ = json.Marshal(env.Data)
	_ = json.Unmarshal(b, &resetHost)
	if resetHost.HostKeyFingerprint != "" {
		t.Fatalf("expected empty fingerprint after reset, got %q", resetHost.HostKeyFingerprint)
	}

	// 6. GET /hosts/{id}/deployments returns [] (not null)
	rec = doJSONReq(t, router, http.MethodGet, hostURL+"/deployments", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"data":[]`) {
		t.Fatalf("expected empty slice [], got status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 7. Create caddy_docker deployment (auto-derives paths & --force reload command)
	certDepsURL := "/api/v1/certificates/" + strconv.FormatInt(cert.ID, 10) + "/deployments"
	depBody, _ := json.Marshal(map[string]any{
		"host_id":            createdHost.ID,
		"template":           "caddy_docker",
		"tls_verify_enabled": false,
	})
	rec = doJSONReq(t, router, http.MethodPost, certDepsURL, string(depBody))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST deployment = %d, body=%s", rec.Code, rec.Body.String())
	}
	env = decodeAPIEnvelope(t, rec)
	var createdDep model.DeploymentDTO
	b, _ = json.Marshal(env.Data)
	_ = json.Unmarshal(b, &createdDep)
	if createdDep.FullchainPath != filepath.Join(remoteCertDir, "example.com", "fullchain.pem") {
		t.Fatalf("derived fullchain_path = %q", createdDep.FullchainPath)
	}
	if !strings.Contains(createdDep.ReloadCommand, "--force") || !strings.Contains(createdDep.ReloadCommand, "caddy-edge") {
		t.Fatalf("derived reload_command = %q", createdDep.ReloadCommand)
	}

	// Deleting host while referenced by deployment -> 409 RESOURCE_IN_USE
	rec = doJSONReq(t, router, http.MethodDelete, hostURL, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("DELETE host in use = %d, want 409", rec.Code)
	}

	// 8. Push deployment & fetch logs
	depURL := "/api/v1/deployments/" + strconv.FormatInt(createdDep.ID, 10)
	rec = doJSONReq(t, router, http.MethodPost, depURL+"/push", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /deployments/{id}/push = %d, body=%s", rec.Code, rec.Body.String())
	}
	env = decodeAPIEnvelope(t, rec)
	var pushLog model.DeployLog
	b, _ = json.Marshal(env.Data)
	_ = json.Unmarshal(b, &pushLog)
	if pushLog.Status != model.JobStatusSuccess {
		t.Fatalf("push status = %q, err=%s", pushLog.Status, pushLog.ErrorMessage)
	}

	rec = doJSONReq(t, router, http.MethodGet, depURL+"/logs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /deployments/{id}/logs = %d", rec.Code)
	}
	env = decodeAPIEnvelope(t, rec)
	var logs []model.DeployLog
	b, _ = json.Marshal(env.Data)
	_ = json.Unmarshal(b, &logs)
	if len(logs) != 1 {
		t.Fatalf("expected 1 deploy log, got %d", len(logs))
	}

	// 9. Update deployment, delete deployment, then delete host
	rec = doJSONReq(t, router, http.MethodPut, depURL, `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /deployments/{id} = %d", rec.Code)
	}
	rec = doJSONReq(t, router, http.MethodDelete, depURL, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /deployments/{id} = %d", rec.Code)
	}
	rec = doJSONReq(t, router, http.MethodDelete, hostURL, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /hosts/{id} after deployment removal = %d, body=%s", rec.Code, rec.Body.String())
	}
	_ = context.Background()
}
