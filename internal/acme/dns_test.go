package acme

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"ssl-center/internal/model"
)

func TestMatchZone_LongestSuffixAndOverride(t *testing.T) {
	zones := []model.DNSZone{
		{ID: "z1", Name: "example.com"},
		{ID: "z2", Name: "a.example.com."},
		{ID: "z3", Name: "notexample.com"},
	}

	z, err := MatchZone("sub.a.example.com", zones, "")
	if err != nil {
		t.Fatalf("MatchZone(sub.a.example.com): %v", err)
	}
	if z.ID != "z2" || z.Name != "a.example.com" {
		t.Fatalf("expected z2 (a.example.com), got %+v", z)
	}

	z, err = MatchZone("*.example.com", zones, "")
	if err != nil {
		t.Fatalf("MatchZone(*.example.com): %v", err)
	}
	if z.ID != "z1" || z.Name != "example.com" {
		t.Fatalf("expected z1 (example.com), got %+v", z)
	}

	z, err = MatchZone("SUB.A.EXAMPLE.COM.", zones, "example.com")
	if err != nil {
		t.Fatalf("MatchZone with override: %v", err)
	}
	if z.ID != "z1" || z.Name != "example.com" {
		t.Fatalf("expected override z1 (example.com), got %+v", z)
	}

	if _, err := MatchZone("sub.a.example.com", zones, "missing.org"); err == nil {
		t.Fatal("expected error for missing zone_override")
	}

	if _, err := MatchZone("other-example.com", zones, ""); err == nil {
		t.Fatal("expected error for non-boundary suffix match")
	}
}

func TestNormalizeChallengeFQDN_WhitespaceAndWildcard(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"_acme-challenge.example.com.", "_acme-challenge.example.com."},
		{"_acme-challenge.*.example.com.", "_acme-challenge.example.com."},
		{"  _acme-challenge.*.example.com.", "_acme-challenge.example.com."},
		{"  _acme-challenge.*.example.com.  ", "_acme-challenge.example.com."},
		{"\t_ACME-CHALLENGE.*.Example.COM.\n", "_acme-challenge.Example.COM."},
		{"  _acme-challenge.sub.example.com. ", "_acme-challenge.sub.example.com."},
	}
	for _, tc := range cases {
		if got := normalizeChallengeFQDN(tc.in); got != tc.want {
			t.Errorf("normalizeChallengeFQDN(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCloudflareProvider_MockHTTP_And_ConcurrentCleanup(t *testing.T) {
	type cfRec struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	}

	var mu sync.Mutex
	nextID := 100
	records := map[string]cfRec{
		"pre-existing": {
			ID:      "pre-existing",
			Type:    "TXT",
			Name:    "_acme-challenge.example.com",
			Content: "pre-existing-txt-value",
			TTL:     120,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf-secret-token-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			page := r.URL.Query().Get("page")
			if page == "" || page == "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"result": []map[string]string{
						{"id": "cf-z1", "name": "example.com"},
					},
					"result_info": map[string]int{"page": 1, "per_page": 50, "total_pages": 2},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result": []map[string]string{
					{"id": "cf-z2", "name": "sub.example.com"},
				},
				"result_info": map[string]int{"page": 2, "per_page": 50, "total_pages": 2},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/zones/cf-z1/dns_records":
			var body cfRec
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			nextID++
			body.ID = fmt.Sprintf("rec-%d", nextID)
			records[body.ID] = body
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  body,
			})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/cf-z1/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/cf-z1/dns_records/")
			mu.Lock()
			_, exists := records[id]
			delete(records, id)
			mu.Unlock()
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := NewCloudflareProvider("cf-secret-token-123", srv.URL, srv.Client())

	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 paginated zones, got %d", len(zones))
	}

	// Concurrent apex + wildcard Present and CleanUp.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := p.Present("example.com", "tok-apex", "keyauth-apex"); err != nil {
			t.Errorf("Present apex: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := p.Present("*.example.com", "tok-wild", "keyauth-wild"); err != nil {
			t.Errorf("Present wildcard: %v", err)
		}
	}()
	wg.Wait()

	mu.Lock()
	if len(records) != 3 {
		t.Fatalf("expected 3 TXT records (pre-existing + apex + wildcard), got %d", len(records))
	}
	mu.Unlock()

	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := p.CleanUp("example.com", "tok-apex", "keyauth-apex"); err != nil {
			t.Errorf("CleanUp apex: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := p.CleanUp("*.example.com", "tok-wild", "keyauth-wild"); err != nil {
			t.Errorf("CleanUp wildcard: %v", err)
		}
	}()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(records) != 1 {
		t.Fatalf("expected pre-existing TXT record to survive, got %+v", records)
	}
	if _, ok := records["pre-existing"]; !ok {
		t.Fatal("pre-existing TXT record was unexpectedly deleted")
	}
}

func TestHuaweiCloudProvider_Signing_And_ConcurrentMultiValueTXTCleanup(t *testing.T) {
	const (
		testAK = "HUAWEI_ACCESS_KEY_TEST"
		testSK = "HUAWEI_SECRET_KEY_TEST_987654"
	)

	// Verify SDK-HMAC-SHA256 signature server-side on every mock request.
	verifyHuaweiSig := func(r *http.Request, body []byte) error {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "SDK-HMAC-SHA256 ") {
			return fmt.Errorf("missing SDK-HMAC-SHA256 header: %q", auth)
		}
		sdkDate := r.Header.Get(huaweiHeaderDate)
		if sdkDate == "" {
			return fmt.Errorf("missing %s header", huaweiHeaderDate)
		}
		if gotHash := r.Header.Get(huaweiHeaderContentSHA256); gotHash != sha256Hex(body) {
			return fmt.Errorf("payload hash mismatch: got %s want %s", gotHash, sha256Hex(body))
		}

		// Recompute signature using server's secret key.
		parts := strings.Split(strings.TrimPrefix(auth, "SDK-HMAC-SHA256 "), ",")
		kv := make(map[string]string)
		for _, p := range parts {
			kvPair := strings.SplitN(strings.TrimSpace(p), "=", 2)
			if len(kvPair) == 2 {
				kv[kvPair[0]] = kvPair[1]
			}
		}
		if kv["Access"] != testAK {
			return fmt.Errorf("unexpected AK %q", kv["Access"])
		}
		signedHeaderNames := strings.Split(kv["SignedHeaders"], ";")
		var canonHeaders strings.Builder
		for _, hName := range signedHeaderNames {
			var vals []string
			if hName == "host" {
				vals = []string{r.Host}
			} else {
				vals = r.Header.Values(hName)
			}
			canonHeaders.WriteString(hName)
			canonHeaders.WriteByte(':')
			canonHeaders.WriteString(strings.Join(vals, ","))
			canonHeaders.WriteByte('\n')
		}
		canonReq := strings.Join([]string{
			r.Method,
			huaweiCanonicalURI(r.URL.Path),
			huaweiCanonicalQuery(r.URL.Query()),
			canonHeaders.String(),
			kv["SignedHeaders"],
			sha256Hex(body),
		}, "\n")
		strToSign := strings.Join([]string{
			huaweiSignAlgorithm,
			sdkDate,
			sha256Hex([]byte(canonReq)),
		}, "\n")
		mac := hmac.New(sha256.New, []byte(testSK))
		_, _ = mac.Write([]byte(strToSign))
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		if kv["Signature"] != expectedSig {
			return fmt.Errorf("signature mismatch: got %s want %s", kv["Signature"], expectedSig)
		}
		return nil
	}

	type rsState struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Type    string   `json:"type"`
		TTL     int      `json:"ttl"`
		Records []string `json:"records"`
	}

	var mu sync.Mutex
	// Pre-populate a same-name TXT record on _acme-challenge.example.com.
	rrsets := map[string]*rsState{
		"rs-existing": {
			ID:      "rs-existing",
			Name:    "_acme-challenge.example.com.",
			Type:    "TXT",
			TTL:     300,
			Records: []string{`"pre-existing-verification-token"`},
		},
	}
	nextRS := 1
	deleteCalled := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err := verifyHuaweiSig(r, body); err != nil {
			t.Errorf("huawei signature verification failed: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"zones": []map[string]string{
					{"id": "hw-z1", "name": "example.com.", "status": "ACTIVE"},
				},
				"metadata": map[string]int{"total_count": 1},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/v2/zones/hw-z1/recordsets":
			mu.Lock()
			list := make([]rsState, 0, len(rrsets))
			for _, rs := range rrsets {
				cp := *rs
				cp.Records = append([]string(nil), rs.Records...)
				list = append(list, cp)
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recordsets": list,
				"metadata":   map[string]int{"total_count": len(list)},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/v2/zones/hw-z1/recordsets":
			var req rsState
			_ = json.Unmarshal(body, &req)
			mu.Lock()
			nextRS++
			req.ID = fmt.Sprintf("rs-%d", nextRS)
			rrsets[req.ID] = &req
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(req)

		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v2/zones/hw-z1/recordsets/"):
			id := strings.TrimPrefix(r.URL.Path, "/v2/zones/hw-z1/recordsets/")
			var req rsState
			_ = json.Unmarshal(body, &req)
			mu.Lock()
			existing, ok := rrsets[id]
			var respCopy rsState
			if ok {
				existing.Records = append([]string(nil), req.Records...)
				existing.TTL = req.TTL
				respCopy = *existing
				respCopy.Records = append([]string(nil), existing.Records...)
			}
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(respCopy)

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v2/zones/hw-z1/recordsets/"):
			id := strings.TrimPrefix(r.URL.Path, "/v2/zones/hw-z1/recordsets/")
			mu.Lock()
			deleteCalled++
			delete(rrsets, id)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	locks := newZoneLockRegistry()
	p := NewHuaweiCloudProvider(testAK, testSK, "cn-north-4", srv.URL, srv.Client(), locks)
	p.nowFn = func() time.Time { return time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC) }

	// Concurrent Present for apex + wildcard (both target _acme-challenge.example.com. RRset).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := p.Present("example.com", "tok1", "keyauth-apex-1"); err != nil {
			t.Errorf("Present apex: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := p.Present("*.example.com", "tok2", "keyauth-wild-2"); err != nil {
			t.Errorf("Present wildcard: %v", err)
		}
	}()
	wg.Wait()

	mu.Lock()
	rs := rrsets["rs-existing"]
	if rs == nil || len(rs.Records) != 3 {
		all := make(map[string]rsState, len(rrsets))
		for k, v := range rrsets {
			all[k] = *v
		}
		mu.Unlock()
		t.Fatalf("expected 3 TXT values (pre-existing + apex + wildcard), got rs=%+v all=%+v", rs, all)
	}
	mu.Unlock()

	// Concurrent CleanUp must remove ONLY the two ACME values and NEVER delete the RRset because pre-existing remains.
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := p.CleanUp("example.com", "tok1", "keyauth-apex-1"); err != nil {
			t.Errorf("CleanUp apex: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := p.CleanUp("*.example.com", "tok2", "keyauth-wild-2"); err != nil {
			t.Errorf("CleanUp wildcard: %v", err)
		}
	}()
	wg.Wait()

	mu.Lock()
	if deleteCalled != 0 {
		t.Fatalf("expected 0 DELETE calls when pre-existing TXT survives, got %d", deleteCalled)
	}
	if len(rs.Records) != 1 || rs.Records[0] != `"pre-existing-verification-token"` {
		t.Fatalf("expected only pre-existing TXT record to remain, got %+v", rs.Records)
	}

	// Now remove the pre-existing RRset manually and verify CleanUp deletes RRset ONLY when empty.
	delete(rrsets, "rs-existing")
	mu.Unlock()

	if err := p.Present("sub.example.com", "tok3", "keyauth-sub-3"); err != nil {
		t.Fatalf("Present sub.example.com: %v", err)
	}
	if err := p.CleanUp("sub.example.com", "tok3", "keyauth-sub-3"); err != nil {
		t.Fatalf("CleanUp sub.example.com: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if deleteCalled != 1 || len(rrsets) != 0 {
		t.Fatalf("expected RRset deletion when empty: deleteCalled=%d remaining=%d", deleteCalled, len(rrsets))
	}

	// Verify quoting/unquoting helper preserves exact ACME TXT value.
	_, val := dns01.GetRecord("example.com", "keyauth-apex-1")
	if got := unquoteTXTValue(quoteTXTValue(val)); got != val {
		t.Fatalf("quote/unquote roundtrip mismatch: got %q want %q", got, val)
	}
}

func TestDNSService_PartialSecretUpdate_Test_And_Redaction(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer initial-cf-token-xyz" && auth != "Bearer rotated-cf-token-999" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"result": []map[string]string{
				{"id": "z-a", "name": "example.com"},
				{"id": "z-b", "name": "a.example.com"},
			},
			"result_info": map[string]int{"page": 1, "per_page": 50, "total_pages": 1},
		})
	}))
	defer srv.Close()

	dnsSvc := NewDNSService(env.db, env.cipher, env.redactor,
		WithDNSHTTPClient(srv.Client()),
		WithCloudflareBaseURL(srv.URL),
	)

	dto, err := dnsSvc.CreateCredential(ctx, model.CreateDNSRequest{
		Name:     "CF Main",
		Provider: model.DNSProviderCloudflare,
		APIToken: "initial-cf-token-xyz",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if !dto.HasSecret {
		t.Fatal("expected HasSecret=true")
	}

	// Verify SecretRedactor masks initial token.
	if got := env.redactor.Redact("token=initial-cf-token-xyz"); strings.Contains(got, "initial-cf-token-xyz") {
		t.Fatal("expected initial DNS token to be redacted")
	}

	// Partial update omitting/empty api_token must preserve existing secret.
	emptyTok := ""
	newName := "CF Main Renamed"
	updated, err := dnsSvc.UpdateCredential(ctx, dto.ID, model.UpdateDNSRequest{
		Name:     &newName,
		APIToken: &emptyTok,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpdateCredential preserve secret: %v", err)
	}
	if updated.Name != newName {
		t.Fatalf("expected updated name %q, got %q", newName, updated.Name)
	}

	testResp, err := dnsSvc.TestCredential(ctx, dto.ID)
	if err != nil || !testResp.OK || len(testResp.Zones) != 2 {
		t.Fatalf("TestCredential after name-only update failed: resp=%+v err=%v", testResp, err)
	}

	// Zone longest-suffix matching endpoint helper.
	zonesResp, err := dnsSvc.ListZonesForDomain(ctx, dto.ID, "api.a.example.com")
	if err != nil {
		t.Fatalf("ListZonesForDomain: %v", err)
	}
	if zonesResp.MatchedZone != "a.example.com" {
		t.Fatalf("expected longest-suffix matched_zone=a.example.com, got %q", zonesResp.MatchedZone)
	}

	// Rotate secret and verify old token removed and new token added to SecretRedactor.
	rotTok := "rotated-cf-token-999"
	if _, err := dnsSvc.UpdateCredential(ctx, dto.ID, model.UpdateDNSRequest{
		APIToken: &rotTok,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("UpdateCredential rotate token: %v", err)
	}
	if got := env.redactor.Redact("new=rotated-cf-token-999"); strings.Contains(got, "rotated-cf-token-999") {
		t.Fatal("expected rotated token to be redacted")
	}
	if got := env.redactor.Redact("old=initial-cf-token-xyz"); !strings.Contains(got, "initial-cf-token-xyz") {
		t.Fatal("expected old rotated-out token to be removed from SecretRedactor")
	}
}
