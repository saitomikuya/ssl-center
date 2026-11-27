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
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"ssl-center/internal/model"
)

const (
	huaweiHeaderDate          = "X-Sdk-Date"
	huaweiHeaderContentSHA256 = "X-Sdk-Content-Sha256"
	huaweiSignAlgorithm       = "SDK-HMAC-SHA256"
)

func normalizeHuaweiRegion(raw string) string {
	r := strings.TrimSpace(raw)
	switch strings.ToLower(r) {
	case "", "domestic", "cn", "china":
		return "cn-north-4"
	case "international", "intl", "global":
		return "ap-southeast-1"
	default:
		return r
	}
}

// HuaweiCloudProvider implements DNSProvider for Huawei Cloud DNS v2
// with authentic SDK-HMAC-SHA256 request signing and per-zone mutex TXT read-modify-write.
type HuaweiCloudProvider struct {
	accessKey    string
	secretKey    string
	region       string
	baseURL      string
	httpClient   *http.Client
	zoneLocks    *zoneLockRegistry
	zoneOverride string
	nowFn        func() time.Time

	mu sync.Mutex
}

// NewHuaweiCloudProvider constructs a HuaweiCloudProvider with injectable baseURL, httpClient, and lock registry.
func NewHuaweiCloudProvider(accessKey, secretKey, region, baseURL string, httpClient *http.Client, locks *zoneLockRegistry) *HuaweiCloudProvider {
	region = normalizeHuaweiRegion(region)
	if strings.TrimSpace(baseURL) == "" {
		baseURL = fmt.Sprintf("https://dns.%s.myhuaweicloud.com", region)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if locks == nil {
		locks = newZoneLockRegistry()
	}
	return &HuaweiCloudProvider{
		accessKey:  accessKey,
		secretKey:  secretKey,
		region:     region,
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		zoneLocks:  locks,
		nowFn:      func() time.Time { return time.Now().UTC() },
	}
}

func (p *HuaweiCloudProvider) SetZoneOverride(zone string) {
	p.mu.Lock()
	p.zoneOverride = strings.TrimSpace(zone)
	p.mu.Unlock()
}

func (p *HuaweiCloudProvider) getZoneOverride() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.zoneOverride
}

func (p *HuaweiCloudProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

type huaweiZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type huaweiMetadata struct {
	TotalCount int `json:"total_count"`
}

type huaweiListZonesResp struct {
	Zones    []huaweiZone   `json:"zones"`
	Metadata huaweiMetadata `json:"metadata"`
}

type huaweiRecordSet struct {
	ID      string   `json:"id,omitempty"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl,omitempty"`
	Records []string `json:"records"`
	Status  string   `json:"status,omitempty"`
}

type huaweiListRecordSetsResp struct {
	RecordSets []huaweiRecordSet `json:"recordsets"`
	Metadata   huaweiMetadata    `json:"metadata"`
}

// ListZones fetches all visible public DNS zones from Huawei Cloud DNS v2.
func (p *HuaweiCloudProvider) ListZones(ctx context.Context) ([]model.DNSZone, error) {
	zones := make([]model.DNSZone, 0)
	offset := 0
	const limit = 500
	for {
		u := fmt.Sprintf("%s/v2/zones?type=public&limit=%d&offset=%d", p.baseURL, limit, offset)
		var resp huaweiListZonesResp
		if err := p.doJSON(ctx, http.MethodGet, u, nil, &resp); err != nil {
			return nil, err
		}
		for _, z := range resp.Zones {
			zones = append(zones, model.DNSZone{
				ID:   z.ID,
				Name: model.NormalizeDomain(z.Name),
			})
		}
		offset += len(resp.Zones)
		if len(resp.Zones) == 0 || (resp.Metadata.TotalCount > 0 && offset >= resp.Metadata.TotalCount) || len(resp.Zones) < limit {
			break
		}
	}
	return zones, nil
}

// Present adds the ACME TXT record value to the RRset under a per-zone mutex,
// preserving any pre-existing or concurrent TXT values on the same record name.
func (p *HuaweiCloudProvider) Present(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info := dns01.GetChallengeInfo(domain, keyAuth)
	effectiveFQDN := normalizeChallengeFQDN(info.EffectiveFQDN)
	fqdn := dns01.ToFqdn(effectiveFQDN)

	zones, err := p.ListZones(ctx)
	if err != nil {
		return err
	}
	zone, err := p.resolveZone(domain, effectiveFQDN, zones)
	if err != nil {
		return err
	}

	zLock := p.zoneLocks.get("huawei:" + zone.ID)
	zLock.Lock()
	defer zLock.Unlock()

	existing, err := p.findTXTRecordSet(ctx, zone.ID, fqdn)
	if err != nil {
		return err
	}

	quotedVal := quoteTXTValue(info.Value)
	if existing == nil {
		reqBody := huaweiRecordSet{
			Name:    fqdn,
			Type:    "TXT",
			TTL:     60,
			Records: []string{quotedVal},
		}
		createURL := fmt.Sprintf("%s/v2/zones/%s/recordsets", p.baseURL, url.PathEscape(zone.ID))
		return p.doJSON(ctx, http.MethodPost, createURL, reqBody, nil)
	}

	for _, rec := range existing.Records {
		if unquoteTXTValue(rec) == info.Value {
			return nil
		}
	}

	updated := make([]string, 0, len(existing.Records)+1)
	updated = append(updated, existing.Records...)
	updated = append(updated, quotedVal)

	ttl := existing.TTL
	if ttl <= 0 {
		ttl = 60
	}
	reqBody := huaweiRecordSet{
		Name:    existing.Name,
		Type:    "TXT",
		TTL:     ttl,
		Records: updated,
	}
	putURL := fmt.Sprintf("%s/v2/zones/%s/recordsets/%s", p.baseURL, url.PathEscape(zone.ID), url.PathEscape(existing.ID))
	return p.doJSON(ctx, http.MethodPut, putURL, reqBody, nil)
}

// CleanUp removes ONLY the TXT value written for this challenge under a per-zone mutex,
// deleting the RRset ONLY when no other TXT values remain.
func (p *HuaweiCloudProvider) CleanUp(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info := dns01.GetChallengeInfo(domain, keyAuth)
	effectiveFQDN := normalizeChallengeFQDN(info.EffectiveFQDN)
	fqdn := dns01.ToFqdn(effectiveFQDN)

	zones, err := p.ListZones(ctx)
	if err != nil {
		return err
	}
	zone, err := p.resolveZone(domain, effectiveFQDN, zones)
	if err != nil {
		return err
	}

	zLock := p.zoneLocks.get("huawei:" + zone.ID)
	zLock.Lock()
	defer zLock.Unlock()

	existing, err := p.findTXTRecordSet(ctx, zone.ID, fqdn)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil
	}

	remaining := make([]string, 0, len(existing.Records))
	removed := false
	for _, rec := range existing.Records {
		if !removed && unquoteTXTValue(rec) == info.Value {
			removed = true
			continue
		}
		remaining = append(remaining, rec)
	}
	if !removed {
		return nil
	}

	if len(remaining) == 0 {
		delURL := fmt.Sprintf("%s/v2/zones/%s/recordsets/%s", p.baseURL, url.PathEscape(zone.ID), url.PathEscape(existing.ID))
		return p.doJSON(ctx, http.MethodDelete, delURL, nil, nil)
	}

	ttl := existing.TTL
	if ttl <= 0 {
		ttl = 60
	}
	reqBody := huaweiRecordSet{
		Name:    existing.Name,
		Type:    "TXT",
		TTL:     ttl,
		Records: remaining,
	}
	putURL := fmt.Sprintf("%s/v2/zones/%s/recordsets/%s", p.baseURL, url.PathEscape(zone.ID), url.PathEscape(existing.ID))
	return p.doJSON(ctx, http.MethodPut, putURL, reqBody, nil)
}

func (p *HuaweiCloudProvider) findTXTRecordSet(ctx context.Context, zoneID, fqdn string) (*huaweiRecordSet, error) {
	q := url.Values{}
	q.Set("name", fqdn)
	q.Set("type", "TXT")
	listURL := fmt.Sprintf("%s/v2/zones/%s/recordsets?%s", p.baseURL, url.PathEscape(zoneID), q.Encode())

	var resp huaweiListRecordSetsResp
	if err := p.doJSON(ctx, http.MethodGet, listURL, nil, &resp); err != nil {
		return nil, err
	}

	target := model.NormalizeDomain(fqdn)
	for i := range resp.RecordSets {
		rs := &resp.RecordSets[i]
		if model.NormalizeDomain(rs.Name) == target && strings.EqualFold(rs.Type, "TXT") {
			return rs, nil
		}
	}
	return nil, nil
}

func (p *HuaweiCloudProvider) resolveZone(domain, effectiveFQDN string, zones []model.DNSZone) (model.DNSZone, error) {
	override := p.getZoneOverride()
	if override != "" {
		return MatchZone(domain, zones, override)
	}
	if z, err := MatchZone(effectiveFQDN, zones, ""); err == nil {
		return z, nil
	}
	return MatchZone(domain, zones, "")
}

func (p *HuaweiCloudProvider) doJSON(ctx context.Context, method, rawURL string, reqBody, dst any) error {
	var bodyBytes []byte
	var err error
	if reqBody != nil {
		bodyBytes, err = json.Marshal(reqBody)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json;charset=utf8")
	req.Header.Set("Accept", "application/json")

	if err := SignHuaweiRequest(req, bodyBytes, p.accessKey, p.secretKey, p.nowFn()); err != nil {
		return fmt.Errorf("sign huawei request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			ErrMsg  string `json:"error_msg"`
		}
		if json.Unmarshal(data, &errBody) == nil && (errBody.Message != "" || errBody.ErrMsg != "") {
			msg := errBody.Message
			if msg == "" {
				msg = errBody.ErrMsg
			}
			return fmt.Errorf("huaweicloud HTTP %d (%s): %s", resp.StatusCode, errBody.Code, msg)
		}
		return fmt.Errorf("huaweicloud HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if dst != nil && len(data) > 0 {
		if err := json.Unmarshal(data, dst); err != nil {
			return fmt.Errorf("decode huaweicloud response: %w", err)
		}
	}
	return nil
}

// SignHuaweiRequest signs req in-place using Huawei Cloud API Gateway SDK-HMAC-SHA256.
func SignHuaweiRequest(req *http.Request, body []byte, accessKey, secretKey string, now time.Time) error {
	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("empty accessKey or secretKey")
	}
	if req.Header.Get(huaweiHeaderDate) == "" {
		req.Header.Set(huaweiHeaderDate, now.UTC().Format("20060102T150405Z"))
	}
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	req.Header.Set("Host", req.Host)

	payloadHash := sha256Hex(body)
	req.Header.Set(huaweiHeaderContentSHA256, payloadHash)

	canonicalURI := huaweiCanonicalURI(req.URL.Path)
	canonicalQuery := huaweiCanonicalQuery(req.URL.Query())
	canonicalHeaders, signedHeaders := huaweiCanonicalHeaders(req.Header)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	sdkDate := req.Header.Get(huaweiHeaderDate)
	stringToSign := strings.Join([]string{
		huaweiSignAlgorithm,
		sdkDate,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	mac := hmac.New(sha256.New, []byte(secretKey))
	_, _ = mac.Write([]byte(stringToSign))
	signature := hex.EncodeToString(mac.Sum(nil))

	authHeader := fmt.Sprintf("%s Access=%s, SignedHeaders=%s, Signature=%s",
		huaweiSignAlgorithm, accessKey, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
	return nil
}

func huaweiCanonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	rawSegments := strings.Split(path, "/")
	escaped := make([]string, 0, len(rawSegments))
	for _, seg := range rawSegments {
		escaped = append(escaped, rfc3986Escape(seg))
	}
	uri := strings.Join(escaped, "/")
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	if !strings.HasSuffix(uri, "/") {
		uri += "/"
	}
	return uri
}

func huaweiCanonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := append([]string(nil), values[k]...)
		sort.Strings(vals)
		ek := rfc3986Escape(k)
		for _, v := range vals {
			parts = append(parts, ek+"="+rfc3986Escape(v))
		}
	}
	return strings.Join(parts, "&")
}

func huaweiCanonicalHeaders(h http.Header) (string, string) {
	lowerMap := make(map[string][]string, len(h))
	names := make([]string, 0, len(h))
	for k, vals := range h {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "" || lk == "authorization" {
			continue
		}
		if _, exists := lowerMap[lk]; !exists {
			names = append(names, lk)
		}
		cleaned := make([]string, len(vals))
		for i, v := range vals {
			cleaned[i] = strings.TrimSpace(v)
		}
		sort.Strings(cleaned)
		lowerMap[lk] = append(lowerMap[lk], cleaned...)
	}
	sort.Strings(names)

	var buf strings.Builder
	for _, name := range names {
		buf.WriteString(name)
		buf.WriteByte(':')
		buf.WriteString(strings.Join(lowerMap[name], ","))
		buf.WriteByte('\n')
	}
	return buf.String(), strings.Join(names, ";")
}

func rfc3986Escape(s string) string {
	var buf strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			buf.WriteByte(c)
		} else {
			fmt.Fprintf(&buf, "%%%02X", c)
		}
	}
	return buf.String()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// quoteTXTValue formats a TXT record string for Huawei Cloud DNS v2 (double-quoted).
func quoteTXTValue(val string) string {
	unquoted := unquoteTXTValue(val)
	escaped := strings.ReplaceAll(unquoted, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// unquoteTXTValue normalizes a TXT record value returned by Huawei Cloud DNS v2
// by stripping surrounding quotes and unescaping backslash-escaped characters.
func unquoteTXTValue(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		inner = strings.ReplaceAll(inner, `\"`, `"`)
		inner = strings.ReplaceAll(inner, `\\`, `\`)
		return inner
	}
	return s
}
