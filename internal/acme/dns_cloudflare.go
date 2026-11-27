package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"ssl-center/internal/model"
)

const defaultCloudflareBaseURL = "https://api.cloudflare.com/client/v4"

type cfRecordRef struct {
	zoneID   string
	recordID string
}

// CloudflareProvider implements DNSProvider using Cloudflare API v4 (API Token).
type CloudflareProvider struct {
	apiToken     string
	baseURL      string
	httpClient   *http.Client
	zoneOverride string

	mu      sync.Mutex
	records map[string]cfRecordRef
}

// NewCloudflareProvider creates a CloudflareProvider with injectable baseURL and httpClient.
func NewCloudflareProvider(apiToken, baseURL string, httpClient *http.Client) *CloudflareProvider {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultCloudflareBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &CloudflareProvider{
		apiToken:   apiToken,
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		records:    make(map[string]cfRecordRef),
	}
}

func (p *CloudflareProvider) SetZoneOverride(zone string) {
	p.mu.Lock()
	p.zoneOverride = strings.TrimSpace(zone)
	p.mu.Unlock()
}

func (p *CloudflareProvider) getZoneOverride() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.zoneOverride
}

func (p *CloudflareProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

type cfZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type cfListZonesResp struct {
	Success    bool         `json:"success"`
	Errors     []cfAPIError `json:"errors"`
	Result     []cfZone     `json:"result"`
	ResultInfo cfResultInfo `json:"result_info"`
}

type cfDNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

type cfDNSRecordResp struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
	Result  cfDNSRecord  `json:"result"`
}

type cfListDNSRecordsResp struct {
	Success bool          `json:"success"`
	Errors  []cfAPIError  `json:"errors"`
	Result  []cfDNSRecord `json:"result"`
}

// ListZones fetches all visible Cloudflare zones using pagination.
func (p *CloudflareProvider) ListZones(ctx context.Context) ([]model.DNSZone, error) {
	zones := make([]model.DNSZone, 0)
	page := 1
	for {
		u := fmt.Sprintf("%s/zones?per_page=50&page=%d", p.baseURL, page)
		var resp cfListZonesResp
		if err := p.doJSON(ctx, http.MethodGet, u, nil, &resp); err != nil {
			return nil, err
		}
		if !resp.Success {
			return nil, fmt.Errorf("cloudflare list zones failed: %s", formatCFErrors(resp.Errors))
		}
		for _, z := range resp.Result {
			zones = append(zones, model.DNSZone{
				ID:   z.ID,
				Name: model.NormalizeDomain(z.Name),
			})
		}
		if resp.ResultInfo.TotalPages <= page || len(resp.Result) == 0 {
			break
		}
		page++
	}
	return zones, nil
}

// Present creates a TXT record for the ACME DNS-01 challenge.
func (p *CloudflareProvider) Present(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := dns01.UnFqdn(normalizeChallengeFQDN(info.EffectiveFQDN))

	zones, err := p.ListZones(ctx)
	if err != nil {
		return err
	}

	zone, err := p.resolveZone(domain, fqdn, zones)
	if err != nil {
		return err
	}

	reqBody := cfDNSRecord{
		Type:    "TXT",
		Name:    fqdn,
		Content: info.Value,
		TTL:     120,
	}
	var resp cfDNSRecordResp
	u := fmt.Sprintf("%s/zones/%s/dns_records", p.baseURL, url.PathEscape(zone.ID))
	if err := p.doJSON(ctx, http.MethodPost, u, reqBody, &resp); err != nil {
		return fmt.Errorf("cloudflare create TXT record for %s: %w", fqdn, err)
	}
	if !resp.Success {
		return fmt.Errorf("cloudflare create TXT record for %s: %s", fqdn, formatCFErrors(resp.Errors))
	}

	p.mu.Lock()
	p.records[cfRecordKey(fqdn, info.Value)] = cfRecordRef{
		zoneID:   zone.ID,
		recordID: resp.Result.ID,
	}
	p.mu.Unlock()
	return nil
}

// CleanUp deletes ONLY the TXT record created for this challenge.
func (p *CloudflareProvider) CleanUp(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := dns01.UnFqdn(normalizeChallengeFQDN(info.EffectiveFQDN))
	key := cfRecordKey(fqdn, info.Value)

	p.mu.Lock()
	ref, ok := p.records[key]
	if ok {
		delete(p.records, key)
	}
	p.mu.Unlock()

	if !ok || ref.recordID == "" {
		// Fallback lookup by exact TXT name and content.
		zones, err := p.ListZones(ctx)
		if err != nil {
			return err
		}
		zone, err := p.resolveZone(domain, fqdn, zones)
		if err != nil {
			return err
		}
		q := url.Values{}
		q.Set("type", "TXT")
		q.Set("name", fqdn)
		q.Set("content", info.Value)
		listURL := fmt.Sprintf("%s/zones/%s/dns_records?%s", p.baseURL, url.PathEscape(zone.ID), q.Encode())
		var listResp cfListDNSRecordsResp
		if err := p.doJSON(ctx, http.MethodGet, listURL, nil, &listResp); err != nil {
			return err
		}
		if !listResp.Success {
			return fmt.Errorf("cloudflare lookup TXT record: %s", formatCFErrors(listResp.Errors))
		}
		for _, rec := range listResp.Result {
			if strings.EqualFold(dns01.UnFqdn(rec.Name), fqdn) && rec.Content == info.Value {
				delURL := fmt.Sprintf("%s/zones/%s/dns_records/%s", p.baseURL, url.PathEscape(zone.ID), url.PathEscape(rec.ID))
				if err := p.doJSON(ctx, http.MethodDelete, delURL, nil, nil); err != nil {
					return err
				}
			}
		}
		return nil
	}

	delURL := fmt.Sprintf("%s/zones/%s/dns_records/%s", p.baseURL, url.PathEscape(ref.zoneID), url.PathEscape(ref.recordID))
	return p.doJSON(ctx, http.MethodDelete, delURL, nil, nil)
}

func (p *CloudflareProvider) resolveZone(domain, fqdn string, zones []model.DNSZone) (model.DNSZone, error) {
	override := p.getZoneOverride()
	if override != "" {
		return MatchZone(domain, zones, override)
	}
	if z, err := MatchZone(fqdn, zones, ""); err == nil {
		return z, nil
	}
	return MatchZone(domain, zones, "")
}

func (p *CloudflareProvider) doJSON(ctx context.Context, method, rawURL string, reqBody, dst any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

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
		var errWrap struct {
			Errors []cfAPIError `json:"errors"`
		}
		if json.Unmarshal(data, &errWrap) == nil && len(errWrap.Errors) > 0 {
			return fmt.Errorf("cloudflare HTTP %d: %s", resp.StatusCode, formatCFErrors(errWrap.Errors))
		}
		return fmt.Errorf("cloudflare HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if dst != nil && len(data) > 0 {
		if err := json.Unmarshal(data, dst); err != nil {
			return fmt.Errorf("decode cloudflare response: %w", err)
		}
	}
	return nil
}

func cfRecordKey(fqdn, value string) string {
	return strings.ToLower(fqdn) + "\x00" + value
}

func formatCFErrors(errs []cfAPIError) string {
	if len(errs) == 0 {
		return "unknown cloudflare API error"
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, fmt.Sprintf("[%d] %s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}
