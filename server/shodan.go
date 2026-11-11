package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	shodanBaseURL       = "https://api.shodan.io"
	shodanMinInterval   = 1100 * time.Millisecond // Shodan allows ~1 request/second per key
	shodanMaxAttempts   = 4                       // per IP, for rate-limit / network / 5xx errors
	shodanMaxBodyBytes  = 64 << 20
	shodanRequestTimout = 60 * time.Second
)

var (
	errNotFound     = errors.New("no information available for that IP")
	errNoUsableKeys = errors.New("no usable Shodan API key left")
	errNoKeys       = errors.New("no Shodan API key configured")
)

// apiError is an error answer from the Shodan API. It never contains the API key.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	msg := e.Message
	if msg == "" {
		switch {
		case e.Status == http.StatusUnauthorized:
			msg = "invalid API key"
		case e.Status == http.StatusForbidden:
			msg = "access denied - the Shodan plan may not include this"
		case e.Status == http.StatusPaymentRequired:
			msg = "not enough credits"
		case e.Status == http.StatusTooManyRequests:
			msg = "rate limit reached"
		case e.Status >= 500:
			msg = "Shodan server error"
		default:
			return fmt.Sprintf("Shodan returned HTTP %d", e.Status)
		}
	}
	return fmt.Sprintf("Shodan: %s (HTTP %d)", msg, e.Status)
}

type errKind int

const (
	kindOther errKind = iota
	kindNotFound
	kindKeyInvalid
	kindKeyDenied
	kindNoCredits
	kindRetry // rate limit, 5xx, network
)

func classify(status int, msg string) errKind {
	low := strings.ToLower(msg)
	switch {
	case status == http.StatusNotFound || strings.Contains(low, "no information available"):
		return kindNotFound
	case strings.Contains(low, "insufficient") || strings.Contains(low, "credits") || status == http.StatusPaymentRequired:
		return kindNoCredits
	case status == http.StatusUnauthorized || strings.Contains(low, "invalid api key"):
		return kindKeyInvalid
	case status == http.StatusForbidden || strings.Contains(low, "access denied") ||
		strings.Contains(low, "membership") || strings.Contains(low, "upgrade your"):
		return kindKeyDenied
	case status == http.StatusTooManyRequests || strings.Contains(low, "rate limit") ||
		strings.Contains(low, "request limit") || status >= 500:
		return kindRetry
	}
	return kindOther
}

type apiKey struct {
	value       string
	nextAllowed time.Time
	disabled    string // why the key is skipped for the rest of this run ("" = usable)
}

// shodanClient talks to the Shodan REST API. One client is created per run,
// so a key that fails is skipped only for that run.
type shodanClient struct {
	baseURL     string
	httpClient  *http.Client
	minInterval time.Duration
	maxAttempts int
	sleep       func(ctx context.Context, d time.Duration) error

	mu   sync.Mutex
	keys []*apiKey
	next int
}

func newShodanClient(keys []string) *shodanClient {
	c := &shodanClient{
		baseURL:     shodanBaseURL,
		httpClient:  &http.Client{Timeout: shodanRequestTimout},
		minInterval: shodanMinInterval,
		maxAttempts: shodanMaxAttempts,
		sleep:       sleepCtx,
	}
	// Testing hook: point the plugin at a fake Shodan API (set on the Mattermost server process).
	if u := os.Getenv("SHODAN_MONITOR_API_URL"); u != "" {
		c.baseURL = strings.TrimRight(u, "/")
	}
	for _, k := range keys {
		c.keys = append(c.keys, &apiKey{value: k})
	}
	return c
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// pickKey returns the next usable key in turn.
func (c *shodanClient) pickKey() (*apiKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.keys) == 0 {
		return nil, errNoKeys
	}
	for i := 0; i < len(c.keys); i++ {
		k := c.keys[(c.next+i)%len(c.keys)]
		if k.disabled == "" {
			c.next = (c.next + i + 1) % len(c.keys)
			return k, nil
		}
	}
	return nil, errNoUsableKeys
}

func (c *shodanClient) disable(k *apiKey, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k.disabled == "" {
		k.disabled = reason
	}
}

// KeyWarnings lists the keys that were skipped during this run (masked).
func (c *shodanClient) KeyWarnings() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, k := range c.keys {
		if k.disabled != "" {
			out = append(out, fmt.Sprintf("API key %s was skipped: %s", maskKey(k.value), k.disabled))
		}
	}
	return out
}

// reserve waits until the key may be used again (rate limit per key).
func (c *shodanClient) reserve(ctx context.Context, k *apiKey) error {
	c.mu.Lock()
	now := time.Now()
	start := k.nextAllowed
	if start.Before(now) {
		start = now
	}
	k.nextAllowed = start.Add(c.minInterval)
	c.mu.Unlock()
	return c.sleep(ctx, time.Until(start))
}

func (c *shodanClient) penalise(k *apiKey, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t := time.Now().Add(d); t.After(k.nextAllowed) {
		k.nextAllowed = t
	}
}

// request performs one HTTP call with the given key. Network errors are
// returned without the request URL, so the key never leaks into messages.
func (c *shodanClient) request(ctx context.Context, k *apiKey, method, path string, form url.Values) (int, []byte, error) {
	if err := c.reserve(ctx, k); err != nil {
		return 0, nil, err
	}
	u := c.baseURL + path + "?key=" + url.QueryEscape(k.value)
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return 0, nil, errors.New("could not build the Shodan request")
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		if uerr, ok := errors.AsType[*url.Error](err); ok {
			err = uerr.Err
		}
		return 0, nil, fmt.Errorf("unable to connect to Shodan: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, shodanMaxBodyBytes))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("error reading the Shodan response: %v", err)
	}
	return resp.StatusCode, data, nil
}

// errorMessage extracts {"error": "..."} from a Shodan response body.
func errorMessage(data []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		return truncateRunes(e.Error, 300)
	}
	return "" // HTML / plain-text error pages are not shown
}

// Host looks up one IP (Shodan's stored data, no active scan), taking turns
// between keys. It returns errNotFound when Shodan has no data for the IP and
// errNoUsableKeys when every key has been skipped.
func (c *shodanClient) Host(ctx context.Context, ip string) (map[string]any, error) {
	attempt := 0
	for {
		k, err := c.pickKey()
		if err != nil {
			return nil, err
		}
		status, data, err := c.request(ctx, k, http.MethodGet, "/shodan/host/"+url.PathEscape(ip), nil)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			attempt++
			if attempt >= c.maxAttempts {
				return nil, err
			}
			if serr := c.sleep(ctx, backoff(attempt)); serr != nil {
				return nil, serr
			}
			continue
		}

		if status == http.StatusOK {
			host, derr := decodeJSON(data)
			if derr == nil && host["error"] == nil {
				return host, nil
			}
			if derr != nil {
				attempt++
				if attempt >= c.maxAttempts {
					return nil, errors.New("unable to parse the Shodan response")
				}
				continue
			}
		}

		msg := errorMessage(data)
		switch classify(status, msg) {
		case kindNotFound:
			return nil, errNotFound
		case kindKeyInvalid:
			c.disable(k, "invalid API key")
		case kindKeyDenied:
			c.disable(k, "access denied: "+firstNonEmpty(msg, "the Shodan plan may not include API access"))
		case kindNoCredits:
			c.disable(k, "out of credits: "+firstNonEmpty(msg, "Shodan refused the request"))
		case kindRetry:
			attempt++
			if attempt >= c.maxAttempts {
				return nil, &apiError{Status: status, Message: msg}
			}
			c.penalise(k, backoff(attempt))
			if serr := c.sleep(ctx, backoff(attempt)); serr != nil {
				return nil, serr
			}
		default:
			return nil, &apiError{Status: status, Message: msg}
		}
	}
}

func backoff(attempt int) time.Duration {
	return time.Duration(1<<attempt) * time.Second // 2s, 4s, 8s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Account info and active (on-demand) scans - these use one specific key
// ---------------------------------------------------------------------------

type apiInfo struct {
	Plan         string `json:"plan"`
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
}

func (c *shodanClient) keyByValue(value string) *apiKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.keys {
		if k.value == value {
			return k
		}
	}
	k := &apiKey{value: value}
	c.keys = append(c.keys, k)
	return k
}

func (c *shodanClient) call(ctx context.Context, key, method, path string, form url.Values, out any) error {
	k := c.keyByValue(key)
	for attempt := 1; ; attempt++ {
		status, data, err := c.request(ctx, k, method, path, form)
		if err == nil && status == http.StatusOK {
			if jerr := json.Unmarshal(data, out); jerr != nil {
				return errors.New("unable to parse the Shodan response")
			}
			return nil
		}
		if err == nil {
			msg := errorMessage(data)
			if classify(status, msg) != kindRetry || attempt >= c.maxAttempts {
				return &apiError{Status: status, Message: msg}
			}
		} else if ctx.Err() != nil || attempt >= c.maxAttempts {
			return err
		}
		if serr := c.sleep(ctx, backoff(attempt)); serr != nil {
			return serr
		}
	}
}

// CheckKeys asks Shodan about every key (api-info) and skips the keys it
// rejects. Needed because Shodan answers host lookups even for invalid keys,
// so a dead key would otherwise never be noticed.
func (c *shodanClient) CheckKeys(ctx context.Context) {
	c.mu.Lock()
	keys := append([]*apiKey(nil), c.keys...)
	c.mu.Unlock()
	for _, k := range keys {
		_, err := c.APIInfo(ctx, k.value)
		var ae *apiError
		if !errors.As(err, &ae) {
			continue // OK, or a network problem: keep using the key
		}
		switch classify(ae.Status, ae.Message) {
		case kindKeyInvalid:
			c.disable(k, "invalid API key")
		case kindKeyDenied:
			c.disable(k, "access denied: "+firstNonEmpty(ae.Message, "the Shodan plan may not include API access"))
		}
	}
}

// APIInfo returns the plan and remaining credits of one key.
func (c *shodanClient) APIInfo(ctx context.Context, key string) (*apiInfo, error) {
	var info apiInfo
	if err := c.call(ctx, key, http.MethodGet, "/api-info", nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

type scanSubmission struct {
	ID          string `json:"id"`
	Count       int    `json:"count"`
	CreditsLeft int    `json:"credits_left"`
}

// SubmitScan asks Shodan to actively scan the IPs (uses 1 scan credit per IP).
func (c *shodanClient) SubmitScan(ctx context.Context, key string, ips []string) (*scanSubmission, error) {
	var sub scanSubmission
	form := url.Values{"ips": {strings.Join(ips, ",")}}
	if err := c.call(ctx, key, http.MethodPost, "/shodan/scan", form, &sub); err != nil {
		return nil, err
	}
	if sub.ID == "" {
		return nil, errors.New("no scan ID in the Shodan response")
	}
	return &sub, nil
}

// ScanStatus returns SUBMITTING, QUEUE, PROCESSING or DONE.
func (c *shodanClient) ScanStatus(ctx context.Context, key, id string) (string, error) {
	var st struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, key, http.MethodGet, "/shodan/scan/"+url.PathEscape(id), nil, &st); err != nil {
		return "", err
	}
	return st.Status, nil
}
