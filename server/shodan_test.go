package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeShodan is a stand-in Shodan API for tests.
type fakeShodan struct {
	mu       sync.Mutex
	calls    []string // "key ip"
	handlers map[string]func(w http.ResponseWriter, ip string, n int)
	perIP    map[string]int
}

func newFakeShodan() *fakeShodan {
	return &fakeShodan{handlers: map[string]func(http.ResponseWriter, string, int){}, perIP: map[string]int{}}
}

func (f *fakeShodan) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	f.mu.Lock()
	switch {
	case strings.HasPrefix(r.URL.Path, "/shodan/host/"):
		ip := strings.TrimPrefix(r.URL.Path, "/shodan/host/")
		f.calls = append(f.calls, key+" "+ip)
		f.perIP[ip]++
		n := f.perIP[ip]
		h := f.handlers[key]
		if h == nil {
			h = f.handlers["*"]
		}
		f.mu.Unlock()
		h(w, ip, n)
		return
	case r.URL.Path == "/api-info":
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"plan":"dev","query_credits":100,"scan_credits":` + map[string]string{"k1": "5", "k2": "0"}[key] + `}`))
		return
	case r.URL.Path == "/shodan/scan" && r.Method == http.MethodPost:
		f.mu.Unlock()
		_ = r.ParseForm()
		n := len(strings.Split(r.PostForm.Get("ips"), ","))
		_, _ = w.Write([]byte(`{"id":"SCAN1","count":` + itoa(n) + `,"credits_left":1}`)) //nolint:gosec // fake test server
		return
	case strings.HasPrefix(r.URL.Path, "/shodan/scan/"):
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"id":"SCAN1","status":"DONE"}`))
		return
	}
	f.mu.Unlock()
	http.NotFound(w, r)
}

func itoa(n int) string { return strconv.Itoa(n) }

func testClient(url string, keys ...string) *shodanClient {
	c := newShodanClient(keys)
	c.baseURL = url
	c.minInterval = 0
	c.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	return c
}

func TestHostRotatesKeys(t *testing.T) {
	f := newFakeShodan()
	f.handlers["*"] = func(w http.ResponseWriter, ip string, n int) {
		_, _ = w.Write([]byte(`{"ip_str":"` + ip + `","ports":[80],"data":[]}`)) //nolint:gosec // fake test server
	}
	srv := httptest.NewServer(f)
	defer srv.Close()

	c := testClient(srv.URL, "k1", "k2")
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		if _, err := c.Host(context.Background(), ip); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"k1 1.1.1.1", "k2 8.8.8.8", "k1 9.9.9.9"}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("calls = %v, want %v", f.calls, want)
		}
	}
}

func TestHostSkipsBadKeysAndReportsThem(t *testing.T) {
	f := newFakeShodan()
	f.handlers["bad"] = func(w http.ResponseWriter, ip string, n int) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Invalid API key"}`))
	}
	f.handlers["good"] = func(w http.ResponseWriter, ip string, n int) {
		_, _ = w.Write([]byte(`{"ip_str":"` + ip + `","data":[]}`)) //nolint:gosec // fake test server
	}
	srv := httptest.NewServer(f)
	defer srv.Close()

	c := testClient(srv.URL, "bad", "good")
	for _, ip := range []string{"1.1.1.1", "8.8.8.8"} {
		if _, err := c.Host(context.Background(), ip); err != nil {
			t.Fatal(err)
		}
	}
	w := c.KeyWarnings()
	if len(w) != 1 || !strings.Contains(w[0], "invalid API key") || strings.Contains(w[0], "bad") {
		t.Fatalf("warnings = %v", w)
	}
	// "bad" must only have been tried once
	n := 0
	for _, call := range f.calls {
		if strings.HasPrefix(call, "bad ") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("bad key used %d times: %v", n, f.calls)
	}
}

func TestHostAllKeysBad(t *testing.T) {
	f := newFakeShodan()
	f.handlers["*"] = func(w http.ResponseWriter, ip string, n int) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<html>403</html>`))
	}
	srv := httptest.NewServer(f)
	defer srv.Close()

	c := testClient(srv.URL, "k1", "k2")
	_, err := c.Host(context.Background(), "1.1.1.1")
	if !errors.Is(err, errNoUsableKeys) {
		t.Fatalf("err = %v, want errNoUsableKeys", err)
	}
}

func TestHostNotFoundRetryAndErrors(t *testing.T) {
	f := newFakeShodan()
	f.handlers["*"] = func(w http.ResponseWriter, ip string, n int) {
		switch ip {
		case "1.1.1.1":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"No information available for that IP."}`))
		case "2.2.2.2": // rate limited once, then OK
			if n == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"Rate limit reached"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ip_str":"2.2.2.2","data":[]}`))
		case "3.3.3.3": // always 500
			w.WriteHeader(http.StatusInternalServerError)
		case "4.4.4.4":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"Invalid IP"}`))
		}
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := testClient(srv.URL, "secretkey123")

	if _, err := c.Host(context.Background(), "1.1.1.1"); !errors.Is(err, errNotFound) {
		t.Errorf("1.1.1.1 err = %v, want not found", err)
	}
	if _, err := c.Host(context.Background(), "2.2.2.2"); err != nil {
		t.Errorf("2.2.2.2 err = %v, want success after retry", err)
	}
	if _, err := c.Host(context.Background(), "3.3.3.3"); err == nil || f.perIP["3.3.3.3"] != shodanMaxAttempts {
		t.Errorf("3.3.3.3 err = %v, attempts = %d", err, f.perIP["3.3.3.3"])
	}
	_, err := c.Host(context.Background(), "4.4.4.4")
	if err == nil || !strings.Contains(err.Error(), "Invalid IP") {
		t.Errorf("4.4.4.4 err = %v", err)
	}
	if len(c.KeyWarnings()) != 0 {
		t.Errorf("unexpected key warnings %v", c.KeyWarnings())
	}
}

func TestNetworkErrorDoesNotLeakKey(t *testing.T) {
	c := testClient("http://127.0.0.1:1", "supersecretkey")
	_, err := c.Host(context.Background(), "1.1.1.1")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "supersecretkey") {
		t.Fatalf("error leaks the key: %v", err)
	}
}

func TestAPIInfoAndScan(t *testing.T) {
	srv := httptest.NewServer(newFakeShodan())
	defer srv.Close()
	c := testClient(srv.URL, "k1")

	info, err := c.APIInfo(context.Background(), "k1")
	if err != nil || info.ScanCredits != 5 || info.Plan != "dev" {
		t.Fatalf("info = %+v, err = %v", info, err)
	}
	sub, err := c.SubmitScan(context.Background(), "k1", []string{"1.1.1.1", "8.8.8.8"})
	if err != nil || sub.ID != "SCAN1" || sub.Count != 2 {
		t.Fatalf("sub = %+v, err = %v", sub, err)
	}
	st, err := c.ScanStatus(context.Background(), "k1", "SCAN1")
	if err != nil || st != "DONE" {
		t.Fatalf("status = %q, err = %v", st, err)
	}
}

func TestCheckKeysSkipsRejectedKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		switch {
		case r.URL.Path == "/api-info" && key == "bad":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("401 Unauthorized"))
		case r.URL.Path == "/api-info":
			_, _ = w.Write([]byte(`{"plan":"dev","query_credits":1,"scan_credits":1}`))
		default: // Shodan answers host lookups even for bad keys
			_, _ = w.Write([]byte(`{"ip_str":"1.1.1.1","data":[]}`))
		}
	}))
	defer srv.Close()

	c := testClient(srv.URL, "good", "bad")
	c.CheckKeys(context.Background())
	w := c.KeyWarnings()
	if len(w) != 1 || !strings.Contains(w[0], "invalid API key") {
		t.Fatalf("warnings = %v", w)
	}
	for range 3 {
		if _, err := c.Host(context.Background(), "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
	}

	c = testClient(srv.URL, "bad")
	c.CheckKeys(context.Background())
	if _, err := c.Host(context.Background(), "1.1.1.1"); !errors.Is(err, errNoUsableKeys) {
		t.Fatalf("err = %v, want errNoUsableKeys", err)
	}
}
