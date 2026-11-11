package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"
)

// TestParseHostMatchesPython checks the Go port against shodan_scan.py: the
// testdata/expected_*.json files were produced by the Python parse_host() from
// the raw testdata/host_*.json Shodan responses.
func TestParseHostMatchesPython(t *testing.T) {
	for _, ip := range []string{"203.0.113.10", "198.51.100.20", "203.0.113.30"} {
		t.Run(ip, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/host_" + ip + ".json") //nolint:gosec // test fixture
			if err != nil {
				t.Fatal(err)
			}
			host, err := decodeJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(LookupResult{IP: ip, Status: statusFound, Host: parseHost(ip, host)})
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile("testdata/expected_" + ip + ".json") //nolint:gosec // test fixture
			if err != nil {
				t.Fatal(err)
			}

			var g, w any
			if err := json.Unmarshal(got, &g); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(want, &w); err != nil {
				t.Fatal(err)
			}
			normaliseVulnOrder(g)
			normaliseVulnOrder(w)
			if !reflect.DeepEqual(g, w) {
				diffAny(t, "", g, w)
			}
		})
	}
}

// Python keeps Shodan's key order for CVEs with equal CVSS; Go maps have no
// order, so CVEs with the same score may come out in a different order. Sort
// ties by ID on both sides before comparing.
func normaliseVulnOrder(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if (k == "vulns" || k == "cves") && child != nil {
				if list, ok := child.([]any); ok {
					sort.SliceStable(list, func(i, j int) bool {
						a, b := list[i].(map[string]any), list[j].(map[string]any)
						ca, _ := a["cvss"].(float64)
						cb, _ := b["cvss"].(float64)
						if ca != cb {
							return ca > cb
						}
						return fmt.Sprint(a["id"]) < fmt.Sprint(b["id"])
					})
				}
			}
			normaliseVulnOrder(child)
		}
	case []any:
		for _, child := range t {
			normaliseVulnOrder(child)
		}
	}
}

func diffAny(t *testing.T, path string, got, want any) {
	t.Helper()
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			t.Errorf("%s: got %T, want object", path, got)
			return
		}
		for k := range w {
			if _, ok := g[k]; !ok {
				t.Errorf("%s.%s: missing", path, k)
				continue
			}
			diffAny(t, path+"."+k, g[k], w[k])
		}
		for k := range g {
			if _, ok := w[k]; !ok {
				t.Errorf("%s.%s: unexpected key (value %v)", path, k, g[k])
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			t.Errorf("%s: got %v, want %v", path, got, want)
			return
		}
		for i := range w {
			diffAny(t, fmt.Sprintf("%s[%d]", path, i), g[i], w[i])
		}
	default:
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %#v, want %#v", path, got, want)
		}
	}
}

func TestLookupResultNonFound(t *testing.T) {
	b, _ := json.Marshal(LookupResult{IP: "1.2.3.4", Status: statusNotFound})
	if string(b) != `{"ip":"1.2.3.4","status":"not_found"}` {
		t.Errorf("not_found = %s", b)
	}
	b, _ = marshalNoEscape(LookupResult{IP: "1.2.3.4", Status: statusError, Error: "boom <x>"})
	if string(b) != `{"ip":"1.2.3.4","status":"error","error":"boom <x>"}` {
		t.Errorf("error = %s", b)
	}
}
