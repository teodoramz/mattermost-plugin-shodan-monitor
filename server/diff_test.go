package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func baseSnap() *Snapshot {
	return &Snapshot{
		Status:    statusFound,
		Hostnames: []string{"a.example.com"},
		Domains:   []string{"example.com"},
		Org:       "Org", ISP: "ISP", ASN: "AS1", Country: "Romania", City: "Bucharest",
		OS:   []string{"Linux"},
		Tags: []string{"cdn"},
		Ports: map[string]PortSnap{
			"22/tcp":  {Service: "ssh", Product: "OpenSSH", Version: "8.2p1"},
			"443/tcp": {Service: "https", Product: "nginx", Version: "1.18.0", HTTPStatus: "200", HTTPTitle: "Home", CertSubject: "CN=a", CertIssuer: "CN=LE", CertExpires: "20270101"},
		},
		CVEs: map[string]string{"CVE-2021-1": "7.5", "CVE-2021-2": ""},
	}
}

func clone(s *Snapshot) *Snapshot {
	b, _ := json.Marshal(s)
	var c Snapshot
	_ = json.Unmarshal(b, &c)
	return &c
}

func TestCompareNoChange(t *testing.T) {
	a := baseSnap()
	b := clone(a)
	b.SavedAt = 12345 // timestamps never count
	if got := Compare(a, b); len(got) != 0 {
		t.Fatalf("expected no changes, got %v", got)
	}
}

func TestCompareEachKind(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *Snapshot)
		want   string
	}{
		{"port opened", func(s *Snapshot) { s.Ports["8080/tcp"] = PortSnap{Product: "nginx", Version: "1.25.3"} }, "Port 8080/tcp opened - nginx 1.25.3"},
		{"port closed", func(s *Snapshot) { delete(s.Ports, "22/tcp") }, "Port 22/tcp closed - OpenSSH 8.2p1"},
		{"version", func(s *Snapshot) { p := s.Ports["443/tcp"]; p.Version = "1.24.0"; s.Ports["443/tcp"] = p }, `Port 443/tcp changed: version "1.18.0" → "1.24.0"`},
		{"product", func(s *Snapshot) { p := s.Ports["22/tcp"]; p.Product = "Dropbear"; s.Ports["22/tcp"] = p }, `Port 22/tcp changed: product "OpenSSH" → "Dropbear"`},
		{"title", func(s *Snapshot) { p := s.Ports["443/tcp"]; p.HTTPTitle = "Login"; s.Ports["443/tcp"] = p }, `page title "Home" → "Login"`},
		{"http status", func(s *Snapshot) { p := s.Ports["443/tcp"]; p.HTTPStatus = "503"; s.Ports["443/tcp"] = p }, `HTTP status "200" → "503"`},
		{"cert", func(s *Snapshot) { p := s.Ports["443/tcp"]; p.CertExpires = "20280101"; s.Ports["443/tcp"] = p }, "TLS certificate changed (expires 20270101 → 20280101)"},
		{"cve added", func(s *Snapshot) { s.CVEs["CVE-2024-9"] = "9.8" }, "New CVE: CVE-2024-9 (CVSS 9.8)"},
		{"cve gone", func(s *Snapshot) { delete(s.CVEs, "CVE-2021-1") }, "CVE no longer reported: CVE-2021-1"},
		{"hostname", func(s *Snapshot) { s.Hostnames = append(s.Hostnames, "b.example.com") }, "New hostname: b.example.com"},
		{"domain gone", func(s *Snapshot) { s.Domains = nil }, "Removed domain: example.com"},
		{"org", func(s *Snapshot) { s.Org = "New Org" }, "Organization changed: Org → New Org"},
		{"asn", func(s *Snapshot) { s.ASN = "AS2" }, "ASN changed: AS1 → AS2"},
		{"city", func(s *Snapshot) { s.City = "Cluj" }, "City changed: Bucharest → Cluj"},
		{"os", func(s *Snapshot) { s.OS = []string{"Windows"} }, "OS changed: Linux → Windows"},
		{"tag", func(s *Snapshot) { s.Tags = []string{"cdn", "vpn"} }, "New tag: vpn"},
		{"gone from shodan", func(s *Snapshot) { *s = Snapshot{Status: statusNotFound} }, "No longer in Shodan's data"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := baseSnap()
			b := clone(a)
			c.mutate(b)
			got := Compare(a, b)
			if len(got) != 1 || !strings.Contains(got[0], c.want) {
				t.Fatalf("Compare = %q, want one line containing %q", got, c.want)
			}
		})
	}
}

func TestCompareBackInShodan(t *testing.T) {
	got := Compare(&Snapshot{Status: statusNotFound}, baseSnap())
	if len(got) == 0 || !strings.Contains(got[0], "Now in Shodan's data (2 open ports)") {
		t.Fatalf("Compare = %v", got)
	}
}

func TestCompareCollapsesManyCVEs(t *testing.T) {
	a := baseSnap()
	b := clone(a)
	for i := range 25 {
		b.CVEs["CVE-2025-"+string(rune('a'+i))] = "5.0"
	}
	got := Compare(a, b)
	if len(got) != maxCVELines+1 || !strings.Contains(got[maxCVELines], "and 15 more new CVEs") {
		t.Fatalf("Compare = %v", got)
	}
}

// A real Shodan host compared with itself after a full parse/snapshot round
// trip must report nothing.
func TestSnapshotRoundTripStable(t *testing.T) {
	raw, err := os.ReadFile("testdata/host_203.0.113.30.json")
	if err != nil {
		t.Fatal(err)
	}
	host, _ := decodeJSON(raw)
	r := LookupResult{IP: "203.0.113.30", Status: statusFound, Host: parseHost("203.0.113.30", host)}
	s1 := snapshotFor(r, 1)
	s2 := clone(snapshotFor(r, 2))
	if got := Compare(s1, s2); len(got) != 0 {
		t.Fatalf("expected no changes, got %v", got)
	}
	if len(s1.CVEs) != 45 || len(s1.Ports) != 4 {
		t.Fatalf("snapshot has %d CVEs, %d ports", len(s1.CVEs), len(s1.Ports))
	}
}
