package main

import (
	"testing"
)

func TestCheckPublicIP(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		reason string
	}{
		{"8.8.8.8", "8.8.8.8", ""},
		{"  1.1.1.1  ", "1.1.1.1", ""},
		{"9.9.9.9", "9.9.9.9", ""},
		{"2001:4860:4860::8888", "2001:4860:4860::8888", ""},
		{"2606:4700:4700:0000:0000:0000:0000:1111", "2606:4700:4700::1111", ""},
		{"::ffff:8.8.4.4", "8.8.4.4", ""},
		{"64:ff9b::808:808", "64:ff9b::808:808", ""},

		{"not-an-ip", "", reasonInvalid},
		{"1.2.3", "", reasonInvalid},
		{"1.2.3.4/24", "", reasonInvalid},
		{"256.1.1.1", "", reasonInvalid},
		{"1.2.3.4:80", "", reasonInvalid},
		{"10.1.2.3", "", reasonPrivate},
		{"172.16.0.1", "", reasonPrivate},
		{"172.31.255.255", "", reasonPrivate},
		{"192.168.1.1", "", reasonPrivate},
		{"127.0.0.1", "", reasonLoopback},
		{"169.254.10.10", "", reasonLinkLocal},
		{"100.64.0.1", "", reasonCGNAT},
		{"100.127.255.254", "", reasonCGNAT},
		{"0.0.0.0", "", reasonThisNetwork},
		{"0.1.2.3", "", reasonThisNetwork},
		{"192.0.0.8", "", reasonIETF},
		{"192.0.2.10", "", reasonDocumentation},
		{"198.51.100.7", "", reasonDocumentation},
		{"203.0.113.10", "", reasonDocumentation},
		{"198.18.0.1", "", reasonBenchmarking},
		{"198.19.255.1", "", reasonBenchmarking},
		{"192.88.99.1", "", reasonReserved},
		{"224.0.0.1", "", reasonMulticast},
		{"239.255.255.250", "", reasonMulticast},
		{"240.0.0.1", "", reasonReserved},
		{"255.255.255.255", "", reasonBroadcast},
		{"::", "", reasonUnspecified},
		{"::1", "", reasonLoopback},
		{"::ffff:10.0.0.1", "", reasonPrivate},
		{"64:ff9b::a00:1", "", reasonPrivate},
		{"fe80::1", "", reasonLinkLocal},
		{"fe80::1%eth0", "", reasonZone},
		{"fd12:3456::1", "", reasonPrivate},
		{"fc00::1", "", reasonPrivate},
		{"ff02::1", "", reasonMulticast},
		{"2001:db8::1", "", reasonDocumentation},
		{"3fff::1", "", reasonDocumentation},
		{"2001:0:1::1", "", reasonIETF},
		{"2002:c000:204::1", "", reasonReserved},
		{"100::1", "", reasonReserved},
		{"4000::1", "", reasonReserved},
		{"fec0::1", "", reasonReserved},
	}
	for _, c := range cases {
		got, reason := CheckPublicIP(c.in)
		if got != c.want || reason != c.reason {
			t.Errorf("CheckPublicIP(%q) = (%q, %q), want (%q, %q)", c.in, got, reason, c.want, c.reason)
		}
	}
}

func TestParseIPList(t *testing.T) {
	text := "\ufeff# my list\r\n8.8.8.8\r\n\r\n1.1.1.1   # cloudflare\n10.0.0.1\nhello\n8.8.8.8\n::ffff:8.8.8.8\n  \n#2.2.2.2\n2001:4860:4860::8888\n"
	got := ParseIPList(text)

	wantIPs := []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"}
	if len(got.IPs) != len(wantIPs) {
		t.Fatalf("IPs = %v, want %v", got.IPs, wantIPs)
	}
	for i := range wantIPs {
		if got.IPs[i] != wantIPs[i] {
			t.Fatalf("IPs = %v, want %v", got.IPs, wantIPs)
		}
	}
	if got.Duplicates != 2 {
		t.Errorf("Duplicates = %d, want 2", got.Duplicates)
	}
	if len(got.Rejected) != 2 {
		t.Fatalf("Rejected = %+v, want 2 entries", got.Rejected)
	}
	if got.Rejected[0] != (Rejected{Line: 5, Value: "10.0.0.1", Reason: reasonPrivate}) {
		t.Errorf("Rejected[0] = %+v", got.Rejected[0])
	}
	if got.Rejected[1] != (Rejected{Line: 6, Value: "hello", Reason: reasonInvalid}) {
		t.Errorf("Rejected[1] = %+v", got.Rejected[1])
	}
}

func TestAPIKeys(t *testing.T) {
	c := &configuration{ShodanAPIKeys: " keyA \n\n# comment\nkeyB, keyC\nkeyA\n"} //nolint:gosec // fake test keys
	got := c.apiKeys()
	want := []string{"keyA", "keyB", "keyC"}
	if len(got) != len(want) {
		t.Fatalf("apiKeys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("apiKeys = %v, want %v", got, want)
		}
	}
	if maskKey("abcdefgh1234") != "...1234" {
		t.Errorf("maskKey = %q", maskKey("abcdefgh1234"))
	}
}
