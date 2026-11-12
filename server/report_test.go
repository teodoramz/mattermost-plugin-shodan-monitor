package main

import (
	"strings"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
)

func TestHostLabelShowsISP(t *testing.T) {
	cases := []struct {
		org, isp, asn string
		want          string
	}{
		{"Linode", "Akamai Connected Cloud", "AS63949", "Linode · Akamai Connected Cloud · AS63949"},
		{"Google LLC", "Google LLC", "AS15169", "Google LLC · AS15169"}, // same ISP shown once
		{"", "Example ISP", "AS64500", "Example ISP · AS64500"},
		{"Example Org", "", "", "Example Org"},
	}
	for _, c := range cases {
		r := LookupResult{IP: "203.0.113.10", Status: statusFound, Host: &hostInfo{Organization: c.org, ISP: c.isp, ASN: c.asn}}
		if got := hostLabel(r, nil); got != c.want {
			t.Errorf("hostLabel(%q, %q, %q) = %q, want %q", c.org, c.isp, c.asn, got, c.want)
		}
	}

	// Not in Shodan any more: the label comes from the saved result.
	old := &Snapshot{Org: "Old Org", ISP: "Old ISP", ASN: "AS1"}
	if got := hostLabel(LookupResult{IP: "203.0.113.10", Status: statusNotFound}, old); got != "Old Org · Old ISP · AS1" {
		t.Errorf("hostLabel from saved result = %q", got)
	}
}

func TestDescribeResultShowsISP(t *testing.T) {
	r := LookupResult{IP: "203.0.113.10", Status: statusFound, Host: &hostInfo{
		Organization: "Linode", ISP: "Akamai Connected Cloud", OpenPorts: []int{22, 80},
	}}
	got := describeResult(r)
	if !strings.HasPrefix(got, "Linode · Akamai Connected Cloud · 2 open ports (22, 80)") {
		t.Errorf("describeResult = %q", got)
	}
}

// Mattermost converts Slack-style "<x|y>" links in command responses unless
// SkipSlackParsing is set; the help table would be broken by that conversion.
func TestRespondSkipsSlackParsing(t *testing.T) {
	r := respond("| `/shodan add <ip>` | Add |\n| `/shodan remove <ip>` | Remove |")
	if !r.SkipSlackParsing {
		t.Fatal("respond must set SkipSlackParsing")
	}
	if got := model.ParseSlackLinksToMarkdown(r.Text); got == r.Text {
		t.Fatal("expected Slack parsing to alter this text; the test no longer guards anything")
	}
}
