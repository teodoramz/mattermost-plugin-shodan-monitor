package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Snapshot is the saved baseline for one IP: only the fields that count as a
// change. Timestamps, banners, coordinates etc. are deliberately left out.
type Snapshot struct {
	Status    string              `json:"status"`
	SavedAt   int64               `json:"saved_at"` // unix millis
	Hostnames []string            `json:"hostnames,omitempty"`
	Domains   []string            `json:"domains,omitempty"`
	Org       string              `json:"org,omitempty"`
	ISP       string              `json:"isp,omitempty"`
	ASN       string              `json:"asn,omitempty"`
	Country   string              `json:"country,omitempty"`
	City      string              `json:"city,omitempty"`
	OS        []string            `json:"os,omitempty"`
	Tags      []string            `json:"tags,omitempty"`
	Ports     map[string]PortSnap `json:"ports,omitempty"` // "443/tcp"
	CVEs      map[string]string   `json:"cves,omitempty"`  // CVE ID -> CVSS ("" when unknown)
}

// PortSnap is the part of a port that counts as a change.
type PortSnap struct {
	Service     string `json:"service,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	OS          string `json:"os,omitempty"`
	HTTPStatus  string `json:"http_status,omitempty"`
	HTTPTitle   string `json:"http_title,omitempty"`
	HTTPServer  string `json:"http_server,omitempty"`
	CertSubject string `json:"cert_subject,omitempty"`
	CertIssuer  string `json:"cert_issuer,omitempty"`
	CertExpires string `json:"cert_expires,omitempty"`
}

func snapshotFor(r LookupResult, savedAt int64) *Snapshot {
	s := &Snapshot{Status: r.Status, SavedAt: savedAt}
	if r.Status != statusFound || r.Host == nil {
		return s
	}
	h := r.Host
	s.Hostnames = h.Hostnames
	s.Domains = h.Domains
	s.Org = h.Organization
	s.ISP = h.ISP
	s.ASN = h.ASN
	s.Country = h.Country
	s.City = h.City
	s.OS = h.OS
	s.Tags = append([]string(nil), h.Tags...)
	sort.Strings(s.Tags)
	s.Ports = map[string]PortSnap{}
	for _, p := range h.Ports {
		if _, dup := s.Ports[p.key()]; dup {
			continue
		}
		s.Ports[p.key()] = PortSnap{
			Service: p.Service, Product: p.Product, Version: p.Version, OS: p.OS,
			HTTPStatus: p.HTTPStatus, HTTPTitle: p.HTTPTitle, HTTPServer: p.HTTPServer,
			CertSubject: p.CertSubject, CertIssuer: p.CertIssuer, CertExpires: p.CertExpires,
		}
	}
	// Ports Shodan lists as open but without a service record.
	for _, port := range h.OpenPorts {
		if !hasPortNumber(s.Ports, port) {
			s.Ports[fmt.Sprintf("%d/tcp", port)] = PortSnap{}
		}
	}
	s.CVEs = map[string]string{}
	for _, v := range h.CVEs {
		cvss := ""
		if v.Has {
			cvss = strconv.FormatFloat(v.CVSS, 'f', -1, 64)
		}
		s.CVEs[v.ID] = cvss
	}
	return s
}

func hasPortNumber(ports map[string]PortSnap, port int) bool {
	prefix := strconv.Itoa(port) + "/"
	for k := range ports {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// maxCVELines is how many added/removed CVEs are listed per IP before
// collapsing the rest into "... and N more".
const maxCVELines = 10

// Compare returns one human-readable line per change between old and cur
// (both non-nil). An empty result means nothing that matters changed.
func Compare(old, cur *Snapshot) []string {
	var out []string

	switch {
	case old.Status == statusFound && cur.Status == statusNotFound:
		return []string{"No longer in Shodan's data"}
	case old.Status != statusFound && cur.Status == statusFound:
		out = append(out, fmt.Sprintf("Now in Shodan's data (%d open ports)", len(cur.Ports)))
		old = &Snapshot{Status: statusFound}
	case cur.Status != statusFound:
		return nil
	}

	field := func(label, a, b string) {
		if a != b {
			out = append(out, fmt.Sprintf("%s changed: %s → %s", label, orDash(a), orDash(b)))
		}
	}
	field("Organization", old.Org, cur.Org)
	field("ISP", old.ISP, cur.ISP)
	field("ASN", old.ASN, cur.ASN)
	field("Country", old.Country, cur.Country)
	field("City", old.City, cur.City)
	field("OS", strings.Join(old.OS, ", "), strings.Join(cur.OS, ", "))

	setDiff := func(label string, a, b []string) {
		added, removed := diffSets(a, b)
		for _, x := range added {
			out = append(out, fmt.Sprintf("New %s: %s", label, x))
		}
		for _, x := range removed {
			out = append(out, fmt.Sprintf("Removed %s: %s", label, x))
		}
	}
	setDiff("hostname", old.Hostnames, cur.Hostnames)
	setDiff("domain", old.Domains, cur.Domains)
	setDiff("tag", old.Tags, cur.Tags)

	// Ports
	for _, k := range sortedPortKeys(old.Ports, cur.Ports) {
		o, inOld := old.Ports[k]
		n, inNew := cur.Ports[k]
		switch {
		case inNew && !inOld:
			out = append(out, fmt.Sprintf("Port %s opened%s", k, describePort(n)))
		case inOld && !inNew:
			out = append(out, fmt.Sprintf("Port %s closed%s", k, describePort(o)))
		default:
			if changes := comparePort(o, n); len(changes) > 0 {
				out = append(out, fmt.Sprintf("Port %s changed: %s", k, strings.Join(changes, "; ")))
			}
		}
	}

	// CVEs
	addedIDs, removedIDs := diffSets(mapKeys(old.CVEs), mapKeys(cur.CVEs))
	sortByCVSS(addedIDs, cur.CVEs)
	sortByCVSS(removedIDs, old.CVEs)
	for i, id := range addedIDs {
		if i == maxCVELines {
			out = append(out, fmt.Sprintf("... and %d more new CVEs (see results.json)", len(addedIDs)-maxCVELines))
			break
		}
		out = append(out, "New CVE: "+cveLabel(id, cur.CVEs[id]))
	}
	for i, id := range removedIDs {
		if i == maxCVELines {
			out = append(out, fmt.Sprintf("... and %d more CVEs no longer reported", len(removedIDs)-maxCVELines))
			break
		}
		out = append(out, "CVE no longer reported: "+id)
	}
	return out
}

func comparePort(o, n PortSnap) []string {
	var c []string
	f := func(label, a, b string) {
		if a != b {
			c = append(c, fmt.Sprintf("%s %s → %s", label, quoteOrDash(a), quoteOrDash(b)))
		}
	}
	f("service", o.Service, n.Service)
	f("product", o.Product, n.Product)
	f("version", o.Version, n.Version)
	f("OS", o.OS, n.OS)
	f("HTTP status", o.HTTPStatus, n.HTTPStatus)
	f("HTTP server", o.HTTPServer, n.HTTPServer)
	f("page title", o.HTTPTitle, n.HTTPTitle)
	if o.CertSubject != n.CertSubject || o.CertIssuer != n.CertIssuer || o.CertExpires != n.CertExpires {
		s := "TLS certificate changed"
		if o.CertExpires != n.CertExpires {
			s += fmt.Sprintf(" (expires %s → %s)", orDash(o.CertExpires), orDash(n.CertExpires))
		}
		if o.CertSubject != n.CertSubject {
			s += fmt.Sprintf(" (subject %s → %s)", orDash(o.CertSubject), orDash(n.CertSubject))
		}
		if o.CertIssuer != n.CertIssuer {
			s += fmt.Sprintf(" (issuer %s → %s)", orDash(o.CertIssuer), orDash(n.CertIssuer))
		}
		c = append(c, s)
	}
	return c
}

func describePort(p PortSnap) string {
	parts := []string{}
	if s := strings.TrimSpace(p.Product + " " + p.Version); s != "" {
		parts = append(parts, s)
	} else if p.Service != "" {
		parts = append(parts, p.Service)
	}
	if p.HTTPTitle != "" {
		parts = append(parts, fmt.Sprintf("title %q", p.HTTPTitle))
	}
	if len(parts) == 0 {
		return ""
	}
	return " - " + strings.Join(parts, ", ")
}

func cveLabel(id, cvss string) string {
	if cvss == "" {
		return id
	}
	return fmt.Sprintf("%s (CVSS %s)", id, cvss)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func quoteOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return strconv.Quote(s)
}

func diffSets(a, b []string) (added, removed []string) {
	inA := map[string]bool{}
	inB := map[string]bool{}
	for _, x := range a {
		inA[x] = true
	}
	for _, x := range b {
		inB[x] = true
	}
	for x := range inB {
		if !inA[x] {
			added = append(added, x)
		}
	}
	for x := range inA {
		if !inB[x] {
			removed = append(removed, x)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortByCVSS(ids []string, cvss map[string]string) {
	sort.SliceStable(ids, func(i, j int) bool {
		a, _ := strconv.ParseFloat(cvss[ids[i]], 64)
		b, _ := strconv.ParseFloat(cvss[ids[j]], 64)
		if a != b {
			return a > b
		}
		return ids[i] < ids[j]
	})
}

// sortedPortKeys returns the union of port keys, ordered by port number then transport.
func sortedPortKeys(a, b map[string]PortSnap) []string {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		pi, ti := splitPortKey(keys[i])
		pj, tj := splitPortKey(keys[j])
		if pi != pj {
			return pi < pj
		}
		return ti < tj
	})
	return keys
}

func splitPortKey(k string) (int, string) {
	port, transport, _ := strings.Cut(k, "/")
	n, _ := strconv.Atoi(port)
	return n, transport
}
