package main

// This file is a Go port of parse_host() from shodan_scan.py. The JSON it
// produces (results.json) has the same fields, in the same order, as the
// Python script's output.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// bannerMaxChars is how many characters of the raw service banner are kept per port.
const bannerMaxChars = 1500

// Lookup statuses.
const (
	statusFound    = "found"
	statusNotFound = "not_found"
	statusError    = "error"
)

// handledServiceKeys are keys of a Shodan service record that are handled
// explicitly or are internal noise. Every other dict-valued key (ftp, smb,
// mysql, rdp, dns, snmp, mongodb, cloud, ...) is copied into "details".
var handledServiceKeys = map[string]bool{
	"_shodan": true, "opts": true, "location": true, "vulns": true, "http": true, "ssl": true, "ssh": true,
	"hostnames": true, "domains": true, "tags": true, "cpe": true, "cpe23": true,
}

// ---------------------------------------------------------------------------
// Ordered JSON object (keeps key order like a Python dict)
// ---------------------------------------------------------------------------

type kv struct {
	k string
	v any
}

// omap is a JSON object that keeps its keys in insertion order.
type omap []kv

func (m omap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, e := range m {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := marshalNoEscape(e.k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalNoEscape(e.v)
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// cleaned builds an omap without empty values, like clean() in the Python script:
// None, "", [] and {} are dropped; false and 0 are kept.
func cleaned(pairs ...kv) omap {
	out := make(omap, 0, len(pairs))
	for _, p := range pairs {
		if !isEmpty(p.v) {
			out = append(out, p)
		}
	}
	return out
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case []string:
		return len(t) == 0
	case []int:
		return len(t) == 0
	case []vulnEntry:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	case omap:
		return len(t) == 0
	}
	return false
}

// marshalNoEscape marshals without turning <, > and & into < etc.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ---------------------------------------------------------------------------
// Typed view of a parsed host (used for change detection and messages)
// ---------------------------------------------------------------------------

type hostInfo struct {
	IP           string
	Hostnames    []string
	Domains      []string
	Country      string
	CountryCode  string
	City         string
	Organization string
	ISP          string
	ASN          string
	OS           []string
	Tags         []string
	OpenPorts    []int
	Ports        []portInfo
	CVEs         []vulnEntry // aggregated, sorted by CVSS (highest first)

	json omap // the results.json entry for this host
}

type portInfo struct {
	Port        int
	Transport   string
	Service     string
	Product     string
	Version     string
	OS          string
	HTTPStatus  string
	HTTPTitle   string
	HTTPServer  string
	CertSubject string
	CertIssuer  string
	CertExpires string
	VulnCount   int
}

func (p portInfo) key() string {
	return fmt.Sprintf("%d/%s", p.Port, p.Transport)
}

type vulnEntry struct {
	ID    string
	CVSS  float64
	Has   bool // CVSS known
	Ports []int
	json  omap
}

func (v vulnEntry) MarshalJSON() ([]byte, error) {
	m := append(omap{}, v.json...)
	if v.Ports != nil {
		m = append(m, kv{"ports", v.Ports})
	}
	return m.MarshalJSON()
}

// LookupResult is one entry of results.json.
type LookupResult struct {
	IP     string
	Status string
	Error  string
	Host   *hostInfo // set when Status == found
}

func (r LookupResult) MarshalJSON() ([]byte, error) {
	if r.Status == statusFound && r.Host != nil {
		return r.Host.json.MarshalJSON()
	}
	m := omap{{"ip", r.IP}, {"status", r.Status}}
	if r.Error != "" {
		m = append(m, kv{"error", r.Error})
	}
	return m.MarshalJSON()
}

// ---------------------------------------------------------------------------
// Helpers for loosely typed JSON
// ---------------------------------------------------------------------------

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

func num(v any) (float64, bool) {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case float64:
		return t, true
	case int:
		return float64(t), true
	case string:
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	}
	return 0, false
}

func toInt(v any) int {
	f, ok := num(v)
	if !ok || math.IsNaN(f) {
		return 0
	}
	return int(f)
}

// truthy mimics Python truthiness for JSON values.
func truthy(v any) bool {
	if isEmpty(v) {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f != 0
	}
	return true
}

func or(a, b any) any {
	if truthy(a) {
		return a
	}
	return b
}

func stringList(v any) []string {
	var out []string
	for _, e := range asSlice(v) {
		if s := str(e); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func truncateRunes(text string, limit int) string {
	n := utf8.RuneCountInString(text)
	if n <= limit {
		return text
	}
	r := []rune(text)
	return string(r[:limit]) + fmt.Sprintf("... [truncated, %d chars total]", n)
}

func truncateAny(v any, limit int) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	return truncateRunes(s, limit)
}

func sortedUnique(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dnString renders a certificate subject/issuer map like "CN=example.com, O=Org".
func dnString(v any) string {
	m := asMap(v)
	if len(m) == 0 {
		return str(v)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+str(m[k]))
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

func parseVulns(v any) []vulnEntry {
	if list := asSlice(v); list != nil {
		out := make([]vulnEntry, 0, len(list))
		for _, id := range list {
			out = append(out, vulnEntry{ID: str(id), json: omap{{"id", str(id)}}})
		}
		return out
	}
	m := asMap(v)
	if len(m) == 0 {
		return nil
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]vulnEntry, 0, len(ids))
	for _, id := range ids {
		info := asMap(m[id])
		cvss, has := num(info["cvss"])
		out = append(out, vulnEntry{
			ID:   id,
			CVSS: cvss,
			Has:  has,
			json: cleaned(
				kv{"id", id},
				kv{"cvss", info["cvss"]},
				kv{"cvss_version", info["cvss_version"]},
				kv{"epss", info["epss"]},
				kv{"kev", info["kev"]},           // in CISA Known Exploited Vulnerabilities
				kv{"verified", info["verified"]}, // Shodan confirmed it (vs. a version-based guess)
				kv{"summary", info["summary"]},
				kv{"references", info["references"]},
			),
		})
	}
	sortVulns(out)
	return out
}

// sortVulns sorts by CVSS, highest first (stable, unknown CVSS counts as 0).
func sortVulns(v []vulnEntry) {
	sort.SliceStable(v, func(i, j int) bool { return v[i].CVSS > v[j].CVSS })
}

func parseHTTP(http map[string]any) omap {
	var redirects []any
	for _, r := range asSlice(http["redirects"]) {
		if loc := asMap(r)["location"]; truthy(loc) {
			redirects = append(redirects, loc)
		}
	}
	var tech []string
	for k := range asMap(http["components"]) {
		tech = append(tech, k)
	}
	sort.Strings(tech)

	return cleaned(
		kv{"status", http["status"]},
		kv{"title", http["title"]},
		kv{"server", http["server"]},
		kv{"host", http["host"]},
		kv{"location", http["location"]},
		kv{"redirects", redirects},
		kv{"technologies", tech},
		kv{"waf", http["waf"]},
		kv{"robots_txt", truncateAny(http["robots"], bannerMaxChars)},
		kv{"favicon_hash", asMap(http["favicon"])["hash"]},
	)
}

func certSANs(cert map[string]any) any {
	for _, ext := range asSlice(cert["extensions"]) {
		e := asMap(ext)
		if str(e["name"]) == "subjectAltName" {
			return e["data"]
		}
	}
	return nil
}

func parseSSL(ssl map[string]any) omap {
	cert := asMap(ssl["cert"])
	return cleaned(
		kv{"subject", cert["subject"]},
		kv{"issuer", cert["issuer"]},
		kv{"issued", cert["issued"]},
		kv{"expires", cert["expires"]},
		kv{"expired", cert["expired"]},
		kv{"serial", cert["serial"]},
		kv{"sig_alg", cert["sig_alg"]},
		kv{"fingerprint_sha256", asMap(cert["fingerprint"])["sha256"]},
		kv{"subject_alt_names", certSANs(cert)},
		kv{"tls_versions", ssl["versions"]}, // entries starting with '-' are NOT supported
		kv{"cipher", ssl["cipher"]},
		kv{"alpn", ssl["alpn"]},
		kv{"jarm", ssl["jarm"]},
		kv{"ja3s", ssl["ja3s"]},
	)
}

func parseSSH(ssh map[string]any) omap {
	return cleaned(
		kv{"type", ssh["type"]},
		kv{"fingerprint", ssh["fingerprint"]},
		kv{"hassh", ssh["hassh"]},
		kv{"kex", ssh["kex"]},
		kv{"cipher", ssh["cipher"]},
		kv{"mac", ssh["mac"]},
	)
}

func parseService(svc map[string]any) (omap, portInfo, []vulnEntry) {
	pairs := []kv{
		{"port", svc["port"]},
		{"transport", svc["transport"]},
		{"service", asMap(svc["_shodan"])["module"]},
		{"product", svc["product"]},
		{"version", svc["version"]},
		{"info", svc["info"]},
		{"os", svc["os"]},
		{"device_type", svc["devicetype"]},
		{"cpe", or(svc["cpe23"], svc["cpe"])},
		{"tags", svc["tags"]},
		{"last_seen", svc["timestamp"]},
		{"banner", truncateAny(svc["data"], bannerMaxChars)},
	}

	info := portInfo{
		Port:      toInt(svc["port"]),
		Transport: str(svc["transport"]),
		Service:   str(asMap(svc["_shodan"])["module"]),
		Product:   str(svc["product"]),
		Version:   str(svc["version"]),
		OS:        str(svc["os"]),
	}

	if http := asMap(svc["http"]); truthy(http) {
		pairs = append(pairs, kv{"http", parseHTTP(http)})
		info.HTTPStatus = str(http["status"])
		info.HTTPTitle = strings.TrimSpace(str(http["title"]))
		info.HTTPServer = str(http["server"])
	}
	if ssl := asMap(svc["ssl"]); truthy(ssl) {
		pairs = append(pairs, kv{"ssl", parseSSL(ssl)})
		cert := asMap(ssl["cert"])
		info.CertSubject = dnString(cert["subject"])
		info.CertIssuer = dnString(cert["issuer"])
		info.CertExpires = str(cert["expires"])
	}
	if ssh := asMap(svc["ssh"]); truthy(ssh) {
		pairs = append(pairs, kv{"ssh", parseSSH(ssh)})
	}

	// Any other protocol-specific info Shodan collected (ftp, smb, rdp, mysql, dns, snmp, ...)
	var detailKeys []string
	for k, v := range svc {
		if _, isMap := v.(map[string]any); isMap && !handledServiceKeys[k] {
			detailKeys = append(detailKeys, k)
		}
	}
	sort.Strings(detailKeys)
	details := omap{}
	for _, k := range detailKeys {
		details = append(details, kv{k, svc[k]})
	}
	pairs = append(pairs, kv{"details", details})

	vulns := parseVulns(svc["vulns"])
	info.VulnCount = len(vulns)
	pairs = append(pairs, kv{"vulns", vulns})

	return cleaned(pairs...), info, vulns
}

// parseHost turns a raw Shodan /shodan/host response into a hostInfo.
func parseHost(ip string, host map[string]any) *hostInfo {
	services := make([]map[string]any, 0)
	for _, s := range asSlice(host["data"]) {
		if m := asMap(s); m != nil {
			services = append(services, m)
		}
	}
	sort.SliceStable(services, func(i, j int) bool {
		pi, pj := toInt(services[i]["port"]), toInt(services[j]["port"])
		if pi != pj {
			return pi < pj
		}
		return str(services[i]["transport"]) < str(services[j]["transport"])
	})

	h := &hostInfo{IP: ip}
	portsJSON := make([]any, 0, len(services))

	hostnames := map[string]bool{}
	domains := map[string]bool{}
	oses := map[string]bool{}
	for _, s := range stringList(host["hostnames"]) {
		hostnames[s] = true
	}
	for _, s := range stringList(host["domains"]) {
		domains[s] = true
	}
	if truthy(host["os"]) {
		oses[str(host["os"])] = true
	}

	// Aggregate CVEs across all ports, remembering where each was seen.
	cveIndex := map[string]int{}
	var cves []vulnEntry

	for _, svc := range services {
		j, info, vulns := parseService(svc)
		portsJSON = append(portsJSON, j)
		h.Ports = append(h.Ports, info)

		for _, s := range stringList(svc["hostnames"]) {
			hostnames[s] = true
		}
		for _, s := range stringList(svc["domains"]) {
			domains[s] = true
		}
		if truthy(svc["os"]) {
			oses[str(svc["os"])] = true
		}

		port := toInt(svc["port"])
		for _, v := range vulns {
			idx, ok := cveIndex[v.ID]
			if !ok {
				entry := v
				entry.Ports = []int{}
				cves = append(cves, entry)
				idx = len(cves) - 1
				cveIndex[v.ID] = idx
			}
			if !slices.Contains(cves[idx].Ports, port) {
				cves[idx].Ports = append(cves[idx].Ports, port)
			}
		}
	}
	for _, id := range stringList(host["vulns"]) { // host-level list (IDs only)
		if _, ok := cveIndex[id]; !ok {
			cves = append(cves, vulnEntry{ID: id, Ports: []int{}, json: omap{{"id", id}}})
			cveIndex[id] = len(cves) - 1
		}
	}
	sortVulns(cves)
	if cves == nil {
		cves = []vulnEntry{}
	}

	openSet := map[int]bool{}
	for _, p := range asSlice(host["ports"]) {
		openSet[toInt(p)] = true
	}
	h.OpenPorts = make([]int, 0, len(openSet))
	for p := range openSet {
		h.OpenPorts = append(h.OpenPorts, p)
	}
	sort.Ints(h.OpenPorts)

	h.Hostnames = sortedUnique(hostnames)
	h.Domains = sortedUnique(domains)
	h.OS = sortedUnique(oses)
	h.Tags = stringList(host["tags"])
	h.Country = str(host["country_name"])
	h.CountryCode = str(host["country_code"])
	h.City = str(host["city"])
	h.Organization = str(host["org"])
	h.ISP = str(host["isp"])
	h.ASN = str(host["asn"])
	h.CVEs = cves

	tags := host["tags"]
	if !truthy(tags) {
		tags = []any{}
	}

	h.json = omap{
		{"ip", ip},
		{"status", statusFound},
		{"hostnames", h.Hostnames},
		{"domains", h.Domains},
		{"country", host["country_name"]},
		{"country_code", host["country_code"]},
		{"city", host["city"]},
		{"region", host["region_code"]},
		{"latitude", host["latitude"]},
		{"longitude", host["longitude"]},
		{"organization", host["org"]},
		{"isp", host["isp"]},
		{"asn", host["asn"]},
		{"operating_systems", h.OS},
		{"tags", tags},
		{"last_update", host["last_update"]},
		{"open_ports", h.OpenPorts},
		{"ports", portsJSON},
		{"cve_count", len(cves)},
		{"cves", cves},
	}
	return h
}

// decodeJSON decodes with json.Number so big integers (certificate serials) survive.
func decodeJSON(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
