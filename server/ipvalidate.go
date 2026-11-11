package main

import (
	"net/netip"
	"strings"
)

// Rejected is one input line that was not accepted into the IP list.
type Rejected struct {
	Line   int    `json:"line"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// ParsedList is the result of cleaning an uploaded IP list.
type ParsedList struct {
	IPs        []string   // valid public IPs, normalised, in file order, no duplicates
	Rejected   []Rejected // invalid / non-public lines
	Duplicates int        // valid lines skipped because the IP was already seen
}

// Reason strings for rejected input.
const (
	reasonInvalid       = "not an IP address"
	reasonPrivate       = "private address"
	reasonLoopback      = "loopback address"
	reasonLinkLocal     = "link-local address"
	reasonMulticast     = "multicast address"
	reasonUnspecified   = "unspecified address"
	reasonBroadcast     = "broadcast address"
	reasonThisNetwork   = "\"this network\" address (0.0.0.0/8)"
	reasonCGNAT         = "carrier-grade NAT / shared address (100.64.0.0/10)"
	reasonDocumentation = "documentation address"
	reasonBenchmarking  = "benchmarking address (198.18.0.0/15)"
	reasonIETF          = "IETF protocol assignment, not globally reachable"
	reasonReserved      = "reserved address, not globally reachable"
	reasonZone          = "IPv6 address with a zone, not globally reachable"
)

type specialRange struct {
	prefix netip.Prefix
	reason string
}

// Special-purpose ranges that are not globally reachable (IANA IPv4/IPv6
// special-purpose address registries). Order matters: the first match wins,
// so more specific ranges come first.
var specialRanges = func() []specialRange {
	r := func(cidr, reason string) specialRange {
		return specialRange{netip.MustParsePrefix(cidr), reason}
	}
	return []specialRange{
		// IPv4
		r("255.255.255.255/32", reasonBroadcast),
		r("0.0.0.0/8", reasonThisNetwork),
		r("10.0.0.0/8", reasonPrivate),
		r("100.64.0.0/10", reasonCGNAT),
		r("127.0.0.0/8", reasonLoopback),
		r("169.254.0.0/16", reasonLinkLocal),
		r("172.16.0.0/12", reasonPrivate),
		r("192.0.0.0/24", reasonIETF),
		r("192.0.2.0/24", reasonDocumentation),
		r("192.88.99.0/24", reasonReserved), // deprecated 6to4 relay anycast
		r("192.168.0.0/16", reasonPrivate),
		r("198.18.0.0/15", reasonBenchmarking),
		r("198.51.100.0/24", reasonDocumentation),
		r("203.0.113.0/24", reasonDocumentation),
		r("224.0.0.0/4", reasonMulticast),
		r("240.0.0.0/4", reasonReserved),
		// IPv6
		r("::/128", reasonUnspecified),
		r("::1/128", reasonLoopback),
		r("64:ff9b:1::/48", reasonReserved), // local-use IPv4/IPv6 translation
		r("100::/64", reasonReserved),       // discard-only
		r("2001::/23", reasonIETF),
		r("2001:db8::/32", reasonDocumentation),
		r("2002::/16", reasonReserved), // 6to4
		r("3fff::/20", reasonDocumentation),
		r("5f00::/16", reasonReserved), // SRv6 SIDs
		r("fc00::/7", reasonPrivate),   // unique local
		r("fe80::/10", reasonLinkLocal),
		r("fec0::/10", reasonReserved), // deprecated site-local
		r("ff00::/8", reasonMulticast),
	}
}()

// globalUnicastV6 is the only IPv6 block currently allocated for global unicast.
var globalUnicastV6 = netip.MustParsePrefix("2000::/3")

// nat64WellKnown embeds IPv4 addresses (64:ff9b::/96); it is globally
// reachable, but only when the embedded IPv4 address is.
var nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")

// CheckPublicIP parses s and returns its normalised form and "" when it is a
// public (globally reachable) IP address, or the reason it was rejected.
func CheckPublicIP(s string) (string, string) {
	s = strings.TrimSpace(s)
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", reasonInvalid
	}
	if addr.Zone() != "" {
		return "", reasonZone
	}
	addr = addr.Unmap() // ::ffff:1.2.3.4 -> 1.2.3.4

	for _, sr := range specialRanges {
		if sr.prefix.Contains(addr) {
			return "", sr.reason
		}
	}
	if addr.Is6() {
		if nat64WellKnown.Contains(addr) {
			b := addr.As16()
			v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
			if _, reason := CheckPublicIP(v4.String()); reason != "" {
				return "", reason
			}
			return addr.String(), ""
		}
		if !globalUnicastV6.Contains(addr) {
			return "", reasonReserved
		}
	}
	return addr.String(), ""
}

// ParseIPList cleans an uploaded list: one IP per line; blank lines and lines
// starting with # are skipped; a trailing "# comment" is allowed; duplicates
// are dropped; invalid and non-public addresses are rejected with a reason.
func ParseIPList(text string) ParsedList {
	var out ParsedList
	seen := map[string]bool{}
	text = strings.TrimPrefix(text, "\ufeff") // UTF-8 BOM

	for i, raw := range strings.Split(text, "\n") {
		line := raw
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ip, reason := CheckPublicIP(line)
		if reason != "" {
			out.Rejected = append(out.Rejected, Rejected{Line: i + 1, Value: truncateRunes(line, 100), Reason: reason})
			continue
		}
		if seen[ip] {
			out.Duplicates++
			continue
		}
		seen[ip] = true
		out.IPs = append(out.IPs, ip)
	}
	return out
}
