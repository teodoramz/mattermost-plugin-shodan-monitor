package main

import (
	"fmt"
	"strings"
)

// maxCVEsInSummary is how many CVEs a single-IP post lists before "... and N more".
const maxCVEsInSummary = 10

// hostLabel is the short "Organization · ISP · ASN" shown next to an IP.
func hostLabel(r LookupResult, old *Snapshot) string {
	org, isp, asn := "", "", ""
	if r.Host != nil {
		org, isp, asn = r.Host.Organization, r.Host.ISP, r.Host.ASN
	}
	if org == "" && isp == "" && old != nil {
		org, isp, asn = old.Org, old.ISP, old.ASN
	}
	return joinDistinct(org, isp, asn)
}

// joinDistinct joins the non-empty values with " · ", skipping repeats
// (the ISP is often the same as the organization).
func joinDistinct(values ...string) string {
	parts := []string{}
	seen := map[string]bool{}
	for _, s := range values {
		if s != "" && !seen[s] {
			seen[s] = true
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " · ")
}

// describeResult is the one-line summary used for first lookups.
func describeResult(r LookupResult) string {
	switch r.Status {
	case statusNotFound:
		return "not in Shodan's data"
	case statusError:
		return "lookup failed: " + r.Error
	}
	h := r.Host
	parts := []string{}
	if who := joinDistinct(h.Organization, h.ISP); who != "" {
		parts = append(parts, who)
	}
	if len(h.OpenPorts) > 0 {
		parts = append(parts, fmt.Sprintf("%s (%s)", plural(len(h.OpenPorts), "open port", "open ports"), joinInts(h.OpenPorts)))
	} else {
		parts = append(parts, "no open ports")
	}
	parts = append(parts, plural(len(h.CVEs), "CVE", "CVEs"))
	return strings.Join(parts, " · ")
}

// renderRunReport renders a whole-list report. It returns the post text, the
// full text (for changes.md) and whether the post had to be cut short.
func renderRunReport(o *runOutcome) (string, string, bool) {
	var b strings.Builder
	fmt.Fprintf(&b, "#### %s - %s · %s\n", productName(), o.Kind, fmtTime(o.Finished))

	parts := []string{fmt.Sprintf("**%d** of %d IPs checked", len(o.Results), o.ListSize)}
	parts = append(parts, fmt.Sprintf("**%d** changed", len(o.Changed)))
	if len(o.First) > 0 {
		parts = append(parts, fmt.Sprintf("**%d** first lookups", len(o.First)))
	}
	if len(o.Errors) > 0 {
		parts = append(parts, fmt.Sprintf("**%d** could not be checked", len(o.Errors)))
	}
	b.WriteString(strings.Join(parts, " · ") + "\n")

	if o.Aborted != "" {
		fmt.Fprintf(&b, "\n**Stopped early:** %s - %d of %d IPs checked. IPs that were not checked keep their previous result.\n",
			md(o.Aborted), len(o.Results), o.ListSize)
	}
	for _, n := range o.Notes {
		b.WriteString("\n" + n + "\n")
	}
	for _, w := range o.KeyWarnings {
		b.WriteString("\n**Warning:** " + md(w) + "\n")
	}

	if len(o.Changed) == 0 && len(o.Errors) == 0 && o.Aborted == "" {
		if len(o.First) == 0 {
			b.WriteString("\n**No changes** since the last lookup.\n")
		} else if len(o.First) < len(o.Results) {
			b.WriteString("\n**No changes** on the IPs that were looked up before.\n")
		}
	}

	if len(o.Changed) > 0 {
		fmt.Fprintf(&b, "\n##### Changed (%d)\n", len(o.Changed))
		for _, c := range o.Changed {
			b.WriteString("\n**" + c.IP + "**")
			if c.Label != "" {
				b.WriteString(" · " + md(c.Label))
			}
			b.WriteString("\n")
			for _, l := range c.Lines {
				b.WriteString("- " + md(l) + "\n")
			}
		}
	}
	if len(o.First) > 0 {
		fmt.Fprintf(&b, "\n##### First lookups (%d) - no earlier result to compare with\n", len(o.First))
		for _, f := range o.First {
			b.WriteString("- **" + f.IP + "** - " + md(f.Text) + "\n")
		}
	}
	if len(o.Errors) > 0 {
		fmt.Fprintf(&b, "\n##### Could not check (%d) - previous result kept\n", len(o.Errors))
		for _, e := range o.Errors {
			b.WriteString("- **" + e.IP + "** - " + md(e.Text) + "\n")
		}
	}
	b.WriteString("\nFull data is in the attached `results.json`.")

	full := b.String()
	short, cut := cutRunes(full, maxPostRunes)
	if cut {
		short += "\n\n_...cut short to fit in one post - the full list is in the attached `changes.md`, and all data is in `results.json`._"
	}
	return short, full, cut
}

// singleView is what a single-IP post shows.
type singleView struct {
	Result      LookupResult
	Kind        string
	InList      bool
	First       bool
	Since       int64
	Changes     []string
	Notes       []string
	KeyWarnings []string
}

func renderSingle(s singleView) string {
	r := s.Result
	var b strings.Builder
	title := productName() + " - lookup of " + r.IP
	if s.Kind == runActive {
		title = productName() + " - active scan of " + r.IP
	}
	fmt.Fprintf(&b, "#### %s\n", title)
	for _, n := range s.Notes {
		b.WriteString(n + "\n\n")
	}
	for _, w := range s.KeyWarnings {
		b.WriteString("**Warning:** " + md(w) + "\n\n")
	}

	switch r.Status {
	case statusNotFound:
		b.WriteString("\nShodan has no data for this IP.\n")
	case statusError:
		b.WriteString("\n**Lookup failed:** " + md(r.Error) + "\n")
	case statusFound:
		renderHostDetails(&b, r.Host)
	}

	b.WriteString("\n")
	switch {
	case !s.InList:
		b.WriteString("_This IP is not in the monitored list, so nothing was saved or compared._\n")
	case r.Status == statusError:
		b.WriteString("_The previous result for this IP was kept._\n")
	case s.First:
		b.WriteString("**Changes:** first lookup of this IP - saved for future comparisons.\n")
	case len(s.Changes) == 0:
		fmt.Fprintf(&b, "**Changes since the last lookup (%s):** none\n", fmtMillis(s.Since))
	default:
		fmt.Fprintf(&b, "**Changes since the last lookup (%s):**\n", fmtMillis(s.Since))
		for _, l := range s.Changes {
			b.WriteString("- " + md(l) + "\n")
		}
	}
	b.WriteString("\nFull data is in the attached `results.json`.")
	out, cut := cutRunes(b.String(), maxPostRunes)
	if cut {
		out += "\n\n_...cut short to fit in one post - see `results.json`._"
	}
	return out
}

func renderHostDetails(b *strings.Builder, h *hostInfo) {
	line := []string{}
	seen := map[string]bool{}
	for _, s := range []string{h.Organization, h.ISP, h.ASN} {
		if s != "" && !seen[s] {
			seen[s] = true
			line = append(line, md(s))
		}
	}
	loc := strings.Trim(strings.Join([]string{h.City, h.Country}, ", "), ", ")
	if loc != "" {
		line = append(line, md(loc))
	}
	if len(line) > 0 {
		b.WriteString(strings.Join(line, " · ") + "\n")
	}
	b.WriteString("\n")
	if len(h.Hostnames) > 0 {
		b.WriteString("**Hostnames:** " + md(strings.Join(h.Hostnames, ", ")) + "  \n")
	}
	if len(h.Domains) > 0 {
		b.WriteString("**Domains:** " + md(strings.Join(h.Domains, ", ")) + "  \n")
	}
	if len(h.OS) > 0 {
		b.WriteString("**OS:** " + md(strings.Join(h.OS, ", ")) + "  \n")
	}
	if len(h.Tags) > 0 {
		b.WriteString("**Tags:** " + md(strings.Join(h.Tags, ", ")) + "  \n")
	}
	if len(h.OpenPorts) > 0 {
		b.WriteString("**Open ports:** " + joinInts(h.OpenPorts) + "\n")
	} else {
		b.WriteString("**Open ports:** none\n")
	}

	if len(h.Ports) > 0 {
		b.WriteString("\n| Port | Service | Product / version | Details |\n|---|---|---|---|\n")
		for _, p := range h.Ports {
			details := []string{}
			if p.HTTPStatus != "" {
				details = append(details, "HTTP "+p.HTTPStatus)
			}
			if p.HTTPTitle != "" {
				details = append(details, fmt.Sprintf("\"%s\"", truncateRunes(p.HTTPTitle, 60)))
			}
			if p.HTTPServer != "" {
				details = append(details, "server "+p.HTTPServer)
			}
			if p.CertSubject != "" || p.CertExpires != "" {
				details = append(details, strings.TrimSpace("TLS "+p.CertSubject+" (expires "+orDash(p.CertExpires)+")"))
			}
			if p.VulnCount > 0 {
				details = append(details, plural(p.VulnCount, "CVE", "CVEs"))
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s |\n", md(p.key()), md(orDash(p.Service)),
				md(orDash(strings.TrimSpace(p.Product+" "+p.Version))), md(orDash(strings.Join(details, " · "))))
		}
	}

	if len(h.CVEs) > 0 {
		fmt.Fprintf(b, "\n**CVEs (%d)** - highest CVSS first: ", len(h.CVEs))
		labels := []string{}
		for i, v := range h.CVEs {
			if i == maxCVEsInSummary {
				labels = append(labels, fmt.Sprintf("... and %d more", len(h.CVEs)-maxCVEsInSummary))
				break
			}
			if v.Has {
				labels = append(labels, fmt.Sprintf("%s (%s)", v.ID, trimFloat(v.CVSS)))
			} else {
				labels = append(labels, v.ID)
			}
		}
		b.WriteString(strings.Join(labels, ", ") + "\n")
	} else {
		b.WriteString("\n**CVEs:** none reported\n")
	}
}

func trimFloat(f float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", f), "0"), ".")
}
