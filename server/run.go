package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/pluginapi/cluster"
)

// Kinds of runs (shown in reports and in results.json "run_type").
const (
	runScheduled = "scheduled lookup"
	runManual    = "manual lookup"
	runSingle    = "single IP lookup"
	runActive    = "active scan"
)

type runRequest struct {
	Kind      string
	ChannelID string   // where the report is posted
	UserID    string   // who asked ("" for scheduled runs)
	Notes     []string // extra lines for the report (active scan details)
}

type ipChange struct {
	IP    string
	Label string
	Lines []string
}

type ipNote struct {
	IP   string
	Text string
}

type runOutcome struct {
	Kind        string
	Started     time.Time
	Finished    time.Time
	ListSize    int
	Results     []LookupResult
	Changed     []ipChange
	First       []ipNote
	Errors      []ipNote
	KeyWarnings []string
	Notes       []string
	Aborted     string
}

func (o *runOutcome) count(status string) int {
	n := 0
	for _, r := range o.Results {
		if r.Status == status {
			n++
		}
	}
	return n
}

// lockWholeList makes sure only one whole-list run (lookup or active scan)
// happens at a time across the cluster. ok=false means one is already running.
func (p *Plugin) lockWholeList(ctx context.Context) (*cluster.Mutex, bool) {
	m, err := cluster.NewMutex(p.API, "whole_list_run")
	if err != nil {
		p.API.LogError("failed to create the run mutex", "err", err.Error())
		return nil, false
	}
	lockCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := m.LockWithContext(lockCtx); err != nil {
		return nil, false
	}
	return m, true
}

func (p *Plugin) alreadyRunningText() string {
	if pr := p.getProgress(); pr != nil {
		return fmt.Sprintf("A whole-list %s is already running (%s, %d/%d done, started %s). Try again when it has finished.",
			pr.Kind, pr.Phase, pr.Done, pr.Total, fmtMillis(pr.Started))
	}
	return "A whole-list run is already going. Try again when it has finished."
}

// runWholeList looks up every IP in the list and posts the changes.
func (p *Plugin) runWholeList(ctx context.Context, req runRequest) {
	m, ok := p.lockWholeList(ctx)
	if !ok {
		if req.Kind == runScheduled {
			// Not recorded as done, so the scheduler retries on its next check.
			p.API.LogDebug("scheduled lookup postponed: another whole-list run is in progress")
		}
		p.ephemeral(req.UserID, req.ChannelID, p.alreadyRunningText())
		return
	}
	defer m.Unlock()
	p.lookupWholeListLocked(ctx, req)
}

// lookupWholeListLocked does the work of runWholeList; the caller holds the lock.
func (p *Plugin) lookupWholeListLocked(ctx context.Context, req runRequest) {
	ips, err := p.getIPList()
	if err != nil {
		p.ephemeral(req.UserID, req.ChannelID, "Could not read the IP list: "+err.Error())
		return
	}
	if len(ips) == 0 {
		p.ephemeral(req.UserID, req.ChannelID, "The IP list is empty. Upload one first (`/shodan upload` explains how).")
		return
	}
	keys := p.getConfiguration().apiKeys()
	if len(keys) == 0 {
		p.ephemeral(req.UserID, req.ChannelID, "No Shodan API key is configured. A system admin can add keys in **System Console → Plugins → Shodan Monitor**.")
		return
	}

	client := p.newShodan(keys)
	client.CheckKeys(ctx)
	o := &runOutcome{Kind: req.Kind, Started: time.Now(), ListSize: len(ips), Notes: req.Notes}
	progress := &runProgress{Kind: req.Kind, Phase: "looking up", Started: o.Started.UnixMilli(), Total: len(ips), By: p.username(req.UserID)}
	p.setProgress(progress)
	defer p.setProgress(nil)

	for i, ip := range ips {
		r, err := p.lookupOne(ctx, client, ip)
		if ctx.Err() != nil {
			// Plugin stopping: nothing is saved or posted, so the run happens again later.
			p.API.LogInfo("whole-list run cancelled", "kind", req.Kind, "done", i)
			return
		}
		if err != nil {
			o.Aborted = err.Error()
			break
		}
		o.Results = append(o.Results, r)
		if (i+1)%5 == 0 {
			progress.Done = i + 1
			p.setProgress(progress)
		}
	}
	o.KeyWarnings = client.KeyWarnings()
	o.Finished = time.Now()
	p.compareAndSave(o)

	if req.ChannelID != "" {
		p.postRunReport(req.ChannelID, o)
	}
	if req.Kind == runScheduled {
		p.setLastScheduled(o.Finished.UnixMilli())
	}
}

// lookupOne looks up a single IP. The error is non-nil only when the whole run
// must stop (no usable key, plugin stopping); per-IP problems are recorded in
// the result.
func (p *Plugin) lookupOne(ctx context.Context, client *shodanClient, ip string) (LookupResult, error) {
	host, err := client.Host(ctx, ip)
	switch {
	case err == nil:
		return LookupResult{IP: ip, Status: statusFound, Host: parseHost(ip, host)}, nil
	case errors.Is(err, errNotFound):
		return LookupResult{IP: ip, Status: statusNotFound}, nil
	case errors.Is(err, errNoUsableKeys), errors.Is(err, errNoKeys), ctx.Err() != nil:
		return LookupResult{}, err
	default:
		return LookupResult{IP: ip, Status: statusError, Error: err.Error()}, nil
	}
}

// compareAndSave compares each result with the IP's saved result, fills in
// the changes, and saves the new result as the baseline (for IPs still in the list).
func (p *Plugin) compareAndSave(o *runOutcome) {
	current := map[string]bool{}
	if ips, err := p.getIPList(); err == nil {
		for _, ip := range ips {
			current[ip] = true
		}
	}
	now := time.Now().UnixMilli()
	for _, r := range o.Results {
		if r.Status == statusError {
			o.Errors = append(o.Errors, ipNote{IP: r.IP, Text: r.Error})
			continue
		}
		snap := snapshotFor(r, now)
		old, err := p.getBaseline(r.IP)
		if err != nil {
			p.API.LogWarn("failed to read the saved result", "ip", r.IP, "err", err.Error())
		}
		if old == nil {
			o.First = append(o.First, ipNote{IP: r.IP, Text: describeResult(r)})
		} else if lines := Compare(old, snap); len(lines) > 0 {
			o.Changed = append(o.Changed, ipChange{IP: r.IP, Label: hostLabel(r, old), Lines: lines})
		}
		if current[r.IP] {
			p.saveBaseline(r.IP, snap)
		}
	}
}

// lookupSingle looks up one IP and posts a full summary of it.
func (p *Plugin) lookupSingle(ctx context.Context, ip string, req runRequest) {
	keys := p.getConfiguration().apiKeys()
	if len(keys) == 0 {
		p.ephemeral(req.UserID, req.ChannelID, "No Shodan API key is configured. A system admin can add keys in **System Console → Plugins → Shodan Monitor**.")
		return
	}
	client := p.newShodan(keys)
	started := time.Now()
	r, err := p.lookupOne(ctx, client, ip)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		msg := "Lookup of " + ip + " failed: " + md(err.Error())
		if w := client.KeyWarnings(); len(w) > 0 {
			msg += "\n- " + strings.Join(w, "\n- ")
		}
		p.ephemeral(req.UserID, req.ChannelID, msg)
		return
	}

	s := singleView{Result: r, InList: p.inList(ip), Notes: req.Notes, KeyWarnings: client.KeyWarnings(), Kind: req.Kind}
	if s.InList && r.Status != statusError {
		snap := snapshotFor(r, time.Now().UnixMilli())
		old, _ := p.getBaseline(ip)
		if old == nil {
			s.First = true
		} else {
			s.Since = old.SavedAt
			s.Changes = Compare(old, snap)
		}
		p.saveBaseline(ip, snap)
	}

	if p.isPublicChannel(req.ChannelID) {
		p.ephemeral(req.UserID, req.ChannelID, publicChannelText)
		return
	}
	o := &runOutcome{Kind: req.Kind, Started: started, Finished: time.Now(), ListSize: 1, Results: []LookupResult{r}}
	data, err := buildResultsJSON(o)
	if err != nil {
		p.API.LogError("failed to build results.json", "err", err.Error())
	}
	p.postMessage(req.ChannelID, renderSingle(s), namedFile{Name: "results.json", Data: data})
}

// buildResultsJSON produces the same format as shodan_scan.py.
func buildResultsJSON(o *runOutcome) ([]byte, error) {
	info := cleaned(
		kv{"source", productName() + " (Mattermost plugin)"},
		kv{"plugin_version", pluginVersion()},
		kv{"run_type", o.Kind},
		kv{"started", isoTime(o.Started)},
		kv{"finished", isoTime(o.Finished)},
		kv{"ips_in_list", o.ListSize},
		kv{"ips_scanned", len(o.Results)},
		kv{"found", o.count(statusFound)},
		kv{"not_found", o.count(statusNotFound)},
		kv{"errors", o.count(statusError)},
		kv{"aborted", o.Aborted},
	)
	results := o.Results
	if results == nil {
		results = []LookupResult{}
	}
	doc := omap{{"scan_info", info}, {"results", results}}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *Plugin) postRunReport(channelID string, o *runOutcome) {
	if p.isPublicChannel(channelID) {
		p.API.LogError("report not posted: the channel is public or no longer exists", "channel_id", channelID)
		return
	}
	msg, full, cut := renderRunReport(o)
	data, err := buildResultsJSON(o)
	if err != nil {
		p.API.LogError("failed to build results.json", "err", err.Error())
	}
	files := []namedFile{{Name: "results.json", Data: data}}
	if cut {
		files = append(files, namedFile{Name: "changes.md", Data: []byte(full)})
	}
	p.postMessage(channelID, msg, files...)
}
