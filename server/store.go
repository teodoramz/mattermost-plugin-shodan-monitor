package main

import (
	"slices"
	"sort"
	"time"

	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/pkg/errors"
)

// KV store keys.
const (
	kvIPList         = "ip_list"
	kvPreviousList   = "ip_list_previous"
	kvLastUpload     = "last_upload"
	kvAccess         = "access_users"
	kvReportChannel  = "report_channel"
	kvLastScheduled  = "last_scheduled_run"
	kvRunProgress    = "run_progress"
	kvBaselinePrefix = "b_"
)

// UploadSummary describes the last time the whole list was replaced.
type UploadSummary struct {
	At            int64      `json:"at"`
	By            string     `json:"by"`
	Source        string     `json:"source"`
	Applied       bool       `json:"applied"`
	Message       string     `json:"message"`
	Total         int        `json:"total"`
	Added         int        `json:"added"`
	Removed       int        `json:"removed"`
	Unchanged     int        `json:"unchanged"`
	Duplicates    int        `json:"duplicates"`
	RejectedCount int        `json:"rejected_count"`
	Rejected      []Rejected `json:"rejected"`
}

const maxStoredRejected = 200

// ---------------------------------------------------------------------------
// IP list
// ---------------------------------------------------------------------------

func (p *Plugin) getIPList() ([]string, error) {
	var ips []string
	if err := p.client.KV.Get(kvIPList, &ips); err != nil {
		return nil, errors.Wrap(err, "failed to read the IP list")
	}
	return ips, nil
}

func (p *Plugin) saveIPList(ips []string) error {
	if ips == nil {
		ips = []string{}
	}
	_, err := p.client.KV.Set(kvIPList, ips)
	return errors.Wrap(err, "failed to save the IP list")
}

func (p *Plugin) getPreviousList() ([]string, error) {
	var ips []string
	err := p.client.KV.Get(kvPreviousList, &ips)
	return ips, err
}

// replaceList replaces the whole list with the IPs in text. A file without a
// single valid public IP never wipes the list.
func (p *Plugin) replaceList(text, byUser, source string) (*UploadSummary, []string, error) {
	parsed := ParseIPList(text)
	sum := &UploadSummary{
		At:            time.Now().UnixMilli(),
		By:            byUser,
		Source:        source,
		Duplicates:    parsed.Duplicates,
		RejectedCount: len(parsed.Rejected),
		Rejected:      parsed.Rejected,
	}
	if len(sum.Rejected) > maxStoredRejected {
		sum.Rejected = sum.Rejected[:maxStoredRejected]
	}

	if len(parsed.IPs) == 0 {
		sum.Message = "No valid public IP address found in the file - the list was not changed."
		prev, err := p.getIPList()
		if err != nil {
			return nil, nil, err
		}
		sum.Total = len(prev)
		p.saveUploadSummary(sum)
		return sum, nil, nil
	}

	p.stateMutex.Lock()
	defer p.stateMutex.Unlock()

	prev, err := p.getIPList()
	if err != nil {
		return nil, nil, err
	}
	added, removed := diffSets(prev, parsed.IPs)
	if err := p.saveIPList(parsed.IPs); err != nil {
		return nil, nil, err
	}
	if len(prev) > 0 {
		if _, err := p.client.KV.Set(kvPreviousList, prev); err != nil {
			p.API.LogWarn("failed to keep the previous IP list", "err", err.Error())
		}
	}
	for _, ip := range removed {
		p.deleteBaseline(ip)
	}

	sum.Applied = true
	sum.Total = len(parsed.IPs)
	sum.Added = len(added)
	sum.Removed = len(removed)
	sum.Unchanged = len(parsed.IPs) - len(added)
	sum.Message = "The IP list was replaced."
	p.saveUploadSummary(sum)
	return sum, prev, nil
}

func (p *Plugin) saveUploadSummary(sum *UploadSummary) {
	if _, err := p.client.KV.Set(kvLastUpload, sum); err != nil {
		p.API.LogWarn("failed to save the upload summary", "err", err.Error())
	}
}

func (p *Plugin) getUploadSummary() *UploadSummary {
	var sum UploadSummary
	if err := p.client.KV.Get(kvLastUpload, &sum); err != nil || sum.At == 0 {
		return nil
	}
	return &sum
}

// addIP adds one public IP. It returns the normalised IP, whether it was
// already in the list, and a rejection reason ("" when accepted).
func (p *Plugin) addIP(input string) (string, bool, string, error) {
	ip, reason := CheckPublicIP(input)
	if reason != "" {
		return "", false, reason, nil
	}
	p.stateMutex.Lock()
	defer p.stateMutex.Unlock()
	ips, err := p.getIPList()
	if err != nil {
		return "", false, "", err
	}
	if slices.Contains(ips, ip) {
		return ip, true, "", nil
	}
	return ip, false, "", p.saveIPList(append(ips, ip))
}

// removeIP removes one IP and its saved result. It reports whether the IP was in the list.
func (p *Plugin) removeIP(input string) (string, bool, error) {
	ip := input
	if norm, reason := CheckPublicIP(input); reason == "" {
		ip = norm
	}
	p.stateMutex.Lock()
	defer p.stateMutex.Unlock()
	ips, err := p.getIPList()
	if err != nil {
		return ip, false, err
	}
	out := make([]string, 0, len(ips))
	found := false
	for _, x := range ips {
		if x == ip {
			found = true
			continue
		}
		out = append(out, x)
	}
	if !found {
		return ip, false, nil
	}
	if err := p.saveIPList(out); err != nil {
		return ip, false, err
	}
	p.deleteBaseline(ip)
	return ip, true, nil
}

func (p *Plugin) inList(ip string) bool {
	ips, err := p.getIPList()
	if err != nil {
		return false
	}
	return slices.Contains(ips, ip)
}

// ---------------------------------------------------------------------------
// Baselines (last saved result per IP)
// ---------------------------------------------------------------------------

func (p *Plugin) getBaseline(ip string) (*Snapshot, error) {
	var s Snapshot
	if err := p.client.KV.Get(kvBaselinePrefix+ip, &s); err != nil {
		return nil, err
	}
	if s.Status == "" {
		return nil, nil
	}
	return &s, nil
}

func (p *Plugin) saveBaseline(ip string, s *Snapshot) {
	if _, err := p.client.KV.Set(kvBaselinePrefix+ip, s); err != nil {
		p.API.LogError("failed to save the result for an IP", "ip", ip, "err", err.Error())
	}
}

func (p *Plugin) deleteBaseline(ip string) {
	if err := p.client.KV.Delete(kvBaselinePrefix + ip); err != nil {
		p.API.LogWarn("failed to delete the saved result for an IP", "ip", ip, "err", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Access list, report channel, schedule state
// ---------------------------------------------------------------------------

func (p *Plugin) getAccessList() ([]string, error) {
	var ids []string
	err := p.client.KV.Get(kvAccess, &ids)
	return ids, errors.Wrap(err, "failed to read the access list")
}

// setAccess grants (grant=true) or removes access; it reports whether anything changed.
func (p *Plugin) setAccess(userID string, grant bool) (bool, error) {
	p.stateMutex.Lock()
	defer p.stateMutex.Unlock()
	ids, err := p.getAccessList()
	if err != nil {
		return false, err
	}
	has := false
	out := make([]string, 0, len(ids)+1)
	for _, id := range ids {
		if id == userID {
			has = true
			if !grant {
				continue
			}
		}
		out = append(out, id)
	}
	if grant == has {
		return false, nil
	}
	if grant {
		out = append(out, userID)
	}
	sort.Strings(out)
	_, err = p.client.KV.Set(kvAccess, out)
	return true, errors.Wrap(err, "failed to save the access list")
}

func (p *Plugin) getReportChannel() string {
	var id string
	_ = p.client.KV.Get(kvReportChannel, &id)
	return id
}

func (p *Plugin) setReportChannel(channelID string) error {
	_, err := p.client.KV.Set(kvReportChannel, channelID)
	return err
}

func (p *Plugin) getLastScheduled() int64 {
	var at int64
	_ = p.client.KV.Get(kvLastScheduled, &at)
	return at
}

func (p *Plugin) setLastScheduled(at int64) {
	if _, err := p.client.KV.Set(kvLastScheduled, at); err != nil {
		p.API.LogError("failed to save the last scheduled run time", "err", err.Error())
	}
}

// runProgress is shown by /shodan status while a whole-list run is going.
type runProgress struct {
	Kind    string `json:"kind"`
	Phase   string `json:"phase"`
	Started int64  `json:"started"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	By      string `json:"by"`
}

func (p *Plugin) setProgress(pr *runProgress) {
	if pr == nil {
		_ = p.client.KV.Delete(kvRunProgress)
		return
	}
	// Expires on its own if this node dies mid-run.
	_, _ = p.client.KV.Set(kvRunProgress, pr, pluginapi.SetExpiry(15*time.Minute))
}

func (p *Plugin) getProgress() *runProgress {
	var pr runProgress
	if err := p.client.KV.Get(kvRunProgress, &pr); err != nil || pr.Started == 0 {
		return nil
	}
	return &pr
}
