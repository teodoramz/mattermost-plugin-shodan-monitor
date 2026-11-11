package main

// Active (on-demand) Shodan scans: Shodan re-scans the IPs now, using 1 scan
// credit per IP. When the scan is done, the IPs are looked up as usual.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	scanBatchSize    = 100              // IPs per scan request
	scanPollInterval = 20 * time.Second // how often to ask Shodan whether the scan is done
	scanMaxWait      = 60 * time.Minute // give up waiting after this long and look up anyway
	scanSettleTime   = 30 * time.Second // let Shodan index the new data before looking up
)

type scanBatch struct {
	key    string
	ips    []string
	id     string
	status string
	err    error
}

type keyCredits struct {
	key     string
	credits int
	err     error
	plan    string
}

// scanCredits returns the scan credits of every configured key.
func (p *Plugin) scanCredits(ctx context.Context, client *shodanClient, keys []string) ([]keyCredits, int) {
	out := make([]keyCredits, 0, len(keys))
	total := 0
	for _, k := range keys {
		info, err := client.APIInfo(ctx, k)
		kc := keyCredits{key: k, err: err}
		if err == nil {
			kc.credits = info.ScanCredits
			kc.plan = info.Plan
			if kc.credits > 0 {
				total += kc.credits
			}
		}
		out = append(out, kc)
	}
	return out, total
}

func creditsText(credits []keyCredits) string {
	parts := make([]string, 0, len(credits))
	for _, c := range credits {
		if c.err != nil {
			parts = append(parts, fmt.Sprintf("%s: %s", maskKey(c.key), c.err.Error()))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %d", maskKey(c.key), c.credits))
		}
	}
	return strings.Join(parts, ", ")
}

// planBatches splits the IPs across keys according to their scan credits.
func planBatches(credits []keyCredits, ips []string) []*scanBatch {
	var batches []*scanBatch
	rest := ips
	for _, c := range credits {
		if c.err != nil || c.credits <= 0 || len(rest) == 0 {
			continue
		}
		n := min(c.credits, len(rest))
		take := rest[:n]
		rest = rest[n:]
		for len(take) > 0 {
			m := min(scanBatchSize, len(take))
			batches = append(batches, &scanBatch{key: c.key, ips: take[:m]})
			take = take[m:]
		}
	}
	return batches
}

// scanCheck answers "/shodan scan all" without "confirm": how many credits it needs.
func (p *Plugin) scanCheck(ctx context.Context, userID, channelID string) {
	ips, err := p.getIPList()
	if err != nil || len(ips) == 0 {
		p.ephemeral(userID, channelID, "The IP list is empty. Upload one first (`/shodan upload` explains how).")
		return
	}
	keys := p.getConfiguration().apiKeys()
	if len(keys) == 0 {
		p.ephemeral(userID, channelID, "No Shodan API key is configured.")
		return
	}
	credits, total := p.scanCredits(ctx, p.newShodan(keys), keys)
	msg := fmt.Sprintf("An active scan of the whole list asks Shodan to scan **%d IPs** now and uses **%d scan credits**.\nScan credits on your keys: %s (total **%d**).\n",
		len(ips), len(ips), creditsText(credits), total)
	if total < len(ips) {
		msg += "\nNot enough scan credits for the whole list. You can still scan single IPs with `/shodan scan <ip>`."
	} else {
		msg += "\nTo start it, run `/shodan scan all confirm`. The result is posted in this channel when Shodan has finished (usually a few minutes, up to an hour)."
	}
	p.ephemeral(userID, channelID, msg)
}

// activeScan submits an on-demand scan, waits for Shodan to finish and then
// posts the lookup result. whole=true scans the whole list.
func (p *Plugin) activeScan(ctx context.Context, ips []string, whole bool, req runRequest) {
	if whole {
		m, ok := p.lockWholeList(ctx)
		if !ok {
			p.ephemeral(req.UserID, req.ChannelID, p.alreadyRunningText())
			return
		}
		defer m.Unlock()
		var err error
		if ips, err = p.getIPList(); err != nil || len(ips) == 0 {
			p.ephemeral(req.UserID, req.ChannelID, "The IP list is empty.")
			return
		}
	}

	keys := p.getConfiguration().apiKeys()
	if len(keys) == 0 {
		p.ephemeral(req.UserID, req.ChannelID, "No Shodan API key is configured.")
		return
	}
	client := p.newShodan(keys)

	credits, total := p.scanCredits(ctx, client, keys)
	if ctx.Err() != nil {
		return
	}
	if total < len(ips) {
		p.ephemeral(req.UserID, req.ChannelID, fmt.Sprintf("Not enough scan credits: this needs %d, your keys have %d (%s). Nothing was scanned.",
			len(ips), total, creditsText(credits)))
		return
	}

	var progress *runProgress
	if whole {
		progress = &runProgress{Kind: runActive, Phase: "submitting the scan", Started: time.Now().UnixMilli(), Total: len(ips), By: p.username(req.UserID)}
		p.setProgress(progress)
		defer p.setProgress(nil)
	}

	batches := planBatches(credits, ips)
	submitted := 0
	var ids, notes []string
	for _, b := range batches {
		sub, err := client.SubmitScan(ctx, b.key, b.ips)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			b.err = err
			notes = append(notes, fmt.Sprintf("A scan of %s could not be submitted with key %s: %s - they were looked up without a fresh scan.",
				plural(len(b.ips), "IP", "IPs"), maskKey(b.key), md(err.Error())))
			continue
		}
		b.id = sub.ID
		submitted += sub.Count
		ids = append(ids, sub.ID)
	}
	if submitted == 0 {
		p.ephemeral(req.UserID, req.ChannelID, "Shodan did not accept the scan:\n- "+strings.Join(notes, "\n- "))
		return
	}

	target := ips[0]
	if whole {
		target = "the whole list (" + plural(len(ips), "IP", "IPs") + ")"
	}
	p.ephemeral(req.UserID, req.ChannelID, fmt.Sprintf("Shodan accepted the active scan of %s - %s used (scan ID %s). Waiting for Shodan to finish; the result will be posted in this channel.",
		target, plural(submitted, "scan credit", "scan credits"), strings.Join(ids, ", ")))

	// Wait for every submitted scan to reach DONE.
	if progress != nil {
		progress.Phase = "waiting for Shodan to finish the scan"
		p.setProgress(progress)
	}
	deadline := time.Now().Add(scanMaxWait)
	for {
		pending := 0
		for _, b := range batches {
			if b.id == "" || b.status == "DONE" {
				continue
			}
			st, err := client.ScanStatus(ctx, b.key, b.id)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				b.status = st
			}
			if b.status != "DONE" {
				pending++
			}
		}
		if pending == 0 || time.Now().After(deadline) {
			break
		}
		if progress != nil {
			p.setProgress(progress) // keep "Running now" alive while waiting (the KV entry expires)
		}
		if sleepCtx(ctx, scanPollInterval) != nil {
			return
		}
	}
	if sleepCtx(ctx, scanSettleTime) != nil {
		return
	}

	notes = append([]string{fmt.Sprintf("Active scan: %s submitted to Shodan (%s used, scan ID %s).",
		plural(submitted, "IP", "IPs"), plural(submitted, "scan credit", "scan credits"), strings.Join(ids, ", "))}, notes...)
	for _, b := range batches {
		if b.id != "" && b.status != "DONE" {
			notes = append(notes, fmt.Sprintf("Scan %s was still %q after %d minutes - the data below may not include it yet.",
				b.id, orDash(b.status), int(scanMaxWait.Minutes())))
		}
	}

	req.Kind = runActive
	req.Notes = append(req.Notes, notes...)
	if whole {
		if progress != nil {
			progress.Phase = "looking up"
			p.setProgress(progress)
		}
		p.lookupWholeListLocked(ctx, req)
		return
	}
	p.lookupSingle(ctx, ips[0], req)
}
