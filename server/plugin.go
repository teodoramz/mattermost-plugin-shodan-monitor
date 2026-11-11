package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"
	"github.com/mattermost/mattermost/server/public/pluginapi/cluster"
)

const (
	defaultLookupIntervalDays = 30

	// How often the scheduler checks whether a scheduled run is due. Each check
	// is a few KV reads; a short tick means a due run (or one postponed because
	// another whole-list run was going) starts within a minute.
	schedulerTick = time.Minute
)

// Plugin implements the Mattermost server plugin interface.
type Plugin struct {
	plugin.MattermostPlugin

	client    *pluginapi.Client
	botUserID string

	configurationLock sync.RWMutex
	configuration     *configuration

	// stateMutex serialises changes to the IP list and access list across the cluster.
	stateMutex *cluster.Mutex
	job        *cluster.Job

	// Background work (lookups, scans) is cancelled when the plugin stops.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// newShodan builds the Shodan client for one run (replaced in tests).
	newShodan func(keys []string) *shodanClient
}

// getConfiguration returns the active configuration under a read lock.
func (p *Plugin) getConfiguration() *configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.configuration == nil {
		return &configuration{LookupIntervalDays: defaultLookupIntervalDays}
	}
	return p.configuration
}

func (p *Plugin) setConfiguration(c *configuration) {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()
	p.configuration = c
}

// OnConfigurationChange loads settings from the System Console.
func (p *Plugin) OnConfigurationChange() error {
	cfg := new(configuration)
	if err := p.API.LoadPluginConfiguration(cfg); err != nil {
		return fmt.Errorf("failed to load plugin configuration: %w", err)
	}
	if cfg.LookupIntervalDays < 0 {
		cfg.LookupIntervalDays = 0
	}
	p.setConfiguration(cfg)
	return nil
}

// OnActivate sets up the bot, the slash command and the scheduler.
func (p *Plugin) OnActivate() error {
	p.client = pluginapi.NewClient(p.API, p.Driver)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	if p.newShodan == nil {
		p.newShodan = newShodanClient
	}

	botID, err := p.client.Bot.EnsureBot(&model.Bot{
		Username:    "shodan-monitor",
		DisplayName: "Shodan Monitor",
		Description: "Looks up the monitored IP list on Shodan and posts what changed.",
	})
	if err != nil {
		return fmt.Errorf("failed to ensure bot account: %w", err)
	}
	p.botUserID = botID

	p.stateMutex, err = cluster.NewMutex(p.API, "state")
	if err != nil {
		return fmt.Errorf("failed to create mutex: %w", err)
	}

	if err = p.registerCommand(); err != nil {
		return fmt.Errorf("failed to register command: %w", err)
	}

	// The job only ticks; scheduledTick decides whether a run is due and
	// starts it in the background, so this callback returns quickly.
	p.job, err = cluster.Schedule(p.API, "scheduler", cluster.MakeWaitForInterval(schedulerTick), p.scheduledTick)
	if err != nil {
		return fmt.Errorf("failed to schedule the job: %w", err)
	}
	return nil
}

// OnDeactivate stops the scheduler and cancels running lookups.
func (p *Plugin) OnDeactivate() error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.job != nil {
		_ = p.job.Close()
	}
	done := make(chan struct{})
	go func() { // not wg.Go: this goroutine waits on wg itself
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		p.API.LogWarn("background work did not stop in time")
	}
	return nil
}

// background runs fn in a goroutine that is cancelled when the plugin stops.
func (p *Plugin) background(fn func(ctx context.Context)) {
	p.wg.Go(func() {
		defer func() {
			if r := recover(); r != nil {
				p.API.LogError("panic in background work", "panic", fmt.Sprint(r))
			}
		}()
		fn(p.ctx)
	})
}

// scheduledTick starts a scheduled whole-list lookup when one is due.
func (p *Plugin) scheduledTick() {
	why, due := p.scheduleState()
	if !due {
		if why != "" {
			p.API.LogDebug("scheduled lookup not run", "reason", why)
		}
		return
	}
	channelID := p.getReportChannel()
	p.background(func(ctx context.Context) {
		p.runWholeList(ctx, runRequest{Kind: runScheduled, ChannelID: channelID})
	})
}

// scheduleState says whether a scheduled run is due now, or why scheduled runs
// are paused (the reason is shown by /shodan status).
func (p *Plugin) scheduleState() (string, bool) {
	cfg := p.getConfiguration()
	if cfg.LookupIntervalDays <= 0 {
		return "scheduled lookups are turned off (interval is 0)", false
	}
	if len(cfg.apiKeys()) == 0 {
		return "no Shodan API key is configured", false
	}
	reportChannel := p.getReportChannel()
	if reportChannel == "" {
		return "no report channel - run /shodan report-here in the private channel that should get the reports", false
	}
	if p.isPublicChannel(reportChannel) {
		return "the report channel is public (or no longer exists) - make it private, or run /shodan report-here in a private channel", false
	}
	ips, err := p.getIPList()
	if err != nil {
		return err.Error(), false
	}
	if len(ips) == 0 {
		return "the IP list is empty", false
	}
	last := p.getLastScheduled()
	if last == 0 {
		return "", true
	}
	next := time.UnixMilli(last).Add(time.Duration(cfg.LookupIntervalDays) * 24 * time.Hour)
	return "", !time.Now().Before(next)
}

// nextScheduled returns when the next scheduled run should happen (zero = as soon as possible).
func (p *Plugin) nextScheduled() time.Time {
	last := p.getLastScheduled()
	if last == 0 {
		return time.Time{}
	}
	return time.UnixMilli(last).Add(time.Duration(p.getConfiguration().LookupIntervalDays) * 24 * time.Hour)
}
