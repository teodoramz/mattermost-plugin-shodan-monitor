package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

const commandTrigger = "shodan"

// listInlineMax is how many IPs /shodan list shows in the channel before
// sending the full list as a file in a direct message.
const listInlineMax = 200

func (p *Plugin) registerCommand() error {
	ac := model.NewAutocompleteData(commandTrigger, "[command]", "Monitor public IPs with Shodan")

	add := func(name, hint, help string) *model.AutocompleteData {
		d := model.NewAutocompleteData(name, hint, help)
		ac.AddCommand(d)
		return d
	}
	add("help", "", "Show usage help")
	add("status", "", "List size, schedule, report channel and API key status")
	add("list", "", "Show the monitored IP list")
	a := add("add", "<ip>", "Add one public IP to the list")
	a.AddTextArgument("IP address", "<ip>", "")
	r := add("remove", "<ip>", "Remove one IP from the list")
	r.AddTextArgument("IP address", "<ip>", "")
	add("upload", "", "How to upload or replace the whole IP list")
	l := add("lookup", "[ip|all]", "Look up Shodan's data now for one IP or the whole list (no scan credits)")
	l.AddTextArgument("An IP address, or all", "[ip|all]", "")
	s := add("scan", "<ip>|all [confirm]", "Ask Shodan to actively scan one IP or the whole list now (uses scan credits)")
	s.AddTextArgument("An IP address, or all", "<ip>|all [confirm]", "")
	add("report-here", "", "Post the scheduled reports in this channel (system admins)")

	acc := model.NewAutocompleteData("access", "add|remove|list", "Manage who can use the plugin besides system admins (system admins)")
	accAdd := model.NewAutocompleteData("add", "@user", "Give a user access")
	accAdd.AddTextArgument("Username", "@user", "")
	accRm := model.NewAutocompleteData("remove", "@user", "Remove a user's access")
	accRm.AddTextArgument("Username", "@user", "")
	acc.AddCommand(accAdd)
	acc.AddCommand(accRm)
	acc.AddCommand(model.NewAutocompleteData("list", "", "Show the users added manually"))
	ac.AddCommand(acc)

	return p.API.RegisterCommand(&model.Command{
		Trigger:          commandTrigger,
		AutoComplete:     true,
		AutoCompleteDesc: "Monitor public IPs with Shodan",
		AutoCompleteHint: "[command]",
		DisplayName:      "Shodan Monitor",
		AutocompleteData: ac,
	})
}

func respond(text string) *model.CommandResponse {
	return &model.CommandResponse{ResponseType: model.CommandResponseTypeEphemeral, Text: text}
}

// ExecuteCommand handles /shodan.
func (p *Plugin) ExecuteCommand(_ *plugin.Context, args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	fields := strings.Fields(args.Command)
	sub := "help"
	if len(fields) > 1 {
		sub = strings.ToLower(fields[1])
	}
	rest := fields[min(2, len(fields)):]

	if !p.canUse(args.UserId) {
		return respond("You don't have access to Shodan Monitor. Ask a system admin to run `/shodan access add @" + p.username(args.UserId) + "`."), nil
	}

	switch sub {
	case "help":
		return respond(p.helpText(p.isSysAdmin(args.UserId))), nil
	case "status":
		return respond(p.statusText()), nil
	case "list":
		return respond(p.listCommand(args)), nil
	case "add":
		return respond(p.addCommand(rest)), nil
	case "remove", "delete", "rm":
		return respond(p.removeCommand(rest)), nil
	case "upload":
		return respond(uploadHelp(p.isSysAdmin(args.UserId))), nil
	case "lookup":
		return respond(p.lookupCommand(args, rest)), nil
	case "scan":
		return respond(p.scanCommand(args, rest)), nil
	case "report-here":
		if !p.isSysAdmin(args.UserId) {
			return respond("Only system admins can choose the report channel."), nil
		}
		if !p.canPostResults(args.ChannelId) {
			return respond("The report channel must be private, so users without Shodan Monitor access can't read the reports. " +
				"Run this in a private channel, or turn on \"Allow public channels\" in the plugin settings."), nil
		}
		if err := p.setReportChannel(args.ChannelId); err != nil {
			return respond("Could not save the report channel: " + err.Error()), nil
		}
		if ch, appErr := p.API.GetChannel(args.ChannelId); appErr == nil && ch.Type == model.ChannelTypeOpen {
			return respond("Scheduled reports will be posted in this channel. **Note:** this is a public channel, so every member of the team can read the reports."), nil
		}
		return respond("Scheduled reports will be posted in this channel."), nil
	case "access":
		if !p.isSysAdmin(args.UserId) {
			return respond("Only system admins can manage access."), nil
		}
		return respond(p.accessCommand(rest)), nil
	}
	return respond(fmt.Sprintf("Unknown option `%s`. Run `/shodan help` for the list of options.", sub)), nil
}

func (p *Plugin) helpText(admin bool) string {
	s := "### " + productName() + " - usage\n" +
		"| Command | What it does |\n|---|---|\n" +
		"| `/shodan status` | List size, schedule, report channel, API key status |\n" +
		"| `/shodan list` | Show the monitored IPs |\n" +
		"| `/shodan add <ip>` | Add one public IP |\n" +
		"| `/shodan remove <ip>` | Remove one IP (and its saved result) |\n" +
		"| `/shodan upload` | How to upload / replace the whole list |\n" +
		"| `/shodan lookup <ip>` | Look up one IP now - Shodan's stored data, no credits used |\n" +
		"| `/shodan lookup all` | Look up the whole list now and post what changed |\n" +
		"| `/shodan scan <ip>` | Ask Shodan to actively scan one IP now (1 scan credit), then post the result |\n" +
		"| `/shodan scan all` | Shows how many scan credits a scan of the whole list needs; add `confirm` to start it |\n"
	if admin {
		s += "| `/shodan report-here` | Post the scheduled reports in this channel *(system admins)* |\n" +
			"| `/shodan access add @user` | Give a user access *(system admins)* |\n" +
			"| `/shodan access remove @user` | Remove a user's access *(system admins)* |\n" +
			"| `/shodan access list` | Users given access manually *(system admins)* |\n"
	}
	s += "\nEvery N days (System Console → Plugins → Shodan Monitor) the whole list is looked up again and only the IPs that changed are posted to the report channel, with the full `results.json` attached."
	if !p.getConfiguration().AllowPublicChannels {
		s += " Results are only posted in private channels and direct messages."
	}
	return s
}

func uploadHelp(admin bool) string {
	s := "**To upload or replace the whole IP list**, send a `.txt` file (one IP per line) to @shodan-monitor in a direct message. " +
		"It replaces the list; invalid and non-public addresses are rejected and listed in the reply, and the previous list is attached so you can undo."
	if admin {
		s += "\n\nAs a system admin you can also use the **Upload** button in **System Console → Plugins → Shodan Monitor → IP list**."
	}
	return s
}

func (p *Plugin) listCommand(args *model.CommandArgs) string {
	ips, err := p.getIPList()
	if err != nil {
		return "Could not read the IP list: " + err.Error()
	}
	if len(ips) == 0 {
		return "The IP list is empty. " + uploadHelp(p.isSysAdmin(args.UserId))
	}
	if len(ips) > listInlineMax {
		p.dm(args.UserId, fmt.Sprintf("The monitored IP list (%d IPs) is attached.", len(ips)),
			namedFile{Name: "shodan-ip-list.txt", Data: []byte(strings.Join(ips, "\n") + "\n")})
		return fmt.Sprintf("The list has %d IPs - I sent it to you as a file in a direct message from @shodan-monitor.", len(ips))
	}
	return fmt.Sprintf("**Monitored IPs (%d):**\n```\n%s\n```", len(ips), strings.Join(ips, "\n"))
}

func (p *Plugin) addCommand(rest []string) string {
	if len(rest) != 1 {
		return "Usage: `/shodan add <ip>`"
	}
	ip, already, reason, err := p.addIP(rest[0])
	switch {
	case err != nil:
		return "Could not add the IP: " + err.Error()
	case reason != "":
		return fmt.Sprintf("`%s` was not added: %s. Only public IP addresses can be monitored.", md(rest[0]), reason)
	case already:
		return fmt.Sprintf("`%s` is already in the list.", ip)
	}
	n := 0
	if ips, err := p.getIPList(); err == nil {
		n = len(ips)
	}
	return fmt.Sprintf("Added `%s` (%d IPs in the list). Run `/shodan lookup %s` to fetch its data now.", ip, n, ip)
}

func (p *Plugin) removeCommand(rest []string) string {
	if len(rest) != 1 {
		return "Usage: `/shodan remove <ip>`"
	}
	ip, removed, err := p.removeIP(rest[0])
	switch {
	case err != nil:
		return "Could not remove the IP: " + err.Error()
	case !removed:
		return fmt.Sprintf("`%s` is not in the list.", md(ip))
	}
	return fmt.Sprintf("Removed `%s` and its saved result.", ip)
}

func (p *Plugin) lookupCommand(args *model.CommandArgs, rest []string) string {
	if len(p.getConfiguration().apiKeys()) == 0 {
		return "No Shodan API key is configured. A system admin can add keys in **System Console → Plugins → Shodan Monitor**."
	}
	if !p.canPostResults(args.ChannelId) {
		return publicChannelText
	}
	target := "all"
	if len(rest) > 0 {
		target = rest[0]
	}
	req := runRequest{ChannelID: args.ChannelId, UserID: args.UserId}

	if strings.EqualFold(target, "all") {
		ips, _ := p.getIPList()
		if len(ips) == 0 {
			return "The IP list is empty. " + uploadHelp(p.isSysAdmin(args.UserId))
		}
		if pr := p.getProgress(); pr != nil {
			return p.alreadyRunningText()
		}
		req.Kind = runManual
		p.background(func(ctx context.Context) { p.runWholeList(ctx, req) })
		return fmt.Sprintf("Looking up %d IPs on Shodan (should take %s). The changes will be posted in this channel.",
			len(ips), estimate(len(ips), len(p.getConfiguration().apiKeys())))
	}

	ip, reason := CheckPublicIP(target)
	if reason != "" {
		return fmt.Sprintf("`%s` can't be looked up: %s.", md(target), reason)
	}
	req.Kind = runSingle
	p.background(func(ctx context.Context) { p.lookupSingle(ctx, ip, req) })
	return fmt.Sprintf("Looking up `%s` on Shodan...", ip)
}

func (p *Plugin) scanCommand(args *model.CommandArgs, rest []string) string {
	if len(rest) == 0 {
		return "Usage: `/shodan scan <ip>` or `/shodan scan all` - an active scan asks Shodan to scan now and uses 1 scan credit per IP. `/shodan lookup` is free."
	}
	if len(p.getConfiguration().apiKeys()) == 0 {
		return "No Shodan API key is configured. A system admin can add keys in **System Console → Plugins → Shodan Monitor**."
	}
	if !p.canPostResults(args.ChannelId) {
		return publicChannelText
	}
	req := runRequest{Kind: runActive, ChannelID: args.ChannelId, UserID: args.UserId}

	if strings.EqualFold(rest[0], "all") {
		if len(rest) < 2 || !strings.EqualFold(rest[1], "confirm") {
			p.background(func(ctx context.Context) { p.scanCheck(ctx, args.UserId, args.ChannelId) })
			return "Checking how many scan credits your keys have..."
		}
		if pr := p.getProgress(); pr != nil {
			return p.alreadyRunningText()
		}
		p.background(func(ctx context.Context) { p.activeScan(ctx, nil, true, req) })
		return "Submitting an active scan of the whole list to Shodan..."
	}

	ip, reason := CheckPublicIP(rest[0])
	if reason != "" {
		return fmt.Sprintf("`%s` can't be scanned: %s.", md(rest[0]), reason)
	}
	p.background(func(ctx context.Context) { p.activeScan(ctx, []string{ip}, false, req) })
	return fmt.Sprintf("Submitting an active scan of `%s` to Shodan (1 scan credit)...", ip)
}

// estimate is a rough duration for n lookups at ~1 request/second per key.
func estimate(n, keys int) string {
	if keys < 1 {
		keys = 1
	}
	d := time.Duration(float64(n)*shodanMinInterval.Seconds()/float64(keys)) * time.Second
	if d < time.Minute {
		return "under a minute"
	}
	return fmt.Sprintf("about %s", plural(int(d.Minutes()+0.5), "minute", "minutes"))
}

func (p *Plugin) accessCommand(rest []string) string {
	if len(rest) == 0 {
		return "Usage: `/shodan access add @user`, `/shodan access remove @user` or `/shodan access list`"
	}
	switch strings.ToLower(rest[0]) {
	case "list":
		return p.accessListText()
	case "add", "remove", "delete", "rm":
		if len(rest) != 2 {
			return fmt.Sprintf("Usage: `/shodan access %s @user`", strings.ToLower(rest[0]))
		}
		name := strings.TrimPrefix(rest[1], "@")
		u, appErr := p.API.GetUserByUsername(name)
		if appErr != nil {
			return fmt.Sprintf("No user named `@%s`.", md(name))
		}
		if strings.EqualFold(rest[0], "add") {
			if u.IsBot {
				return "Bots can't be given access."
			}
			if p.isSysAdmin(u.Id) {
				return fmt.Sprintf("@%s is a system admin and already has access.", u.Username)
			}
			changed, err := p.setAccess(u.Id, true)
			if err != nil {
				return "Could not save: " + err.Error()
			}
			if !changed {
				return fmt.Sprintf("@%s already has access.", u.Username)
			}
			return fmt.Sprintf("@%s can now use Shodan Monitor.", u.Username)
		}
		changed, err := p.setAccess(u.Id, false)
		if err != nil {
			return "Could not save: " + err.Error()
		}
		if !changed {
			return fmt.Sprintf("@%s was not on the access list.", u.Username)
		}
		return fmt.Sprintf("Removed @%s's access.", u.Username)
	}
	return "Usage: `/shodan access add @user`, `/shodan access remove @user` or `/shodan access list`"
}

// accessListText lists the users added manually. System admins are not listed.
func (p *Plugin) accessListText() string {
	ids, err := p.getAccessList()
	if err != nil {
		return "Could not read the access list: " + err.Error()
	}
	var users []*model.User
	var lines []string
	for _, id := range ids {
		if p.isSysAdmin(id) {
			continue
		}
		u, appErr := p.API.GetUser(id)
		if appErr != nil {
			lines = append(lines, fmt.Sprintf("- unknown user `%s`", id))
			continue
		}
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	for _, u := range users {
		line := "- @" + u.Username
		if full := strings.TrimSpace(u.FirstName + " " + u.LastName); full != "" {
			line += " - " + md(full)
		}
		if u.DeleteAt != 0 {
			line += " _(deactivated)_"
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return "No users have been given access. System admins always have access. Add someone with `/shodan access add @user`."
	}
	return fmt.Sprintf("**Users given access (%d):**\n%s\n\n_System admins always have access and are not listed. Remove a user with `/shodan access remove @user`._",
		len(lines), strings.Join(lines, "\n"))
}

func (p *Plugin) statusText() string {
	cfg := p.getConfiguration()
	var b strings.Builder
	b.WriteString("#### " + productName() + " - status\n")

	ips, _ := p.getIPList()
	fmt.Fprintf(&b, "- **IP list:** %s\n", plural(len(ips), "IP", "IPs"))

	if ch := p.getReportChannel(); ch == "" {
		b.WriteString("- **Report channel:** not set - run `/shodan report-here` in the channel that should get the reports\n")
	} else if c, appErr := p.API.GetChannel(ch); appErr == nil {
		name := c.DisplayName
		if name == "" {
			name = c.Name
		}
		fmt.Fprintf(&b, "- **Report channel:** %s\n", md(name))
	} else {
		b.WriteString("- **Report channel:** the saved channel no longer exists - run `/shodan report-here` again\n")
	}

	if cfg.AllowPublicChannels {
		b.WriteString("- **Public channels:** allowed (results posted there are visible to every member of the team)\n")
	} else {
		b.WriteString("- **Public channels:** not allowed - results are only posted in private channels and direct messages\n")
	}
	if cfg.LookupIntervalDays > 0 {
		fmt.Fprintf(&b, "- **Lookup interval:** every %s\n", plural(cfg.LookupIntervalDays, "day", "days"))
	} else {
		b.WriteString("- **Lookup interval:** scheduled lookups are off (interval 0)\n")
	}
	fmt.Fprintf(&b, "- **Last scheduled run:** %s\n", fmtMillis(p.getLastScheduled()))
	if why, due := p.scheduleState(); why != "" {
		fmt.Fprintf(&b, "- **Next scheduled run:** paused - %s\n", why)
	} else if due {
		b.WriteString("- **Next scheduled run:** due now (starts within a minute)\n")
	} else {
		fmt.Fprintf(&b, "- **Next scheduled run:** %s\n", fmtTime(p.nextScheduled()))
	}
	if pr := p.getProgress(); pr != nil {
		by := ""
		if pr.By != "" {
			by = " by @" + pr.By
		}
		fmt.Fprintf(&b, "- **Running now:** %s - %s, %d/%d (started %s%s)\n", pr.Kind, pr.Phase, pr.Done, pr.Total, fmtMillis(pr.Started), by)
	}
	access := "system admins"
	if p.getConfiguration().TeamAdminAccess {
		if team := p.reportTeam(); team != nil {
			access += ", team admins of " + md(team.DisplayName)
		} else {
			access += " (team admin access is on, but there is no report channel in a team yet)"
		}
	}
	if ids, err := p.getAccessList(); err == nil {
		n := 0
		for _, id := range ids {
			if !p.isSysAdmin(id) {
				n++
			}
		}
		access += fmt.Sprintf(", and %s added manually", plural(n, "user", "users"))
	}
	fmt.Fprintf(&b, "- **Access:** %s\n", access)

	keys := cfg.apiKeys()
	if len(keys) == 0 {
		b.WriteString("- **API keys:** none configured - add them in System Console → Plugins → Shodan Monitor\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **API keys (%d):**\n", len(keys))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := p.newShodan(keys)
	for _, k := range keys {
		info, err := client.APIInfo(ctx, k)
		if err != nil {
			fmt.Fprintf(&b, "  - `%s` - error: %s\n", maskKey(k), md(err.Error()))
			continue
		}
		fmt.Fprintf(&b, "  - `%s` - plan %s · %d query credits · %d scan credits\n", maskKey(k), md(orDash(info.Plan)), info.QueryCredits, info.ScanCredits)
	}
	return b.String()
}
