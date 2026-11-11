package main

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

// productName is how the plugin names itself in posts and in results.json,
// e.g. "Shodan Monitor v1.0.0". The version comes from plugin.json.
func productName() string {
	if v := pluginVersion(); v != "" {
		return "Shodan Monitor v" + v
	}
	return "Shodan Monitor"
}

// pluginVersion is the "version" field of plugin.json (via the generated manifest.go).
func pluginVersion() string {
	if manifest == nil {
		return ""
	}
	return manifest.Version
}

// maxPostRunes keeps posts under Mattermost's default 16383-character limit.
const maxPostRunes = 15000

type namedFile struct {
	Name string
	Data []byte
}

// postMessage creates a bot post in the channel with the files attached.
func (p *Plugin) postMessage(channelID, msg string, files ...namedFile) {
	post := &model.Post{UserId: p.botUserID, ChannelId: channelID}
	for _, f := range files {
		info, appErr := p.API.UploadFile(f.Data, channelID, f.Name)
		if appErr != nil {
			p.API.LogError("failed to upload a file", "name", f.Name, "err", appErr.Error())
			msg += fmt.Sprintf("\n\n**Warning:** Could not attach `%s` (%s).", f.Name, appErr.Message)
			continue
		}
		post.FileIds = append(post.FileIds, info.Id)
	}
	post.Message = msg
	if _, appErr := p.API.CreatePost(post); appErr != nil {
		p.API.LogError("failed to create a post", "channel_id", channelID, "err", appErr.Error())
	}
}

// ephemeral shows a message only the user can see.
func (p *Plugin) ephemeral(userID, channelID, msg string) {
	if userID == "" || channelID == "" {
		return
	}
	p.API.SendEphemeralPost(userID, &model.Post{UserId: p.botUserID, ChannelId: channelID, Message: msg})
}

// dm sends a bot direct message to the user.
func (p *Plugin) dm(userID, msg string, files ...namedFile) {
	ch, appErr := p.API.GetDirectChannel(userID, p.botUserID)
	if appErr != nil {
		p.API.LogError("failed to open a direct channel", "user_id", userID, "err", appErr.Error())
		return
	}
	p.postMessage(ch.Id, msg, files...)
}

func (p *Plugin) isSysAdmin(userID string) bool {
	return p.API.HasPermissionTo(userID, model.PermissionManageSystem)
}

// canUse: system admins; team admins of the report channel's team when the
// "Team admins have access" setting is on; users added with /shodan access add.
//
// Team admin access is limited to the report team on purpose: any user who may
// create teams becomes team admin of the team they create, so "admin of any
// team" would let every user give themselves access.
func (p *Plugin) canUse(userID string) bool {
	if p.isSysAdmin(userID) || p.isReportTeamAdmin(userID) {
		return true
	}
	ids, err := p.getAccessList()
	if err != nil {
		return false
	}
	return slices.Contains(ids, userID)
}

// isReportTeamAdmin: the setting is on and the user is a team admin of the
// team that holds the report channel.
func (p *Plugin) isReportTeamAdmin(userID string) bool {
	if !p.getConfiguration().TeamAdminAccess {
		return false
	}
	team := p.reportTeam()
	if team == nil {
		return false
	}
	return p.API.HasPermissionToTeam(userID, team.Id, model.PermissionManageTeam)
}

// reportTeam is the team of the report channel (nil when not set, or when the
// report channel is a direct/group message).
func (p *Plugin) reportTeam() *model.Team {
	chID := p.getReportChannel()
	if chID == "" {
		return nil
	}
	ch, appErr := p.API.GetChannel(chID)
	if appErr != nil || ch.TeamId == "" {
		return nil
	}
	team, appErr := p.API.GetTeam(ch.TeamId)
	if appErr != nil {
		return nil
	}
	return team
}

// isPublicChannel: results are never posted in public channels, so users
// without Shodan Monitor access can't read them.
func (p *Plugin) isPublicChannel(channelID string) bool {
	ch, appErr := p.API.GetChannel(channelID)
	if appErr != nil {
		return true // unknown: treat as public, i.e. don't post
	}
	return ch.Type == model.ChannelTypeOpen
}

const publicChannelText = "Results are only posted in private channels and direct messages, so users without " +
	"Shodan Monitor access can't see them. Run this in a private channel or in a direct message with @shodan-monitor."

func (p *Plugin) username(userID string) string {
	if userID == "" {
		return ""
	}
	u, appErr := p.API.GetUser(userID)
	if appErr != nil {
		return userID
	}
	return u.Username
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func fmtMillis(ms int64) string {
	if ms == 0 {
		return "never"
	}
	return fmtTime(time.UnixMilli(ms))
}

func isoTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05-07:00")
}

var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"<", `\<`, ">", `\>`, "|", `\|`, "#", `\#`, "~", `\~`,
)

// md escapes text that comes from Shodan (titles, banners, names) so it can't
// add links or formatting to a post, or notify people: "@" gets a zero-width
// space after it, so "@channel", "@all" or "@user" never become mentions.
func md(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
	return strings.ReplaceAll(mdEscaper.Replace(s), "@", "@\u200b")
}

// cutRunes shortens a post at a line boundary so it stays under limit runes.
func cutRunes(s string, limit int) (string, bool) {
	r := []rune(s)
	if len(r) <= limit {
		return s, false
	}
	cut := string(r[:limit])
	if i := strings.LastIndex(cut, "\n"); i > 0 {
		cut = cut[:i]
	}
	return cut, true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, ", ")
}
