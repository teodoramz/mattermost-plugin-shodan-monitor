package main

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

const maxUploadBytes = 5 << 20

// rejectedInline is how many rejected lines are listed in a reply before the
// rest goes into an attached file.
const rejectedInline = 30

// MessageHasBeenPosted handles .txt files sent to the bot in a direct message:
// they replace the IP list.
func (p *Plugin) MessageHasBeenPosted(_ *plugin.Context, post *model.Post) {
	if post.UserId == "" || post.UserId == p.botUserID || post.Type != "" {
		return
	}
	ch, appErr := p.API.GetChannel(post.ChannelId)
	if appErr != nil || ch.Type != model.ChannelTypeDirect || ch.Name != model.GetDMNameFromIds(post.UserId, p.botUserID) {
		return
	}
	reply := func(msg string, files ...namedFile) { p.postMessage(post.ChannelId, msg, files...) }

	if !p.canUse(post.UserId) {
		reply("You don't have access to Shodan Monitor. Ask a system admin to run `/shodan access add @" + p.username(post.UserId) + "`.")
		return
	}
	if len(post.FileIds) == 0 {
		reply("Send me a `.txt` file with one IP address per line to **replace** the monitored IP list. Run `/shodan help` for everything else.")
		return
	}

	var info *model.FileInfo
	for _, id := range post.FileIds {
		fi, ferr := p.API.GetFileInfo(id)
		if ferr != nil {
			continue
		}
		if strings.EqualFold(fi.Extension, "txt") || strings.HasPrefix(fi.MimeType, "text/") {
			info = fi
			break
		}
	}
	if info == nil {
		reply("Please send a plain-text `.txt` file with one IP address per line. The list was not changed.")
		return
	}
	if info.Size > maxUploadBytes {
		reply(fmt.Sprintf("`%s` is too big (max %d MB). The list was not changed.", md(info.Name), maxUploadBytes>>20))
		return
	}
	data, appErr := p.API.GetFile(info.Id)
	if appErr != nil {
		reply("Could not read the file: " + appErr.Message)
		return
	}
	if !utf8.Valid(data) {
		reply("That file is not plain text (UTF-8). The list was not changed.")
		return
	}

	sum, prev, err := p.replaceList(string(data), p.username(post.UserId), "direct message")
	if err != nil {
		reply("Could not replace the list: " + err.Error())
		return
	}
	msg, files := uploadReply(sum, prev)
	reply(msg, files...)
}

// uploadReply renders the result of a list replacement.
func uploadReply(sum *UploadSummary, prev []string) (string, []namedFile) {
	var b strings.Builder
	var files []namedFile
	if !sum.Applied {
		b.WriteString("" + sum.Message + "\n")
	} else {
		fmt.Fprintf(&b, "**IP list replaced - %s now.** %d added · %d removed · %d unchanged",
			plural(sum.Total, "IP", "IPs"), sum.Added, sum.Removed, sum.Unchanged)
		if sum.Duplicates > 0 {
			fmt.Fprintf(&b, " · %s skipped", plural(sum.Duplicates, "duplicate line", "duplicate lines"))
		}
		b.WriteString("\n")
	}
	if sum.RejectedCount > 0 {
		fmt.Fprintf(&b, "\n**Rejected lines (%d):**\n", sum.RejectedCount)
		for i, r := range sum.Rejected {
			if i == rejectedInline {
				fmt.Fprintf(&b, "- ... %d more in the attached `rejected-lines.txt`\n", sum.RejectedCount-rejectedInline)
				break
			}
			fmt.Fprintf(&b, "- line %d: `%s` - %s\n", r.Line, strings.ReplaceAll(r.Value, "`", "'"), r.Reason)
		}
		if sum.RejectedCount > rejectedInline {
			var rb strings.Builder
			for _, r := range sum.Rejected {
				fmt.Fprintf(&rb, "line %d\t%s\t%s\n", r.Line, r.Value, r.Reason)
			}
			if sum.RejectedCount > len(sum.Rejected) {
				fmt.Fprintf(&rb, "... and %d more\n", sum.RejectedCount-len(sum.Rejected))
			}
			files = append(files, namedFile{Name: "rejected-lines.txt", Data: []byte(rb.String())})
		}
	}
	if sum.Applied && len(prev) > 0 {
		b.WriteString("\nThe previous list is attached as `previous-ip-list.txt` - send it back to me to undo.")
		files = append(files, namedFile{Name: "previous-ip-list.txt", Data: []byte(strings.Join(prev, "\n") + "\n")})
	}
	if sum.Applied {
		b.WriteString("\nRun `/shodan lookup all` to fetch the data for the list now.")
	}
	return b.String(), files
}
