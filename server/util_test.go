package main

import (
	"strings"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
)

func TestMdNeutralisesMentionsAndMarkup(t *testing.T) {
	in := "@channel @all hi @here [click](http://x) ![img](http://y) `code` <b> | ~town-square #h *b* _i_"
	out := md(in)

	// Mentions get a zero-width space after "@", so they never notify anyone.
	for _, m := range []string{"@channel", "@all", "@here"} {
		if strings.Contains(out, m) {
			t.Errorf("md(%q) still contains the mention %q: %q", in, m, out)
		}
	}
	if !strings.Contains(out, "@\u200bchannel") {
		t.Errorf("md did not neutralise @channel: %q", out)
	}
	// Markdown characters are backslash-escaped, so no links, images, code or channel links.
	for _, want := range []string{`\[click\]`, `!\[img\]`, "\\`code\\`", `\<b\>`, `\|`, `\~town-square`, `\#h`, `\*b\*`, `\_i\_`} {
		if !strings.Contains(out, want) {
			t.Errorf("md(%q) = %q, want it to contain %q", in, out, want)
		}
	}
	if strings.Contains(md("line1\nline2\r"), "\n") {
		t.Error("md kept a newline")
	}
}

func TestCanPostIn(t *testing.T) {
	off := &configuration{}
	on := &configuration{AllowPublicChannels: true}
	cases := []struct {
		chType model.ChannelType
		cfg    *configuration
		want   bool
	}{
		{model.ChannelTypePrivate, off, true},
		{model.ChannelTypeDirect, off, true},
		{model.ChannelTypeGroup, off, true},
		{model.ChannelTypeOpen, off, false},
		{model.ChannelTypeOpen, on, true},
		{model.ChannelTypePrivate, on, true},
	}
	for _, c := range cases {
		if got := canPostIn(&model.Channel{Type: c.chType}, c.cfg); got != c.want {
			t.Errorf("canPostIn(type %q, allowPublic=%v) = %v, want %v", c.chType, c.cfg.AllowPublicChannels, got, c.want)
		}
	}
}
