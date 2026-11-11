package main

import (
	"strings"
)

// configuration holds the admin-configurable settings declared in plugin.json.
//
// Do not read the fields directly; go through Plugin.getConfiguration so access
// is synchronised with configuration reloads.
type configuration struct {
	// ShodanAPIKeys holds one Shodan API key per line.
	ShodanAPIKeys string

	// LookupIntervalDays is how often the whole list is looked up. 0 = scheduled lookups off.
	LookupIntervalDays int

	// TeamAdminAccess gives team admins of the report channel's team access.
	TeamAdminAccess bool

	// AllowPublicChannels lets results be posted in public channels too.
	AllowPublicChannels bool

	// The "IPList" setting is a custom System Console component; the list itself
	// lives in the KV store, never in the configuration.
}

// Clone returns a copy of the configuration.
func (c *configuration) Clone() *configuration {
	clone := *c
	return &clone
}

// apiKeys returns the configured keys: one per line (commas and spaces also
// separate keys), blank lines and lines starting with # ignored, duplicates dropped.
func (c *configuration) apiKeys() []string {
	var keys []string
	seen := map[string]bool{}
	for line := range strings.SplitSeq(c.ShodanAPIKeys, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, k := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' }) {
			if k != "" && !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	return keys
}

// maskKey shows only the last 4 characters of an API key.
func maskKey(key string) string {
	if len(key) <= 4 {
		return "..." + strings.Repeat("*", len(key))
	}
	return "..." + key[len(key)-4:]
}
