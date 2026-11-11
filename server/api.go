package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/mattermost/mattermost/server/public/plugin"
)

// ServeHTTP serves the API used by the "IP list" box in the System Console.
// Every route is for system admins only.
func (p *Plugin) ServeHTTP(_ *plugin.Context, w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
		http.Error(w, "not authorized", http.StatusUnauthorized)
		return
	}
	if !p.isSysAdmin(userID) {
		http.Error(w, "only system admins can do this", http.StatusForbidden)
		return
	}

	switch {
	case r.URL.Path == "/api/v1/iplist" && r.Method == http.MethodGet:
		ips, err := p.getIPList()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		prev, _ := p.getPreviousList()
		writeJSON(w, map[string]any{
			"count":         len(ips),
			"last_upload":   p.getUploadSummary(),
			"previous_size": len(prev),
		})

	case r.URL.Path == "/api/v1/iplist" && r.Method == http.MethodPost:
		data, err := io.ReadAll(io.LimitReader(r.Body, maxUploadBytes+1))
		if err != nil {
			http.Error(w, "could not read the upload", http.StatusBadRequest)
			return
		}
		if len(data) > maxUploadBytes {
			http.Error(w, "file too big (max 5 MB)", http.StatusRequestEntityTooLarge)
			return
		}
		if !utf8.Valid(data) {
			http.Error(w, "the file is not plain text (UTF-8)", http.StatusBadRequest)
			return
		}
		sum, prev, err := p.replaceList(string(data), p.username(userID), "System Console")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"summary": sum, "previous_size": len(prev)})

	case r.URL.Path == "/api/v1/iplist/download" && r.Method == http.MethodGet:
		ips, err := p.getIPList()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeText(w, "shodan-ip-list.txt", ips)

	case r.URL.Path == "/api/v1/iplist/previous" && r.Method == http.MethodGet:
		prev, err := p.getPreviousList()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeText(w, "previous-ip-list.txt", prev)

	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeText(w http.ResponseWriter, name string, lines []string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	body := strings.Join(lines, "\n")
	if body != "" {
		body += "\n"
	}
	_, _ = w.Write([]byte(body))
}
