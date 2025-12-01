package store

import "strings"

// RemoteURIFromNames extracts the remote URI from a qault remote name entry.
// It expects names that start with "qault" and "remote" (case-insensitive) and
// returns the trimmed last element when present.
func RemoteURIFromNames(names []string) (string, bool) {
	if len(names) < 3 {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(names[0]), "qault") {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(names[1]), "remote") {
		return "", false
	}
	uri := strings.TrimSpace(names[len(names)-1])
	if uri == "" {
		return "", false
	}
	return uri, true
}
