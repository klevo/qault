package store

import (
	"sort"
	"strings"
)

type RemoteDefinition struct {
	URI      string
	Username string
	Password string
}

// RemoteURIFromNames extracts the remote URI from a qault remote name entry.
// It expects names that start with "qault" and "remote" (case-insensitive) and
// returns the trimmed URI when present. Remote definitions may optionally
// include a username as the final name element.
func RemoteURIFromNames(names []string) (string, bool) {
	uri, _, ok := RemoteDetailsFromNames(names)
	return uri, ok
}

// RemoteDetailsFromNames extracts the remote URI and optional username from a
// qault remote name entry. It expects names that start with "qault" and
// "remote" (case-insensitive). When a username is present, it is expected to be
// the final element, with the URI as the element preceding it.
func RemoteDetailsFromNames(names []string) (string, string, bool) {
	if len(names) < 3 {
		return "", "", false
	}
	if !strings.EqualFold(strings.TrimSpace(names[0]), "qault") {
		return "", "", false
	}
	if !strings.EqualFold(strings.TrimSpace(names[1]), "remote") {
		return "", "", false
	}

	var uri, username string
	if len(names) >= 4 {
		uri = strings.TrimSpace(names[len(names)-2])
		username = strings.TrimSpace(names[len(names)-1])
		if username == "" {
			return "", "", false
		}
	} else {
		uri = strings.TrimSpace(names[len(names)-1])
	}
	if uri == "" {
		return "", "", false
	}
	return uri, username, true
}

// RemoteDefinitionsFromSecrets collects remote definitions from the provided
// secrets, deduplicating by URI. When multiple entries exist for the same URI,
// an entry containing credentials takes precedence.
func RemoteDefinitionsFromSecrets(secrets []Secret) []RemoteDefinition {
	remotes := map[string]RemoteDefinition{}
	for _, s := range secrets {
		uri, username, ok := RemoteDetailsFromNames(s.Name)
		if !ok {
			continue
		}

		def := RemoteDefinition{URI: uri}
		if username != "" && strings.TrimSpace(s.Secret) != "" {
			def.Username = username
			def.Password = s.Secret
		}

		existing, exists := remotes[uri]
		if !exists || def.Username != "" {
			remotes[uri] = def
		} else if existing.URI == "" {
			remotes[uri] = def
		}
	}

	if len(remotes) == 0 {
		return nil
	}

	out := make([]RemoteDefinition, 0, len(remotes))
	keys := make([]string, 0, len(remotes))
	for uri := range remotes {
		keys = append(keys, uri)
	}
	sort.Strings(keys)

	for _, uri := range keys {
		out = append(out, remotes[uri])
	}
	return out
}
