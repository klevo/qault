package tui

import (
	"reflect"
	"testing"

	"github.com/charmbracelet/bubbles/list"
)

func TestRemoteURIFromNames(t *testing.T) {
	tests := []struct {
		name    string
		parts   []string
		wantURI string
		wantOK  bool
	}{
		{"basic", []string{"qault", "remote", "git@github.com:example/repo.git"}, "git@github.com:example/repo.git", true},
		{"extra parts", []string{"qault", "remote", "folder", "ssh://example.com/repo"}, "ssh://example.com/repo", true},
		{"case-insensitive", []string{"QaUlT", "ReMoTe", "https://example.com/r.git"}, "https://example.com/r.git", true},
		{"trim whitespace", []string{" qault ", " remote ", "  https://example.com/r.git  "}, "https://example.com/r.git", true},
		{"too short", []string{"qault", "remote"}, "", false},
		{"missing prefix", []string{"other", "remote", "git@host/repo"}, "", false},
		{"missing remote marker", []string{"qault", "something", "git@host/repo"}, "", false},
		{"empty uri", []string{"qault", "remote", "   "}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURI, ok := remoteURIFromNames(tt.parts)
			if ok != tt.wantOK || gotURI != tt.wantURI {
				t.Fatalf("remoteURIFromNames(%v) = (%q, %v), want (%q, %v)", tt.parts, gotURI, ok, tt.wantURI, tt.wantOK)
			}
		})
	}
}

func TestModelRemoteURIs(t *testing.T) {
	delegate := newItemDelegate(newItemDelegateKeyMap())
	l := list.New([]list.Item{}, delegate, 0, 0)

	items := []list.Item{
		item{names: []string{"qault", "remote", "git@github.com:one.git"}},
		item{names: []string{"qault", "remote", "git@github.com:two.git"}},
		item{names: []string{"qault", "remote", "git@github.com:one.git"}},   // duplicate
		item{names: []string{"other", "remote", "git@github.com:three.git"}}, // ignored
	}

	l.SetItems(items)
	m := model{list: l}

	got := m.remoteURIs()
	want := []string{"git@github.com:one.git", "git@github.com:two.git"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remoteURIs() = %v, want %v", got, want)
	}
}
