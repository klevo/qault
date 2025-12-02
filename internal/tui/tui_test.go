package tui

import (
	"reflect"
	"testing"

	"github.com/charmbracelet/bubbles/list"
	"qault/internal/store"
)

func TestModelRemoteDefinitions(t *testing.T) {
	delegate := newItemDelegate(newItemDelegateKeyMap())
	l := list.New([]list.Item{}, delegate, 0, 0)

	items := []list.Item{
		item{names: []string{"qault", "remote", "https://example.com/one.git", "alice"}, secret: "pw"},
		item{names: []string{"qault", "remote", "https://example.com/two.git"}},
		item{names: []string{"qault", "remote", "https://example.com/one.git"}},                 // duplicate, no override
		item{names: []string{"other", "remote", "https://example.com/three.git"}, secret: "pw"}, // ignored
	}

	l.SetItems(items)
	m := model{list: l}

	got := m.remoteDefinitions()
	want := []store.RemoteDefinition{
		{URI: "https://example.com/one.git", Username: "alice", Password: "pw"},
		{URI: "https://example.com/two.git"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remoteDefinitions() = %v, want %v", got, want)
	}
}
