package tui

import (
	"reflect"
	"testing"

	"github.com/charmbracelet/bubbles/list"
)

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
