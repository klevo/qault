package tui

import (
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"

	iotp "qault/internal/otp"
)

type item struct {
	name      string
	secret    string
	otp       bool
	otpConfig *iotp.Config
	updatedAt time.Time
	createdAt time.Time
	path      string
}

type deleteItemRequestedMsg struct {
	index int
	item  item
}

type editItemRequestedMsg struct {
	index int
	item  item
}

const timeDisplayLayout = "2006-01-02 15:04"

func (i item) Title() string {
	lines := strings.FieldsFunc(i.name, func(r rune) bool { return r == '\n' })
	return strings.Join(lines, " › ")
}
func (i item) Description() string {
	desc := i.updatedAt.Format(timeDisplayLayout)
	if i.otp {
		desc += " +OTP"
	}
	return desc
}
func (i item) FilterValue() string {
	filter := strings.ReplaceAll(i.name, "\n", "   ")
	return filter
}

func newItemDelegate(keys *itemDelegateKeyMap) list.DefaultDelegate {
	d := list.NewDefaultDelegate()
	// d.ShowDescription = false

	d.UpdateFunc = func(msg tea.Msg, m *list.Model) tea.Cmd {
		var (
			title    string
			secret   string
			selected item
		)

		if i, ok := m.SelectedItem().(item); ok {
			title = i.Title()
			secret = i.secret
			selected = i
			keys.copyOTP.SetEnabled(selected.otpConfig != nil)
		} else {
			return nil
		}

		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch {
			case key.Matches(msg, keys.choose):
				index := m.GlobalIndex()
				return func() tea.Msg {
					return editItemRequestedMsg{
						index: index,
						item:  selected,
					}
				}

			case key.Matches(msg, keys.copy):
				if err := clipboard.WriteAll(secret); err != nil {
					return m.NewStatusMessage(errorStyle.Render("Failed to copy"))
				}
				return m.NewStatusMessage(statusMessageStyle("Copied " + title))

			case key.Matches(msg, keys.copyOTP):
				if selected.otpConfig == nil {
					return m.NewStatusMessage(errorStyle.Render("OTP not configured"))
				}

				code, err := iotp.GenerateCode(*selected.otpConfig, time.Now().UTC())
				if err != nil {
					return m.NewStatusMessage(errorStyle.Render("Failed to generate OTP"))
				}

				if err := clipboard.WriteAll(code); err != nil {
					return m.NewStatusMessage(errorStyle.Render("Failed to copy OTP"))
				}

				return m.NewStatusMessage(statusMessageStyle("Copied OTP " + title))

			case key.Matches(msg, keys.remove):
				index := m.Index()
				return func() tea.Msg {
					return deleteItemRequestedMsg{
						index: index,
						item:  selected,
					}
				}
			}
		}

		return nil
	}

	help := []key.Binding{keys.choose, keys.copy, keys.copyOTP, keys.remove}

	d.ShortHelpFunc = func() []key.Binding {
		return help
	}

	d.FullHelpFunc = func() [][]key.Binding {
		return [][]key.Binding{help}
	}

	return d
}

type itemDelegateKeyMap struct {
	choose  key.Binding
	copy    key.Binding
	copyOTP key.Binding
	remove  key.Binding
}

// Additional short help entries. This satisfies the help.KeyMap interface and
// is entirely optional.
func (d itemDelegateKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{
		d.choose,
		d.copy,
		d.copyOTP,
		d.remove,
	}
}

// Additional full help entries. This satisfies the help.KeyMap interface and
// is entirely optional.
func (d itemDelegateKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{
			d.choose,
			d.copy,
			d.copyOTP,
			d.remove,
		},
	}
}

func newItemDelegateKeyMap() *itemDelegateKeyMap {
	copyOTP := key.NewBinding(
		key.WithKeys("o"),
		key.WithHelp("o", "copy OTP"),
	)
	copyOTP.SetEnabled(false)

	return &itemDelegateKeyMap{
		choose: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "edit"),
		),
		copy: key.NewBinding(
			key.WithKeys("y"),
			key.WithHelp("y", "copy secret"),
		),
		copyOTP: copyOTP,
		remove: key.NewBinding(
			key.WithKeys("x"),
			key.WithHelp("x", "delete"),
		),
	}
}
