package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	appStyle = lipgloss.NewStyle().Padding(0, 1)

	headerStyle = lipgloss.NewStyle().MarginBottom(1)

	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#00567C")).
			Padding(0, 1)

	confirmationMessageStyle = lipgloss.NewStyle().
					Bold(true).
					Foreground(lipgloss.AdaptiveColor{Light: "#B58900", Dark: "#B58900"})

	statusMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Light: "#04B575", Dark: "#04B575"}).
				Render

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("1"))
)

const PASSWORD = "dev"

type listKeyMap struct {
	toggleSpinner  key.Binding
	toggleHelpMenu key.Binding
	insertItem     key.Binding
}

func newListKeyMap() *listKeyMap {
	return &listKeyMap{
		toggleSpinner: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "toggle spinner"),
		),
		toggleHelpMenu: key.NewBinding(
			key.WithKeys("H"),
			key.WithHelp("H", "toggle help"),
		),
		insertItem: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "add item"),
		),
	}
}

type itemFormKeyMap struct {
	save      key.Binding
	cancel    key.Binding
	nextField key.Binding
}

func newItemFormKeyMap() *itemFormKeyMap {
	return &itemFormKeyMap{
		save: key.NewBinding(
			key.WithKeys("ctrl+s"),
			key.WithHelp("ctrl+s", "save item"),
		),
		cancel: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "cancel"),
		),
		nextField: key.NewBinding(
			key.WithKeys("tab", "shift+tab"),
			key.WithHelp("tab", "switch field"),
		),
	}
}

func (k itemFormKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.save, k.cancel, k.nextField}
}

func (k itemFormKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.save, k.cancel, k.nextField}}
}

type model struct {
	screen          screenState
	list            list.Model
	masterPassInput textinput.Model
	addItemFocus    string
	addItemName     textarea.Model
	addItemSecret   textarea.Model
	addItemError    string
	formMode        formMode
	editIndex       int
	formKeys        *itemFormKeyMap
	formHelp        help.Model
	pendingDelete   *deleteItemRequestedMsg
	itemGenerator   *randomItemGenerator
	keys            *listKeyMap
	delegateKeys    *itemDelegateKeyMap
}

type screenState string

const (
	screenUnlock   screenState = "unlock"
	screenList     screenState = "list"
	screenItemForm screenState = "itemForm"
)

type formMode string

const (
	formModeAdd  formMode = "add"
	formModeEdit formMode = "edit"
)

func newModel() model {
	var (
		itemGenerator   randomItemGenerator
		delegateKeys    = newItemDelegateKeyMap()
		listKeys        = newListKeyMap()
		formKeys        = newItemFormKeyMap()
		masterPassInput = textinput.New()
		addItemName     = textarea.New()
		addItemSecret   = textarea.New()
		formHelp        = help.New()
	)

	// Setup master pass input
	masterPassInput.Prompt = "Master password: "
	masterPassInput.Focus()
	masterPassInput.EchoMode = textinput.EchoPassword
	masterPassInput.EchoCharacter = '•'

	// Setup add item inputs
	addItemName.SetHeight(3)
	addItemSecret.SetHeight(5)

	// Setup list
	delegate := newItemDelegate(delegateKeys)
	secretsList := list.New([]list.Item{}, delegate, 0, 0)
	secretsList.SetShowTitle(false)
	secretsList.SetShowStatusBar(false)
	secretsList.AdditionalFullHelpKeys = func() []key.Binding {
		return []key.Binding{
			listKeys.toggleSpinner,
			listKeys.toggleHelpMenu,
			listKeys.insertItem,
		}
	}

	// Keep escape available for list actions (like clearing filters) without quitting the app.
	secretsList.KeyMap.Quit.SetKeys("q")

	return model{
		screen:          screenUnlock,
		list:            secretsList,
		masterPassInput: masterPassInput,
		addItemName:     addItemName,
		addItemSecret:   addItemSecret,
		formMode:        formModeAdd,
		editIndex:       -1,
		formKeys:        formKeys,
		formHelp:        formHelp,
		keys:            listKeys,
		delegateKeys:    delegateKeys,
		itemGenerator:   &itemGenerator,
	}
}

func (m model) PopulateList() (tea.Model, tea.Cmd) {
	const numItems = 24
	items := make([]list.Item, numItems)
	for i := 0; i < numItems; i++ {
		items[i] = m.itemGenerator.next()
	}
	return m, m.list.SetItems(items)
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, textarea.Blink)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h, v := appStyle.GetFrameSize()
		availableHeight := msg.Height - v - m.headerHeight() - m.confirmationHeight()
		availableWidth := msg.Width - h
		if availableHeight < 0 {
			availableHeight = 0
		}
		m.list.SetSize(msg.Width-h, availableHeight)
		if availableWidth > 0 {
			m.addItemName.SetWidth(availableWidth)
			m.addItemSecret.SetWidth(availableWidth)
		}

	case tea.KeyMsg:
		if msg.String() == "ctrl+q" {
			return m, tea.Quit
		}
	}

	switch m.screen {
	case screenUnlock:
		newModel, cmds := m.LockUpdate(msg, cmds)
		return newModel, tea.Batch(cmds...)
	case screenItemForm:
		newModel, cmds := m.ItemFormUpdate(msg, cmds)
		return newModel, tea.Batch(cmds...)
	default:
		newModel, cmds := m.ListUpdate(msg, cmds)
		return newModel, tea.Batch(cmds...)
	}
}

func (m model) LockUpdate(msg tea.Msg, cmds []tea.Cmd) (tea.Model, []tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyEnter {
			if m.masterPassInput.Value() == PASSWORD {
				m.screen = screenList
				newModel, cmd := m.PopulateList()
				return newModel, append(cmds, cmd)
			} else {
				m.masterPassInput.Err = fmt.Errorf("Incorrect password")
				return m, nil
			}
		}
	}

	inputModel, cmd := m.masterPassInput.Update(msg)
	m.masterPassInput = inputModel

	return m, append(cmds, cmd)
}

func (m model) startItemForm(mode formMode, existing item, index int) (tea.Model, []tea.Cmd) {
	m.screen = screenItemForm
	m.formMode = mode
	m.editIndex = index
	m.pendingDelete = nil
	m.addItemFocus = "name"
	m.addItemError = ""
	m.addItemSecret.Blur()

	if mode == formModeEdit {
		m.addItemName.SetValue(existing.name)
		m.addItemSecret.SetValue(existing.secret)
	} else {
		m.addItemName.Reset()
		m.addItemSecret.Reset()
	}

	cmd := m.addItemName.Focus()
	return m, []tea.Cmd{cmd}
}

func (m model) ItemFormUpdate(msg tea.Msg, cmds []tea.Cmd) (tea.Model, []tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.formKeys.save):
			m.delegateKeys.remove.SetEnabled(true)
			name := strings.TrimSpace(m.addItemName.Value())
			secret := strings.TrimSpace(m.addItemSecret.Value())

			if name == "" {
				m.addItemError = "Name cannot be empty"
				return m, cmds
			}
			if secret == "" {
				m.addItemError = "Secret cannot be empty"
				return m, cmds
			}

			var (
				statusCmd tea.Cmd
				actionCmd tea.Cmd
			)

			if m.formMode == formModeEdit {
				edited := item{
					name:      m.addItemName.Value(),
					secret:    m.addItemSecret.Value(),
					otp:       m.currentEditingItem().otp,
					updatedAt: time.Now(),
				}
				actionCmd = m.list.SetItem(m.editIndex, edited)
				statusCmd = m.list.NewStatusMessage(statusMessageStyle("Updated " + edited.Title()))
			} else {
				newItem := item{
					name:      m.addItemName.Value(),
					secret:    m.addItemSecret.Value(),
					otp:       false,
					updatedAt: time.Now(),
				}
				actionCmd = m.list.InsertItem(0, newItem)
				statusCmd = m.list.NewStatusMessage(statusMessageStyle("Added " + newItem.Title()))
			}

			m.screen = screenList
			m.formMode = formModeAdd
			m.editIndex = -1
			m.addItemName.Blur()
			m.addItemSecret.Blur()
			m.addItemError = ""
			return m, append(cmds, actionCmd, statusCmd)
		case key.Matches(msg, m.formKeys.cancel):
			m.screen = screenList
			m.formMode = formModeAdd
			m.editIndex = -1
			m.addItemName.Blur()
			m.addItemSecret.Blur()
			m.addItemError = ""
			return m, cmds
		case key.Matches(msg, m.formKeys.nextField):
			if m.addItemFocus == "name" {
				m.addItemFocus = "secret"
				m.addItemName.Blur()
				cmd := m.addItemSecret.Focus()
				return m, append(cmds, cmd)
			}
			m.addItemFocus = "name"
			m.addItemSecret.Blur()
			cmd := m.addItemName.Focus()
			return m, append(cmds, cmd)
		}
	}

	var cmd tea.Cmd
	if m.addItemFocus == "secret" {
		m.addItemSecret, cmd = m.addItemSecret.Update(msg)
	} else {
		m.addItemName, cmd = m.addItemName.Update(msg)
	}

	return m, append(cmds, cmd)
}

func (m model) currentEditingItem() item {
	if m.editIndex < 0 {
		return item{}
	}
	if items := m.list.Items(); m.editIndex < len(items) {
		if it, ok := items[m.editIndex].(item); ok {
			return it
		}
	}
	return item{}
}

func (m model) ListUpdate(msg tea.Msg, cmds []tea.Cmd) (tea.Model, []tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.pendingDelete != nil {
			switch msg.String() {
			case "enter":
				p := m.pendingDelete
				m.list.RemoveItem(p.index)
				if len(m.list.Items()) == 0 {
					m.delegateKeys.remove.SetEnabled(false)
				}
				m.pendingDelete = nil
				statusCmd := m.list.NewStatusMessage(statusMessageStyle("Deleted " + p.item.Title()))
				return m, append(cmds, statusCmd)
			case "esc":
				m.pendingDelete = nil
				statusCmd := m.list.NewStatusMessage(statusMessageStyle("Canceled deletion"))
				return m, append(cmds, statusCmd)
			}
		}

		// Don't match any of the keys below if we're actively filtering.
		if m.list.FilterState() == list.Filtering {
			break
		}

		switch {
		case key.Matches(msg, m.keys.toggleSpinner):
			cmd := m.list.ToggleSpinner()
			return m, append(cmds, cmd)

		case key.Matches(msg, m.keys.toggleHelpMenu):
			m.list.SetShowHelp(!m.list.ShowHelp())
			return m, cmds

		case key.Matches(msg, m.keys.insertItem):
			return m.startItemForm(formModeAdd, item{}, -1)
		}
	}

	if msg, ok := msg.(deleteItemRequestedMsg); ok {
		m.pendingDelete = &msg
		return m, cmds
	}

	if msg, ok := msg.(editItemRequestedMsg); ok {
		// Clear pending delete prompt if editing.
		m.pendingDelete = nil
		return m.startItemForm(formModeEdit, msg.item, msg.index)
	}

	// This will also call our delegate's update function.
	listModel, cmd := m.list.Update(msg)
	m.list = listModel

	return m, append(cmds, cmd)
}

// The main view, which just calls the appropriate sub-view
func (m model) View() string {
	header := m.HeaderView()

	var body string
	switch m.screen {
	case screenUnlock:
		parts := []string{m.masterPassInput.View()}
		if err := m.masterPassInput.Err; err != nil {
			parts = append(parts, errorStyle.Render(err.Error()))
		}
		body = lipgloss.JoinVertical(lipgloss.Left, parts...)
	case screenItemForm:
		body = m.ItemFormView()
	default:
		body = m.list.View()
		confirmMsg := ""
		if m.pendingDelete != nil {
			confirmMsg = fmt.Sprintf("Delete '%s'? enter to confirm, esc to cancel", m.pendingDelete.item.Title())
		}
		if confirmMsg == "" {
			confirmMsg = " "
		}
		confirm := confirmationMessageStyle.Render(confirmMsg)
		body = lipgloss.JoinVertical(lipgloss.Left, body, confirm)
	}

	return appStyle.Render(lipgloss.JoinVertical(lipgloss.Left, header, body))
}

func (m model) ItemFormView() string {
	parts := []string{
		"Name",
		m.addItemName.View(),
		"",
		"Secret",
		m.addItemSecret.View(),
	}
	if m.addItemError != "" {
		parts = append(parts, "", errorStyle.Render(m.addItemError))
	}

	body := lipgloss.JoinVertical(lipgloss.Left, parts...)
	body = lipgloss.NewStyle().Padding(0, 2).Render(body)

	helpView := m.formHelp.View(m.formKeys)
	return lipgloss.JoinVertical(lipgloss.Left, body, "", helpView)
}

func (m model) HeaderView() string {
	status := "unlocked"
	switch m.screen {
	case screenUnlock:
		status = "locked"
	case screenItemForm:
		if m.formMode == formModeEdit {
			status = "Edit item"
		} else {
			status = "New item"
		}
	}

	return headerStyle.Render(fmt.Sprintf("%s %s", titleStyle.Render("qault"), status))
}

func (m model) headerHeight() int {
	return lipgloss.Height(m.HeaderView())
}

func (m model) confirmationHeight() int {
	return lipgloss.Height(confirmationMessageStyle.Render(" "))
}

func Run() error {
	_, err := tea.NewProgram(newModel(), tea.WithAltScreen()).Run()
	return err
}
