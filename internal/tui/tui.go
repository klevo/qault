package tui

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"

	"qault/internal/auth"
	ifs "qault/internal/fs"
	"qault/internal/gitrepo"
	iotp "qault/internal/otp"
	"qault/internal/store"
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
	toggleHelpMenu key.Binding
	insertItem     key.Binding
}

func newListKeyMap() *listKeyMap {
	return &listKeyMap{
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
	generate  key.Binding
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
		generate: key.NewBinding(
			key.WithKeys("ctrl+g"),
			key.WithHelp("ctrl+g", "generate password"),
		),
	}
}

func (k itemFormKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.save, k.cancel, k.nextField, k.generate}
}

func (k itemFormKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.save, k.cancel, k.nextField, k.generate}}
}

type model struct {
	screen          screenState
	list            list.Model
	masterPassInput textinput.Model
	addItemFocus    string
	addItemName     textarea.Model
	addItemSecret   textarea.Model
	addItemOTP      textinput.Model
	addItemError    string
	statusMessage   string
	statusIsError   bool
	formMode        formMode
	editIndex       int
	formKeys        *itemFormKeyMap
	formHelp        help.Model
	pendingDelete   *deleteItemRequestedMsg
	keys            *listKeyMap
	delegateKeys    *itemDelegateKeyMap
	dataDir         string
	rootKey         []byte
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

const (
	addItemFocusName   = "name"
	addItemFocusSecret = "secret"
	addItemFocusOTP    = "otp"
)

type statusMessageMsg struct {
	text    string
	isError bool
}

func newModel() model {
	var (
		delegateKeys    = newItemDelegateKeyMap()
		listKeys        = newListKeyMap()
		formKeys        = newItemFormKeyMap()
		masterPassInput = textinput.New()
		addItemName     = textarea.New()
		addItemSecret   = textarea.New()
		addItemOTP      = textinput.New()
		formHelp        = help.New()
	)

	// Setup master pass input
	masterPassInput.Prompt = "Master password: "
	masterPassInput.Focus()
	masterPassInput.EchoMode = textinput.EchoPassword
	masterPassInput.EchoCharacter = '•'

	// Setup add item inputs
	addItemName.SetHeight(4)
	addItemSecret.SetHeight(5)
	addItemOTP.Placeholder = "/path/to/qr-code.png"
	faintLineNumbers := lipgloss.NewStyle().Faint(true)
	addItemName.FocusedStyle.LineNumber = addItemName.FocusedStyle.LineNumber.Faint(true)
	addItemName.FocusedStyle.CursorLineNumber = addItemName.FocusedStyle.CursorLineNumber.Faint(true)
	addItemName.BlurredStyle.LineNumber = addItemName.BlurredStyle.LineNumber.Faint(true)
	addItemName.BlurredStyle.CursorLineNumber = addItemName.BlurredStyle.CursorLineNumber.Faint(true)
	addItemSecret.FocusedStyle.LineNumber = addItemSecret.FocusedStyle.LineNumber.Inherit(faintLineNumbers)
	addItemSecret.FocusedStyle.CursorLineNumber = addItemSecret.FocusedStyle.CursorLineNumber.Inherit(faintLineNumbers)
	addItemSecret.BlurredStyle.LineNumber = addItemSecret.BlurredStyle.LineNumber.Inherit(faintLineNumbers)
	addItemSecret.BlurredStyle.CursorLineNumber = addItemSecret.BlurredStyle.CursorLineNumber.Inherit(faintLineNumbers)

	// Setup list
	delegate := newItemDelegate(delegateKeys)
	secretsList := list.New([]list.Item{}, delegate, 0, 0)
	secretsList.SetShowTitle(false)
	secretsList.SetShowStatusBar(false)
	secretsList.KeyMap.PrevPage.SetKeys("left", "h", "pgup", "b")
	secretsList.KeyMap.NextPage.SetKeys("right", "l", "pgdown", "f")
	secretsList.AdditionalFullHelpKeys = func() []key.Binding {
		return []key.Binding{
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
		addItemOTP:      addItemOTP,
		formMode:        formModeAdd,
		editIndex:       -1,
		formKeys:        formKeys,
		formHelp:        formHelp,
		keys:            listKeys,
		delegateKeys:    delegateKeys,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, textarea.Blink)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case statusMessageMsg:
		m.statusMessage = msg.text
		m.statusIsError = msg.isError
		return m, tea.Batch(cmds...)
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
			m.addItemOTP.Width = availableWidth
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
			m.masterPassInput.Err = nil

			dir, rootKey, items, err := unlockVault(m.masterPassInput.Value())
			if err != nil {
				m.masterPassInput.Err = err
				return m, nil
			}

			m.dataDir = dir
			m.rootKey = rootKey
			m.screen = screenList
			m.delegateKeys.remove.SetEnabled(len(items) > 0)
			cmd := m.list.SetItems(items)
			return m, append(cmds, cmd)
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
	m.addItemFocus = addItemFocusName
	m.addItemError = ""
	m.addItemSecret.Blur()
	m.addItemOTP.Blur()

	if mode == formModeEdit {
		m.addItemName.SetValue(existing.name)
		m.addItemSecret.SetValue(existing.secret)
		m.addItemOTP.SetValue("")
	} else {
		m.addItemName.Reset()
		m.addItemSecret.Reset()
		m.addItemOTP.Reset()
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
			otpPath := strings.TrimSpace(m.addItemOTP.Value())

			var (
				statusCmd tea.Cmd
				reloadCmd tea.Cmd
				err       error
			)

			if m.formMode == formModeEdit {
				statusCmd, reloadCmd, err = m.saveEdit(name, secret, otpPath)
			} else {
				statusCmd, reloadCmd, err = m.saveNew(name, secret, otpPath)
			}
			if err != nil {
				m.addItemError = err.Error()
				return m, cmds
			}

			m.screen = screenList
			m.formMode = formModeAdd
			m.editIndex = -1
			m.addItemName.Blur()
			m.addItemSecret.Blur()
			m.addItemOTP.Blur()
			m.addItemError = ""
			return m, append(cmds, statusCmd, reloadCmd)
		case key.Matches(msg, m.formKeys.cancel):
			m.screen = screenList
			m.formMode = formModeAdd
			m.editIndex = -1
			m.addItemName.Blur()
			m.addItemSecret.Blur()
			m.addItemOTP.Blur()
			m.addItemError = ""
			return m, cmds
		case key.Matches(msg, m.formKeys.generate):
			pw, err := generatePassword(10)
			if err != nil {
				m.addItemError = err.Error()
				return m, cmds
			}
			lines := strings.Split(m.addItemSecret.Value(), "\n")
			if len(lines) == 0 {
				lines = []string{""}
			}
			lines[0] = pw
			m.addItemSecret.SetValue(strings.Join(lines, "\n"))
			return m, cmds
		case key.Matches(msg, m.formKeys.nextField):
			switch m.addItemFocus {
			case addItemFocusName:
				m.addItemFocus = addItemFocusSecret
				m.addItemName.Blur()
				cmd := m.addItemSecret.Focus()
				return m, append(cmds, cmd)
			case addItemFocusSecret:
				m.addItemFocus = addItemFocusOTP
				m.addItemSecret.Blur()
				cmd := m.addItemOTP.Focus()
				return m, append(cmds, cmd)
			}
			m.addItemFocus = addItemFocusName
			m.addItemOTP.Blur()
			cmd := m.addItemName.Focus()
			return m, append(cmds, cmd)
		}
	}

	var cmd tea.Cmd
	switch m.addItemFocus {
	case addItemFocusSecret:
		m.addItemSecret, cmd = m.addItemSecret.Update(msg)
	case addItemFocusOTP:
		m.addItemOTP, cmd = m.addItemOTP.Update(msg)
	default:
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
				if err := m.deleteSecret(p.item.path); err != nil {
					statusCmd := newStatusMessage(err.Error(), true)
					m.pendingDelete = nil
					return m, append(cmds, statusCmd)
				}

				reloadCmd, err := m.reloadList()
				if err != nil {
					statusCmd := newStatusMessage(err.Error(), true)
					m.pendingDelete = nil
					return m, append(cmds, statusCmd)
				}

				m.pendingDelete = nil
				statusCmd := newStatusMessage("Deleted "+p.item.Title(), false)
				return m, append(cmds, statusCmd, reloadCmd)
			case "esc":
				m.pendingDelete = nil
				statusCmd := newStatusMessage("Canceled deletion", false)
				return m, append(cmds, statusCmd)
			}
		}

		// Don't match any of the keys below if we're actively filtering.
		if m.list.FilterState() == list.Filtering {
			break
		}

		switch {
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
		message := confirmationMessageStyle.Render(" ")
		if m.pendingDelete != nil {
			message = confirmationMessageStyle.Render(fmt.Sprintf("Delete '%s'? enter to confirm, esc to cancel", m.pendingDelete.item.Title()))
		} else if m.statusMessage != "" {
			if m.statusIsError {
				message = errorStyle.Render(m.statusMessage)
			} else {
				message = statusMessageStyle(m.statusMessage)
			}
		}
		body = lipgloss.JoinVertical(lipgloss.Left, body, message)
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
		"",
		"OTP setup QR code",
		m.addItemOTP.View(),
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

func unlockVault(password string) (string, []byte, []list.Item, error) {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return "", nil, nil, err
	}

	if err := auth.EnsureInitialized(dir); err != nil {
		return "", nil, nil, err
	}

	rootKey, err := auth.UnlockRootKey(dir, password)
	if err != nil {
		return "", nil, nil, err
	}

	records, err := auth.LoadSecretRecords(dir, rootKey)
	if err != nil {
		return "", nil, nil, err
	}

	return dir, rootKey, toListItems(records), nil
}

func toListItems(secrets []auth.SecretRecord) []list.Item {
	items := make([]item, 0, len(secrets))
	for _, record := range secrets {
		items = append(items, item{
			name:      strings.Join(record.Secret.Name, "\n"),
			names:     record.Secret.Name,
			secret:    record.Secret.Secret,
			otp:       record.Secret.OTP != nil,
			otpConfig: record.Secret.OTP,
			updatedAt: record.Secret.UpdatedAt,
			createdAt: record.Secret.CreatedAt,
			path:      record.Path,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].createdAt.After(items[j].createdAt)
	})

	listItems := make([]list.Item, len(items))
	for i := range items {
		listItems[i] = items[i]
	}
	return listItems
}

func parseNameInput(name string) ([]string, error) {
	parts := strings.Split(name, "\n")
	var names []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		names = append(names, trimmed)
	}
	if len(names) == 0 {
		return nil, errors.New("Name cannot be empty")
	}
	return names, nil
}

func normalizeNames(names []string) string {
	return strings.Join(normalizeNameParts(names), "\x00")
}

func normalizeNameParts(names []string) []string {
	normalized := make([]string, len(names))
	for i, name := range names {
		normalized[i] = strings.ToLower(strings.TrimSpace(name))
	}
	return normalized
}

func (m *model) reloadList() (tea.Cmd, error) {
	records, err := m.loadRecords()
	if err != nil {
		return nil, err
	}
	items := toListItems(records)
	m.delegateKeys.remove.SetEnabled(len(items) > 0)
	return m.list.SetItems(items), nil
}

func (m *model) saveNew(nameInput, secretValue, otpPath string) (tea.Cmd, tea.Cmd, error) {
	names, err := parseNameInput(nameInput)
	if err != nil {
		return nil, nil, err
	}

	records, err := m.loadRecords()
	if err != nil {
		return nil, nil, err
	}
	for _, record := range records {
		if normalizeNames(record.Secret.Name) == normalizeNames(names) {
			return nil, nil, errors.New("Name already exists")
		}
	}

	otpConfig, err := parseOTPConfig(otpPath)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	secret := store.Secret{
		Name:      names,
		Secret:    secretValue,
		OTP:       otpConfig,
		CreatedAt: now,
		UpdatedAt: now,
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, nil, err
	}
	filename := filepath.Join(m.dataDir, id.String())

	enc, err := store.EncryptSecret(m.rootKey, secret)
	if err != nil {
		return nil, nil, err
	}
	if err := store.WriteFile(filename, enc); err != nil {
		return nil, nil, err
	}

	if err := gitrepo.CommitFiles(m.dataDir, "secret added", filename); err != nil {
		return nil, nil, err
	}

	reloadCmd, err := m.reloadList()
	if err != nil {
		return nil, nil, err
	}
	status := newStatusMessage("Added "+strings.Join(names, " / "), false)
	return status, reloadCmd, nil
}

func (m *model) saveEdit(nameInput, secretValue, otpPath string) (tea.Cmd, tea.Cmd, error) {
	names, err := parseNameInput(nameInput)
	if err != nil {
		return nil, nil, err
	}

	current := m.currentEditingItem()
	if current.path == "" {
		return nil, nil, errors.New("Unable to locate selected secret")
	}

	records, err := m.loadRecords()
	if err != nil {
		return nil, nil, err
	}
	for _, record := range records {
		if record.Path == current.path {
			continue
		}
		if normalizeNames(record.Secret.Name) == normalizeNames(names) {
			return nil, nil, errors.New("Name already exists")
		}
	}

	secret, err := readSecret(current.path, m.rootKey)
	if err != nil {
		return nil, nil, err
	}

	otpConfig, err := parseOTPConfig(otpPath)
	if err != nil {
		return nil, nil, err
	}

	secret.Name = names
	secret.Secret = secretValue
	secret.UpdatedAt = time.Now().UTC()
	if otpConfig != nil {
		secret.OTP = otpConfig
	}

	enc, err := store.EncryptSecret(m.rootKey, secret)
	if err != nil {
		return nil, nil, err
	}
	if err := store.WriteFile(current.path, enc); err != nil {
		return nil, nil, err
	}

	if err := gitrepo.CommitFiles(m.dataDir, "secret updated", current.path); err != nil {
		return nil, nil, err
	}

	reloadCmd, err := m.reloadList()
	if err != nil {
		return nil, nil, err
	}

	status := newStatusMessage("Updated "+strings.Join(names, " / "), false)
	return status, reloadCmd, nil
}

func parseOTPConfig(path string) (*iotp.Config, error) {
	if path == "" {
		return nil, nil
	}

	cfg, err := iotp.ConfigFromImagePath(path)
	if err != nil {
		return nil, fmt.Errorf("otp: %w", err)
	}

	return &cfg, nil
}

func newStatusMessage(text string, isError bool) tea.Cmd {
	return func() tea.Msg {
		return statusMessageMsg{text: text, isError: isError}
	}
}

func generatePassword(length int) (string, error) {
	if length < 4 {
		return "", errors.New("password length too short")
	}

	charsets := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
		"!@#$%^&*()-_=+[]{}:;,.?/",
	}
	allChars := strings.Join(charsets, "")

	var password []byte
	for _, set := range charsets {
		c, err := randomChar(set)
		if err != nil {
			return "", err
		}
		password = append(password, c)
	}

	for len(password) < length {
		c, err := randomChar(allChars)
		if err != nil {
			return "", err
		}
		password = append(password, c)
	}

	if err := shuffle(password); err != nil {
		return "", err
	}

	return string(password), nil
}

func randomChar(from string) (byte, error) {
	n, err := randInt(len(from))
	if err != nil {
		return 0, err
	}
	return from[n], nil
}

func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		n, err := randInt(i + 1)
		if err != nil {
			return err
		}
		b[i], b[n] = b[n], b[i]
	}
	return nil
}

func randInt(max int) (int, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(nBig.Int64()), nil
}

func (m *model) deleteSecret(path string) error {
	if path == "" {
		return errors.New("No secret selected")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return gitrepo.CommitFiles(m.dataDir, "secret deleted", path)
}

func readSecret(path string, rootKey []byte) (store.Secret, error) {
	data, err := store.ReadFile(path)
	if err != nil {
		return store.Secret{}, err
	}
	return store.DecryptSecret(rootKey, data)
}

func (m *model) loadRecords() ([]auth.SecretRecord, error) {
	return auth.LoadSecretRecords(m.dataDir, m.rootKey)
}
