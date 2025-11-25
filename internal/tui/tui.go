package tui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	icrypto "qault/internal/crypto"
	ifs "qault/internal/fs"
	"qault/internal/store"
)

type lockFile struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

var errIncorrectPassword = errors.New("Incorrect master password")

type uiState int

const (
	stateUnlock uiState = iota
	stateList
)

type unlockResultMsg struct {
	secrets []store.Secret
	err     error
}

type model struct {
	dir      string
	state    uiState
	password textinput.Model
	list     list.Model
	secrets  []store.Secret
	errMsg   string
	loading  bool
	width    int
	height   int
}

var (
	titleStyle = lipgloss.NewStyle().Bold(true).MarginBottom(1)
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("160"))
	helpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

func Run(out, errOut io.Writer) error {
	_ = errOut

	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return err
	}

	hasLock, err := ifs.HasLock(dir)
	if err != nil {
		return err
	}
	if !hasLock {
		return errors.New("Vault is not initialized")
	}

	m := newModel(dir)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithOutput(out))
	_, err = p.Run()
	return err
}

func newModel(dir string) model {
	input := textinput.New()
	input.Placeholder = "Master password"
	input.Prompt = "Master password: "
	input.EchoMode = textinput.EchoPassword
	input.Focus()

	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false

	l := list.New(nil, delegate, 0, 0)
	l.SetFilteringEnabled(true)
	l.Title = "Secrets"
	l.Styles.Title = lipgloss.NewStyle().MarginLeft(1).Bold(true)
	l.Styles.PaginationStyle = helpStyle.MarginLeft(1)
	l.Styles.HelpStyle = helpStyle.MarginLeft(1)

	return model{
		dir:      dir,
		state:    stateUnlock,
		password: input,
		list:     l,
	}
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.state == stateList {
			m.list.SetSize(msg.Width, msg.Height)
		}
	case unlockResultMsg:
		m.loading = false
		if msg.err != nil {
			m.errMsg = msg.err.Error()
			m.password.SetValue("")
			return m, nil
		}
		m.errMsg = ""
		m.state = stateList
		m.secrets = msg.secrets
		m.list.SetItems(toItems(msg.secrets))
		if m.width > 0 && m.height > 0 {
			m.list.SetSize(m.width, m.height)
		}
		return m, nil
	}

	switch m.state {
	case stateUnlock:
		return m.updateUnlock(msg)
	case stateList:
		return m.updateList(msg)
	default:
		return m, nil
	}
}

func (m model) View() string {
	switch m.state {
	case stateUnlock:
		var b strings.Builder
		fmt.Fprintln(&b, titleStyle.Render("Unlock qault"))
		fmt.Fprintln(&b, m.password.View())
		if m.loading {
			fmt.Fprintln(&b)
			fmt.Fprintln(&b, helpStyle.Render("Unlocking..."))
		} else {
			fmt.Fprintln(&b)
			fmt.Fprintln(&b, helpStyle.Render("Press Enter to unlock, Esc to quit"))
		}
		if m.errMsg != "" {
			fmt.Fprintln(&b)
			fmt.Fprintln(&b, errorStyle.Render(m.errMsg))
		}
		return b.String()
	case stateList:
		return m.list.View()
	default:
		return ""
	}
}

func (m model) updateUnlock(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "enter":
			if m.loading {
				return m, nil
			}
			m.loading = true
			cmd := unlockCmd(m.dir, m.password.Value())
			return m, cmd
		}
	}

	var cmd tea.Cmd
	m.password, cmd = m.password.Update(msg)
	return m, cmd
}

func (m model) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func unlockCmd(dir, password string) tea.Cmd {
	return func() tea.Msg {
		secrets, err := unlockAndLoad(dir, password)
		return unlockResultMsg{secrets: secrets, err: err}
	}
}

func unlockAndLoad(dir, password string) ([]store.Secret, error) {
	rootKey, err := deriveRootKey(dir, password)
	if err != nil {
		return nil, err
	}

	secrets, err := loadSecrets(dir, rootKey)
	if err != nil {
		return nil, err
	}

	sort.Slice(secrets, func(i, j int) bool {
		return namesLessFold(secrets[i].Name, secrets[j].Name)
	})

	return secrets, nil
}

func deriveRootKey(dir, password string) ([]byte, error) {
	data, err := store.ReadFile(ifs.LockPath(dir))
	if err != nil {
		return nil, err
	}

	var lock lockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(lock.Salt)
	if err != nil {
		return nil, err
	}

	rootKey, err := icrypto.DeriveRootKey(password, salt)
	if err != nil {
		return nil, err
	}

	env := icrypto.Envelope{
		Nonce:      lock.Nonce,
		Ciphertext: lock.Ciphertext,
	}

	if _, err := icrypto.DecryptWithKey(rootKey, env); err != nil {
		return nil, errIncorrectPassword
	}

	return rootKey, nil
}

func loadSecrets(dir string, rootKey []byte) ([]store.Secret, error) {
	files, err := ifs.ListSecretFiles(dir)
	if err != nil {
		return nil, err
	}

	var secrets []store.Secret
	for _, path := range files {
		data, err := store.ReadFile(path)
		if err != nil {
			return nil, err
		}

		secret, err := store.DecryptSecret(rootKey, data)
		if err != nil {
			return nil, fmt.Errorf("Failed to decrypt secret %s", filepath.Base(path))
		}

		secrets = append(secrets, secret)
	}

	return secrets, nil
}

func toItems(secrets []store.Secret) []list.Item {
	items := make([]list.Item, 0, len(secrets))
	for _, secret := range secrets {
		items = append(items, secretItem{
			name:   formatName(secret.Name),
			hasOTP: secret.OTP != nil,
		})
	}
	return items
}

type secretItem struct {
	name   string
	hasOTP bool
}

func (s secretItem) Title() string {
	if s.hasOTP {
		return s.name + " (otp)"
	}
	return s.name
}

func (s secretItem) Description() string {
	return ""
}

func (s secretItem) FilterValue() string {
	return s.name
}

func formatName(names []string) string {
	if len(names) == 0 {
		return ""
	}

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, formatNamePart(name))
	}

	return strings.Join(parts, " ")
}

func formatNamePart(name string) string {
	if hasWhitespace(name) {
		return strconv.Quote(name)
	}
	return name
}

func hasWhitespace(value string) bool {
	for _, r := range value {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func namesLessFold(a, b []string) bool {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := 0; i < minLen; i++ {
		lhs := strings.ToLower(a[i])
		rhs := strings.ToLower(b[i])
		if lhs == rhs {
			continue
		}
		return lhs < rhs
	}

	return len(a) < len(b)
}
