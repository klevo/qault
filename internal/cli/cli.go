package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/term"

	"qault/internal/agent"
	icrypto "qault/internal/crypto"
	ifs "qault/internal/fs"
	"qault/internal/otp"
	"qault/internal/store"
)

type exitError struct {
	code int
	msg  string
	err  error
}

func (e exitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.msg
}

func userError(msg string) exitError {
	return exitError{code: 1, msg: msg}
}

func fatalError(err error) exitError {
	return exitError{code: 1, err: err}
}

type lockFile struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

var errWrongMasterKey = errors.New("Incorrect master password")

type Prompter interface {
	MasterPassword() (string, error)
	NewMasterPassword() (string, error)
	SecretValue() (string, error)
}

type CLI struct {
	Out      io.Writer
	Err      io.Writer
	Prompter Prompter
}

var timeNow = time.Now

func NewDefault() *CLI {
	return &CLI{
		Out:      os.Stdout,
		Err:      os.Stderr,
		Prompter: NewTerminalPrompter(os.Stderr),
	}
}

func (c *CLI) Run(args []string) int {
	if err := c.dispatch(args); err != nil {
		return c.handleError(err)
	}
	return 0
}

func (c *CLI) handleError(err error) int {
	if e, ok := err.(exitError); ok {
		switch {
		case e.msg != "":
			fmt.Fprintln(c.Err, e.msg)
		case e.err != nil:
			fmt.Fprintln(c.Err, e.err)
		default:
			fmt.Fprintln(c.Err, err)
		}
		return e.code
	}

	fmt.Fprintln(c.Err, err)
	return 1
}

func (c *CLI) dispatch(args []string) error {
	if len(args) == 0 {
		return c.handleList()
	}

	switch args[0] {
	case "init":
		return c.handleInit()
	case "unlock":
		return c.handleUnlock()
	case "lock":
		return c.handleLock()
	case "agent":
		return c.serveAgent()
	case "add":
		return c.handleAddArgs(args[1:])
	default:
		return c.handleFetchArgs(args)
	}
}

func (c *CLI) handleInit() error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	hasLock, err := ifs.HasLock(dir)
	if err != nil {
		return fatalError(err)
	}
	if hasLock {
		fmt.Fprintln(c.Out, dir)
		return nil
	}

	fmt.Fprintln(c.Err, "Use a strong master secret: 16+ random characters or a 5-7 word diceware-style passphrase to give ~90 bits of entropy; Argon2id slows attackers but offline GPU cracking is still viable with weak passwords.")

	password, err := c.Prompter.NewMasterPassword()
	if err != nil {
		return fatalError(err)
	}

	lockValue, err := icrypto.RandomLockString()
	if err != nil {
		return fatalError(err)
	}

	salt, err := icrypto.GenerateSalt()
	if err != nil {
		return fatalError(err)
	}

	rootKey, err := icrypto.DeriveRootKey(password, salt)
	if err != nil {
		return fatalError(err)
	}

	env, err := icrypto.EncryptWithKey(rootKey, []byte(lockValue))
	if err != nil {
		return fatalError(err)
	}

	lock := lockFile{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      env.Nonce,
		Ciphertext: env.Ciphertext,
	}

	payload, err := json.Marshal(lock)
	if err != nil {
		return fatalError(err)
	}

	if err := store.WriteFile(ifs.LockPath(dir), payload); err != nil {
		return fatalError(err)
	}

	fmt.Fprintln(c.Out, dir)
	return nil
}

func (c *CLI) handleAddArgs(args []string) error {
	if len(args) == 0 {
		return userError("name is required for add")
	}

	name := args[0]
	if len(args) == 1 {
		return c.handleAddSecret(name)
	}

	if len(args) == 3 && args[1] == "-o" {
		return c.handleAddOTP(name, args[2])
	}

	return userError("usage: qault add [NAME] [-o PATH]")
}

func (c *CLI) handleAddSecret(name string) error {
	if name == "" {
		return userError("Name is required")
	}

	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := ensureInitialized(dir); err != nil {
		return fatalError(err)
	}

	rootKey, err := c.getRootKeyWithFallback(dir)
	if err != nil {
		return c.handleMasterKeyError(err)
	}

	if _, _, found, err := findSecretByName(dir, rootKey, name); err != nil {
		return err
	} else if found {
		return exitError{code: 1, msg: "Name already exists"}
	}

	secretValue, err := c.Prompter.SecretValue()
	if err != nil {
		return fatalError(err)
	}

	s := store.Secret{
		Name:      name,
		Secret:    secretValue,
		CreatedAt: timeNow().UTC(),
		UpdatedAt: timeNow().UTC(),
	}

	encrypted, err := store.EncryptSecret(rootKey, s)
	if err != nil {
		return fatalError(err)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return fatalError(err)
	}

	if err := store.WriteFile(filepath.Join(dir, id.String()), encrypted); err != nil {
		return fatalError(err)
	}

	fmt.Fprintf(c.Out, "Secret '%s' added\n", name)
	return nil
}

func (c *CLI) handleAddOTP(name, qrPath string) error {
	if name == "" {
		return userError("Name is required")
	}

	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := ensureInitialized(dir); err != nil {
		return fatalError(err)
	}

	rootKey, err := c.getRootKeyWithFallback(dir)
	if err != nil {
		return c.handleMasterKeyError(err)
	}

	secret, pathForSecret, found, err := findSecretByName(dir, rootKey, name)
	if err != nil {
		return err
	}
	if !found {
		return exitError{code: 1, msg: "Secret not found"}
	}

	file, err := os.Open(qrPath)
	if err != nil {
		return fatalError(err)
	}
	defer file.Close()

	uri, err := otp.DecodeImage(file)
	if err != nil {
		return userError(fmt.Sprintf("Failed to decode QR: %v", err))
	}

	cfg, err := otp.ParseURI(uri)
	if err != nil {
		return userError(err.Error())
	}

	secret.OTP = &cfg
	secret.UpdatedAt = timeNow().UTC()

	encrypted, err := store.EncryptSecret(rootKey, secret)
	if err != nil {
		return fatalError(err)
	}

	if err := store.WriteFile(pathForSecret, encrypted); err != nil {
		return fatalError(err)
	}

	fmt.Fprintf(c.Out, "OTP added to '%s'\n", secret.Name)
	return nil
}

func (c *CLI) handleList() error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := ensureInitialized(dir); err != nil {
		return fatalError(err)
	}

	rootKey, err := c.getRootKeyWithFallback(dir)
	if err != nil {
		return c.handleMasterKeyError(err)
	}

	files, err := ifs.ListSecretFiles(dir)
	if err != nil {
		return fatalError(err)
	}

	var (
		groups  = make(map[string][]string)
		singles []string
	)

	for _, path := range files {
		data, err := store.ReadFile(path)
		if err != nil {
			return fatalError(err)
		}

		secret, err := store.DecryptSecret(rootKey, data)
		if err != nil {
			return userError(fmt.Sprintf("Failed to decrypt secret %s", filepath.Base(path)))
		}

		if group, leaf, ok := splitGroup(secret.Name); ok {
			groups[group] = append(groups[group], leaf)
			continue
		}

		singles = append(singles, secret.Name)
	}

	type listing struct {
		title    string
		children []string
		isGroup  bool
	}

	var listings []listing

	for group, names := range groups {
		sort.Strings(names)
		listings = append(listings, listing{title: group, children: names, isGroup: true})
	}

	sort.Strings(singles)
	for _, name := range singles {
		listings = append(listings, listing{title: name})
	}

	sort.Slice(listings, func(i, j int) bool {
		return listings[i].title < listings[j].title
	})

	for _, item := range listings {
		if item.isGroup {
			fmt.Fprintln(c.Out, item.title)
			for _, child := range item.children {
				fmt.Fprintf(c.Out, "  %s\n", child)
			}
			continue
		}

		fmt.Fprintln(c.Out, item.title)
	}

	return nil
}

func (c *CLI) handleFetchArgs(args []string) error {
	if len(args) == 0 || args[0] == "" {
		return userError("Name is required")
	}

	if len(args) == 2 && args[1] == "-o" {
		return c.handleFetchOTP(args[0])
	}

	if len(args) == 1 {
		return c.handleFetchSecret(args[0])
	}

	return userError("usage: qault init | qault unlock | qault lock | qault add [NAME] [-o PATH] | qault [NAME] [-o]")
}

func (c *CLI) handleFetchSecret(name string) error {
	if name == "" {
		return userError("Name is required")
	}

	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := ensureInitialized(dir); err != nil {
		return fatalError(err)
	}

	rootKey, err := c.getRootKeyWithFallback(dir)
	if err != nil {
		return c.handleMasterKeyError(err)
	}

	secret, _, found, err := findSecretByName(dir, rootKey, name)
	if err != nil {
		return err
	}
	if !found {
		return exitError{code: 1, msg: "Secret not found"}
	}

	if isTerminal(c.Out) {
		fmt.Fprintln(c.Out, secret.Secret)
	} else {
		fmt.Fprint(c.Out, secret.Secret)
	}
	return nil
}

func (c *CLI) handleFetchOTP(name string) error {
	if name == "" {
		return userError("Name is required")
	}

	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := ensureInitialized(dir); err != nil {
		return fatalError(err)
	}

	rootKey, err := c.getRootKeyWithFallback(dir)
	if err != nil {
		return c.handleMasterKeyError(err)
	}

	secret, _, found, err := findSecretByName(dir, rootKey, name)
	if err != nil {
		return err
	}
	if !found {
		return exitError{code: 1, msg: "Secret not found"}
	}
	if secret.OTP == nil {
		return exitError{code: 1, msg: "OTP not configured for this secret"}
	}

	code, err := otp.GenerateCode(*secret.OTP, timeNow().UTC())
	if err != nil {
		return fatalError(err)
	}

	if isTerminal(c.Out) {
		fmt.Fprintln(c.Out, code)
	} else {
		fmt.Fprint(c.Out, code)
	}
	return nil
}

func (c *CLI) handleUnlock() error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := ensureInitialized(dir); err != nil {
		return fatalError(err)
	}

	sock := agent.SocketPath(dir)

	if _, ok, _ := agent.FetchRootKey(sock); ok {
		fmt.Fprintf(c.Out, "Vault is already unlocked\n")
		return nil
	}

	password, err := c.Prompter.MasterPassword()
	if err != nil {
		return fatalError(err)
	}

	rootKey, err := unlockRootKey(dir, password)
	if err != nil {
		return c.handleMasterKeyError(err)
	}

	ttl := 5 * time.Minute

	if os.Getenv("QAULT_INLINE_AGENT") == "1" {
		go func() {
			_ = agent.Serve(rootKey, ttl, sock)
		}()
	} else {
		cmd := exec.Command(os.Args[0], "agent")
		cmd.Env = append(os.Environ(), fmt.Sprintf("QAULT_AGENT_TTL=%d", int64(ttl.Seconds())))
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return fatalError(err)
		}

		go func() {
			defer stdin.Close()
			_ = json.NewEncoder(stdin).Encode(base64.StdEncoding.EncodeToString(rootKey))
		}()

		if err := cmd.Start(); err != nil {
			return fatalError(err)
		}
	}

	if err := waitForAgent(sock, 10, 50*time.Millisecond); err != nil {
		return fatalError(err)
	}

	fmt.Fprintf(c.Out, "Vault unlocked for %s\n", ttl)
	return nil
}

func (c *CLI) handleLock() error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}
	sock := agent.SocketPath(dir)

	if err := agent.Lock(sock); err != nil {
		fmt.Fprintln(c.Err, "Vault is already locked")
		return nil
	}

	_ = waitForAgentStop(sock, 10, 50*time.Millisecond)

	fmt.Fprintln(c.Out, "Vault locked")
	return nil
}

func (c *CLI) serveAgent() error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return err
	}
	sock := agent.SocketPath(dir)

	ttl := 5 * time.Minute
	if v := os.Getenv("QAULT_AGENT_TTL"); v != "" {
		if seconds, err := parseTTLSeconds(v); err == nil {
			ttl = seconds
		}
	}

	decoder := json.NewDecoder(os.Stdin)
	var keyB64 string
	if err := decoder.Decode(&keyB64); err != nil {
		return err
	}

	rootKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return err
	}

	return agent.Serve(rootKey, ttl, sock)
}

func parseTTLSeconds(v string) (time.Duration, error) {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Second, nil
}

func ensureInitialized(dir string) error {
	hasLock, err := ifs.HasLock(dir)
	if err != nil {
		return err
	}

	if !hasLock {
		return errors.New("Vault is not initialized")
	}

	return nil
}

func (c *CLI) getRootKeyWithFallback(dir string) ([]byte, error) {
	sock := agent.SocketPath(dir)
	if key, ok, _ := agent.FetchRootKey(sock); ok {
		return key, nil
	}

	password, err := c.Prompter.MasterPassword()
	if err != nil {
		return nil, err
	}

	rootKey, err := unlockRootKey(dir, password)
	if err != nil {
		return nil, err
	}

	return rootKey, nil
}

func (c *CLI) handleMasterKeyError(err error) error {
	if errors.Is(err, errWrongMasterKey) {
		return exitError{code: 1, msg: "Incorrect master password"}
	}
	return fatalError(err)
}

func findSecretByName(dir string, rootKey []byte, name string) (store.Secret, string, bool, error) {
	files, err := ifs.ListSecretFiles(dir)
	if err != nil {
		return store.Secret{}, "", false, fatalError(err)
	}

	for _, path := range files {
		data, err := store.ReadFile(path)
		if err != nil {
			return store.Secret{}, "", false, fatalError(err)
		}

		secret, err := store.DecryptSecret(rootKey, data)
		if err != nil {
			return store.Secret{}, "", false, userError(fmt.Sprintf("Failed to decrypt secret %s", filepath.Base(path)))
		}

		if strings.EqualFold(secret.Name, name) {
			return secret, path, true, nil
		}
	}

	return store.Secret{}, "", false, nil
}

func splitGroup(full string) (group, name string, ok bool) {
	parts := strings.Split(full, "/")
	if len(parts) < 2 {
		return "", "", false
	}

	name = parts[len(parts)-1]
	group = strings.Join(parts[:len(parts)-1], "/")

	if name == "" || group == "" {
		return "", "", false
	}

	return group, name, true
}

func unlockRootKey(dir, password string) ([]byte, error) {
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
		return nil, errWrongMasterKey
	}

	return rootKey, nil
}

func waitForAgent(sock string, attempts int, delay time.Duration) error {
	for i := 0; i < attempts; i++ {
		if _, ok, _ := agent.FetchRootKey(sock); ok {
			return nil
		}
		time.Sleep(delay)
	}
	return errors.New("agent did not start")
}

func waitForAgentStop(sock string, attempts int, delay time.Duration) error {
	for i := 0; i < attempts; i++ {
		if _, ok, _ := agent.FetchRootKey(sock); !ok {
			return nil
		}
		time.Sleep(delay)
	}
	return errors.New("agent did not stop")
}

type TerminalPrompter struct {
	Err    io.Writer
	inputs []string
}

func NewTerminalPrompter(err io.Writer) *TerminalPrompter {
	if err == nil {
		err = os.Stderr
	}
	var inputs []string
	if v := os.Getenv("QAULT_TEST_INPUTS"); v != "" {
		inputs = strings.Split(v, "\n")
	}

	return &TerminalPrompter{Err: err, inputs: inputs}
}

func (p *TerminalPrompter) MasterPassword() (string, error) {
	return p.promptNonEmpty("Master password: ")
}

func (p *TerminalPrompter) NewMasterPassword() (string, error) {
	for {
		first, err := p.promptNonEmpty("Master password: ")
		if err != nil {
			return "", err
		}

		second, err := p.promptNonEmpty("Confirm master password: ")
		if err != nil {
			return "", err
		}

		if first == second {
			return first, nil
		}

		fmt.Fprintln(p.Err, "passwords do not match")
	}
}

func (p *TerminalPrompter) SecretValue() (string, error) {
	return p.promptNonEmpty("Secret: ")
}

func (p *TerminalPrompter) promptNonEmpty(prompt string) (string, error) {
	for {
		if value, ok := p.popTestInput(); ok {
			if value != "" {
				return value, nil
			}
			fmt.Fprintln(p.Err, "input cannot be empty")
			continue
		}

		value, err := readHiddenInput(p.Err, prompt)
		if err != nil {
			return "", err
		}

		if value != "" {
			return value, nil
		}

		fmt.Fprintln(p.Err, "input cannot be empty")
	}
}

func (p *TerminalPrompter) popTestInput() (string, bool) {
	if len(p.inputs) == 0 {
		return "", false
	}

	value := p.inputs[0]
	p.inputs = p.inputs[1:]
	return value, true
}

func readHiddenInput(errWriter io.Writer, prompt string) (string, error) {
	fmt.Fprint(errWriter, prompt)
	fd := int(os.Stdin.Fd())

	state, _ := term.GetState(fd)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	restore := func() {
		if state != nil {
			_ = term.Restore(fd, state)
		}
	}
	defer func() {
		signal.Stop(sigs)
		restore()
	}()

	go func() {
		if _, ok := <-sigs; ok {
			restore()
			os.Exit(1)
		}
	}()

	input, err := term.ReadPassword(fd)
	fmt.Fprintln(errWriter)
	if err != nil {
		return "", err
	}

	return string(input), nil
}

func isTerminal(w io.Writer) bool {
	type fdWriter interface {
		Fd() uintptr
	}
	if f, ok := w.(fdWriter); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}
