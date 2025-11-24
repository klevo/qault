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
	"unicode"

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

const (
	colorBlue  = "\033[34m"
	colorTeal  = "\033[36m"
	colorFaint = "\033[2m"
	colorReset = "\033[0m"
)

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
	case "rm":
		return c.handleRemoveArgs(args[1:])
	case "mv":
		return c.handleMoveArgs(args[1:])
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
	names, otpPath, err := parseAddArgs(args)
	if err != nil {
		return err
	}
	if otpPath != "" {
		return c.handleAddOTP(names, otpPath)
	}
	return c.handleAddSecret(names)
}

func (c *CLI) handleRemoveArgs(args []string) error {
	names, err := parseNameArgs(args, "Name is required for rm")
	if err != nil {
		return err
	}
	return c.handleRemove(names)
}

func (c *CLI) handleMoveArgs(args []string) error {
	oldNames, newNames, err := parseMoveArgs(args)
	if err != nil {
		return err
	}
	return c.handleMove(oldNames, newNames)
}

func (c *CLI) handleRemove(names []string) error {
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

	_, path, found, err := findSecretByName(dir, rootKey, names)
	if err != nil {
		return err
	}
	if !found {
		return exitError{code: 1, msg: "Secret not found"}
	}

	if err := os.Remove(path); err != nil {
		return fatalError(err)
	}

	return nil
}

func (c *CLI) handleMove(oldNames, newNames []string) error {
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

	secret, path, found, err := findSecretByName(dir, rootKey, oldNames)
	if err != nil {
		return err
	}
	if !found {
		return exitError{code: 1, msg: "Secret not found"}
	}

	if _, _, conflict, err := findSecretByName(dir, rootKey, newNames); err != nil {
		return err
	} else if conflict && !namesEqualFold(oldNames, newNames) {
		return exitError{code: 1, msg: "Name already exists"}
	}

	secret.Name = newNames
	secret.UpdatedAt = timeNow().UTC()

	encrypted, err := store.EncryptSecret(rootKey, secret)
	if err != nil {
		return fatalError(err)
	}

	if err := store.WriteFile(path, encrypted); err != nil {
		return fatalError(err)
	}

	return nil
}

func parseAddArgs(args []string) ([]string, string, error) {
	var names []string
	var otpPath string

	for i := 0; i < len(args); i++ {
		if args[i] == "-o" {
			if otpPath != "" || i == len(args)-1 {
				return nil, "", userError("usage: qault add NAME... [-o PATH]")
			}
			otpPath = args[i+1]
			i++
			continue
		}
		names = append(names, args[i])
	}

	if len(names) == 0 {
		return nil, "", userError("name is required for add")
	}

	return names, otpPath, nil
}

func parseMoveArgs(args []string) ([]string, []string, error) {
	var oldNames []string
	var newNames []string
	sawSeparator := false

	for _, arg := range args {
		if arg == "--to" {
			if sawSeparator {
				return nil, nil, userError("usage: qault mv OLD... --to NEW...")
			}
			sawSeparator = true
			continue
		}

		if sawSeparator {
			newNames = append(newNames, arg)
		} else {
			oldNames = append(oldNames, arg)
		}
	}

	if !sawSeparator || len(oldNames) == 0 || len(newNames) == 0 {
		return nil, nil, userError("usage: qault mv OLD... --to NEW...")
	}

	return oldNames, newNames, nil
}

func (c *CLI) handleAddSecret(names []string) error {
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

	if _, _, found, err := findSecretByName(dir, rootKey, names); err != nil {
		return err
	} else if found {
		return exitError{code: 1, msg: "Name already exists"}
	}

	secretValue, err := c.Prompter.SecretValue()
	if err != nil {
		return fatalError(err)
	}

	s := store.Secret{
		Name:      names,
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

	fmt.Fprintf(c.Out, "Secret '%s' added\n", formatNames(names))
	return nil
}

func (c *CLI) handleAddOTP(names []string, qrPath string) error {
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

	secret, pathForSecret, found, err := findSecretByName(dir, rootKey, names)
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

	fmt.Fprintf(c.Out, "OTP added\n")
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

	var secrets []store.Secret
	for _, path := range files {
		data, err := store.ReadFile(path)
		if err != nil {
			return fatalError(err)
		}

		secret, err := store.DecryptSecret(rootKey, data)
		if err != nil {
			return userError(fmt.Sprintf("Failed to decrypt secret %s", filepath.Base(path)))
		}

		secrets = append(secrets, secret)
	}

	sort.Slice(secrets, func(i, j int) bool {
		return namesLessFold(secrets[i].Name, secrets[j].Name)
	})

	useColor := isTerminal(c.Out)
	for _, secret := range secrets {
		fmt.Fprintln(c.Out, formatListEntry(secret.Name, secret.OTP != nil, useColor))
	}

	return nil
}

func (c *CLI) handleFetchArgs(args []string) error {
	names, wantOTP, err := parseFetchArgs(args)
	if err != nil {
		return err
	}
	if wantOTP {
		return c.handleFetchOTP(names)
	}
	return c.handleFetchSecret(names)
}

func parseFetchArgs(args []string) ([]string, bool, error) {
	var names []string
	wantOTP := false

	for _, arg := range args {
		if arg == "-o" {
			if wantOTP {
				return nil, false, userError("usage: qault init | qault unlock | qault lock | qault add NAME... [-o PATH] | qault rm NAME... | qault mv OLD... --to NEW... | qault NAME... [-o]")
			}
			wantOTP = true
			continue
		}
		names = append(names, arg)
	}

	parsedNames, err := parseNameArgs(names, "Name is required")
	if err != nil {
		return nil, false, err
	}

	return parsedNames, wantOTP, nil
}

func parseNameArgs(args []string, emptyMsg string) ([]string, error) {
	if len(args) == 0 || args[0] == "" {
		return nil, userError(emptyMsg)
	}
	return args, nil
}

func (c *CLI) handleFetchSecret(names []string) error {
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

	secret, _, found, err := findSecretByName(dir, rootKey, names)
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

func (c *CLI) handleFetchOTP(names []string) error {
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

	secret, _, found, err := findSecretByName(dir, rootKey, names)
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

func findSecretByName(dir string, rootKey []byte, names []string) (store.Secret, string, bool, error) {
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

		if namesEqualFold(secret.Name, names) {
			return secret, path, true, nil
		}
	}

	return store.Secret{}, "", false, nil
}

func namesEqualFold(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
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

func formatListEntry(names []string, hasOTP bool, useColor bool) string {
	if len(names) == 0 {
		return ""
	}

	parts := formatNameParts(names)
	if useColor && len(parts) > 1 {
		colors := []string{colorTeal, colorBlue}
		colorIdx := 0
		for i := 0; i < len(parts)-1; i++ {
			parts[i] = colors[colorIdx] + parts[i] + colorReset
			colorIdx = (colorIdx + 1) % len(colors)
		}
	}

	name := strings.Join(parts, " ")
	if !hasOTP {
		return name
	}

	if useColor {
		return name + " " + colorFaint + "-o" + colorReset
	}
	return name + " -o"
}

func formatNames(names []string) string {
	if len(names) == 0 {
		return ""
	}

	parts := formatNameParts(names)

	return strings.Join(parts, " ")
}

func formatNameParts(names []string) []string {
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, formatNamePart(name))
	}
	return parts
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
