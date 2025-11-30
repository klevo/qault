package cli

import (
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

	"qault/internal/auth"
	icrypto "qault/internal/crypto"
	ifs "qault/internal/fs"
	"qault/internal/gitrepo"
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

type Prompter interface {
	MasterPassword() (string, error)
	NewMasterPassword() (string, error)
	SecretValue() (string, error)
	SecretValueWithPrompt(prompt string) (string, error)
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
		return userError("command required; try `qault list` or see available subcommands")
	}

	switch args[0] {
	case "init":
		return c.handleInit()
	case "add":
		return c.handleAddArgs(args[1:])
	case "rm":
		return c.handleRemoveArgs(args[1:])
	case "mv":
		return c.handleMoveArgs(args[1:])
	case "edit":
		return c.handleEditArgs(args[1:])
	case "recent":
		return c.handleRecent()
	case "list":
		return c.handleList()
	case "change-master-password":
		return c.handleChangeMasterPassword()
	default:
		return c.handleFetchArgs(args)
	}
}

func (c *CLI) handleInit() error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := gitrepo.Init(dir); err != nil {
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

	if err := auth.WriteLockFile(dir, lockValue, salt, rootKey); err != nil {
		return fatalError(err)
	}

	if err := gitrepo.CommitFiles(dir, "master password changed", ifs.LockPath(dir)); err != nil {
		return fatalError(err)
	}

	fmt.Fprintln(c.Out, dir)
	return nil
}

func (c *CLI) handleAddArgs(args []string) error {
	names, otpPath, useEditor, err := parseAddArgs(args)
	if err != nil {
		return err
	}
	if otpPath != "" {
		return c.handleAddOTP(names, otpPath)
	}
	return c.handleAddSecret(names, useEditor)
}

func (c *CLI) handleRemoveArgs(args []string) error {
	names, err := parseNameArgs(args, "Name is required for rm")
	if err != nil {
		return err
	}
	return c.handleRemove(names)
}

func (c *CLI) handleEditArgs(args []string) error {
	names, useEditor, err := parseEditArgs(args)
	if err != nil {
		return err
	}
	return c.handleEdit(names, useEditor)
}

func (c *CLI) handleChangeMasterPassword() error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := auth.EnsureInitialized(dir); err != nil {
		return fatalError(err)
	}

	lock, salt, err := auth.ReadLockFile(dir)
	if err != nil {
		return err
	}

	currentPassword, err := c.promptWithLabel("Current master password: ")
	if err != nil {
		return fatalError(err)
	}

	oldRootKey, lockValue, err := auth.DeriveLockValue(lock, salt, currentPassword)
	if err != nil {
		return c.handleMasterKeyError(err)
	}

	newPassword, err := c.promptNewPassword()
	if err != nil {
		return fatalError(err)
	}

	newSalt, err := icrypto.GenerateSalt()
	if err != nil {
		return fatalError(err)
	}

	newRootKey, err := icrypto.DeriveRootKey(newPassword, newSalt)
	if err != nil {
		return fatalError(err)
	}

	updatedPaths, err := reencryptSecrets(dir, oldRootKey, newRootKey)
	if err != nil {
		return err
	}

	if err := auth.WriteLockFile(dir, lockValue, newSalt, newRootKey); err != nil {
		return err
	}

	commitPaths := append(updatedPaths, ifs.LockPath(dir))
	if err := gitrepo.CommitFiles(dir, "master password changed", commitPaths...); err != nil {
		return fatalError(err)
	}

	fmt.Fprintln(c.Out, "Master password updated")
	return nil
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

	if err := auth.EnsureInitialized(dir); err != nil {
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

	if err := auth.EnsureInitialized(dir); err != nil {
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

	if err := gitrepo.CommitFiles(dir, "secret updated", path); err != nil {
		return fatalError(err)
	}

	return nil
}

func reencryptSecrets(dir string, oldRootKey, newRootKey []byte) ([]string, error) {
	files, err := ifs.ListSecretFiles(dir)
	if err != nil {
		return nil, fatalError(err)
	}

	var updated []string
	for _, path := range files {
		data, err := store.ReadFile(path)
		if err != nil {
			return nil, fatalError(err)
		}

		secret, err := store.DecryptSecret(oldRootKey, data)
		if err != nil {
			return nil, userError(fmt.Sprintf("Failed to decrypt secret %s", filepath.Base(path)))
		}

		encrypted, err := store.EncryptSecret(newRootKey, secret)
		if err != nil {
			return nil, fatalError(err)
		}

		if err := store.WriteFile(path, encrypted); err != nil {
			return nil, fatalError(err)
		}

		updated = append(updated, path)
	}

	return updated, nil
}

func (c *CLI) handleEdit(names []string, useEditor bool) error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := auth.EnsureInitialized(dir); err != nil {
		return fatalError(err)
	}

	rootKey, err := c.getRootKeyWithFallback(dir)
	if err != nil {
		return c.handleMasterKeyError(err)
	}

	secret, path, found, err := findSecretByName(dir, rootKey, names)
	if err != nil {
		return err
	}
	if !found {
		return exitError{code: 1, msg: "Secret not found"}
	}

	newSecretValue, err := c.secretInput(useEditor, "New secret: ", secret.Secret)
	if err != nil {
		return err
	}

	secret.Secret = newSecretValue
	secret.UpdatedAt = timeNow().UTC()

	encrypted, err := store.EncryptSecret(rootKey, secret)
	if err != nil {
		return fatalError(err)
	}

	if err := store.WriteFile(path, encrypted); err != nil {
		return fatalError(err)
	}

	if err := gitrepo.CommitFiles(dir, "secret updated", path); err != nil {
		return fatalError(err)
	}

	fmt.Fprintf(c.Out, "Secret '%s' updated\n", formatNames(secret.Name))
	return nil
}

func parseAddArgs(args []string) ([]string, string, bool, error) {
	var names []string
	var otpPath string
	useEditor := false

	for i := 0; i < len(args); i++ {
		if args[i] == "-o" {
			if otpPath != "" || i == len(args)-1 {
				return nil, "", false, userError("usage: qault add NAME... [-o PATH] [-e]")
			}
			otpPath = args[i+1]
			i++
			continue
		}
		if args[i] == "-e" {
			if useEditor {
				return nil, "", false, userError("usage: qault add NAME... [-o PATH] [-e]")
			}
			useEditor = true
			continue
		}
		names = append(names, args[i])
	}

	if otpPath != "" && useEditor {
		return nil, "", false, userError("usage: qault add NAME... [-o PATH] [-e]")
	}

	if len(names) == 0 {
		return nil, "", false, userError("name is required for add")
	}

	return names, otpPath, useEditor, nil
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

func parseEditArgs(args []string) ([]string, bool, error) {
	useEditor := false
	var names []string

	for _, arg := range args {
		if arg == "-e" {
			if useEditor {
				return nil, false, userError("usage: qault edit NAME... [-e]")
			}
			useEditor = true
			continue
		}
		names = append(names, arg)
	}

	parsedNames, err := parseNameArgs(names, "Name is required for edit")
	if err != nil {
		return nil, false, err
	}

	return parsedNames, useEditor, nil
}

func (c *CLI) handleAddSecret(names []string, useEditor bool) error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := auth.EnsureInitialized(dir); err != nil {
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

	secretValue, err := c.secretInput(useEditor, "Secret: ", "")
	if err != nil {
		return err
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

	if err := gitrepo.CommitFiles(dir, "secret added", filepath.Join(dir, id.String())); err != nil {
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

	if err := auth.EnsureInitialized(dir); err != nil {
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

	cfg, err := otp.ConfigFromImagePath(qrPath)
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return fatalError(err)
		}
		return userError(fmt.Sprintf("Failed to read OTP QR: %v", err))
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

	if err := gitrepo.CommitFiles(dir, "secret updated", pathForSecret); err != nil {
		return fatalError(err)
	}

	fmt.Fprintf(c.Out, "OTP added\n")
	return nil
}

func (c *CLI) handleList() error {
	return c.handleListSorted(false)
}

func (c *CLI) handleRecent() error {
	return c.handleListSorted(true)
}

func (c *CLI) handleListSorted(sortByUpdated bool) error {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		return fatalError(err)
	}

	if err := auth.EnsureInitialized(dir); err != nil {
		return fatalError(err)
	}

	rootKey, err := c.getRootKeyWithFallback(dir)
	if err != nil {
		return c.handleMasterKeyError(err)
	}

	secrets, err := auth.LoadSecrets(dir, rootKey)
	if err != nil {
		return err
	}

	if sortByUpdated {
		sort.Slice(secrets, func(i, j int) bool {
			return secrets[i].UpdatedAt.After(secrets[j].UpdatedAt)
		})
	} else {
		sort.Slice(secrets, func(i, j int) bool {
			return namesLessFold(secrets[i].Name, secrets[j].Name)
		})
	}

	useColor := isTerminal(c.Out)
	for _, secret := range secrets {
		fmt.Fprintln(c.Out, formatListEntry(secret.Name, secret.OTP != nil, useColor, sortByUpdated, secret.UpdatedAt))
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
				return nil, false, userError("usage: qault list | qault init | qault add NAME... [-o PATH] | qault rm NAME... | qault mv OLD... --to NEW... | qault recent | qault NAME... [-o]")
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

	if err := auth.EnsureInitialized(dir); err != nil {
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

	if err := auth.EnsureInitialized(dir); err != nil {
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

func (c *CLI) getRootKeyWithFallback(dir string) ([]byte, error) {
	password, err := c.Prompter.MasterPassword()
	if err != nil {
		return nil, err
	}

	rootKey, err := auth.UnlockRootKey(dir, password)
	if err != nil {
		return nil, err
	}

	return rootKey, nil
}

func (c *CLI) handleMasterKeyError(err error) error {
	if errors.Is(err, auth.ErrWrongMasterPassword) {
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

func formatListEntry(names []string, hasOTP bool, useColor bool, includeTimestamp bool, updatedAt time.Time) string {
	if len(names) == 0 {
		return ""
	}

	parts := formatNameParts(names)
	if useColor && len(parts) > 1 {
		colors := []string{colorTeal, colorBlue}
		for i, colorIdx := 0, 0; i < len(parts)-1; i, colorIdx = i+1, (colorIdx+1)%len(colors) {
			parts[i] = colors[colorIdx] + parts[i] + colorReset
		}
	}

	name := strings.Join(parts, " ")
	if hasOTP {
		if useColor {
			name += " " + colorFaint + "-o" + colorReset
		} else {
			name += " -o"
		}
	}

	if includeTimestamp {
		ts := updatedAt.UTC().Format(time.RFC3339)
		if useColor {
			name = colorFaint + ts + colorReset + " " + name
		} else {
			name = ts + " " + name
		}
	}

	return name
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

func (c *CLI) secretInput(useEditor bool, prompt, initial string) (string, error) {
	if useEditor {
		value, err := secretFromEditor(initial)
		if err != nil {
			return "", err
		}
		return value, nil
	}

	if prompt == "" {
		return c.Prompter.SecretValue()
	}
	return c.Prompter.SecretValueWithPrompt(prompt)
}

func secretFromEditor(initial string) (string, error) {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		return "", userError("EDITOR is not set")
	}

	file, err := os.CreateTemp("", "qault-edit-*")
	if err != nil {
		return "", fatalError(err)
	}
	path := file.Name()
	defer os.Remove(path)
	defer file.Close()

	if _, err := file.WriteString(initial); err != nil {
		return "", fatalError(err)
	}

	if err := file.Chmod(0o600); err != nil {
		return "", fatalError(err)
	}

	cmd := buildEditorCommand(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fatalError(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fatalError(err)
	}

	value := strings.TrimRight(string(data), "\n")
	if value == "" {
		return "", userError("Secret cannot be empty")
	}

	return value, nil
}

func buildEditorCommand(editor, path string) *exec.Cmd {
	if strings.Contains(editor, " ") || strings.Contains(editor, "\t") {
		return exec.Command("sh", "-c", editor+" \"$@\"", "--", path)
	}
	return exec.Command(editor, path)
}

func (c *CLI) promptWithLabel(label string) (string, error) {
	if tp, ok := c.Prompter.(*TerminalPrompter); ok {
		return tp.promptNonEmpty(label)
	}
	return c.Prompter.MasterPassword()
}

func (c *CLI) promptNewPassword() (string, error) {
	if tp, ok := c.Prompter.(*TerminalPrompter); ok {
		for {
			first, err := tp.promptNonEmpty("New master password: ")
			if err != nil {
				return "", err
			}

			second, err := tp.promptNonEmpty("Confirm new master password: ")
			if err != nil {
				return "", err
			}

			if first == second {
				return first, nil
			}

			fmt.Fprintln(tp.Err, "passwords do not match")
		}
	}
	return c.Prompter.NewMasterPassword()
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

func (p *TerminalPrompter) SecretValueWithPrompt(prompt string) (string, error) {
	return p.promptNonEmpty(prompt)
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
