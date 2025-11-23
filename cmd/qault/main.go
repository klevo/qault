package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/term"

	"qault/internal/agent"
	icrypto "qault/internal/crypto"
	ifs "qault/internal/fs"
	"qault/internal/store"
)

var errWrongMasterKey = errors.New("master key is wrong")

type lockFile struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func main() {
	args := os.Args[1:]

	switch {
	case len(args) == 0:
		handleList()
	case len(args) == 1:
		if args[0] == "init" {
			handleInit()
			return
		}

		if args[0] == "unlock" {
			handleUnlock()
			return
		}

		if args[0] == "lock" {
			handleLock()
			return
		}

		if args[0] == "add" {
			fmt.Fprintln(os.Stderr, "name is required for add")
			os.Exit(1)
		}

		if args[0] == "agent" {
			if err := serveAgent(); err != nil {
				fail(err)
			}
			return
		}

		handleFetch(args[0])
	case len(args) == 2 && args[0] == "add":
		handleAdd(args[1])
	default:
		fmt.Fprintln(os.Stderr, "usage: qault init | qault unlock | qault lock | qault add [NAME] | qault [NAME]")
		os.Exit(1)
	}
}

func handleInit() {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		fail(err)
	}

	hasLock, err := ifs.HasLock(dir)
	if err != nil {
		fail(err)
	}
	if hasLock {
		fmt.Println(dir)
		return
	}

	fmt.Fprintln(os.Stderr, "Use a strong master secret: 16+ random characters or a 5-7 word diceware-style passphrase to give ~90 bits of entropy; Argon2id slows attackers but offline GPU cracking is still viable with weak passwords.")

	password, err := promptNewMasterPassword()
	if err != nil {
		fail(err)
	}

	lockValue, err := icrypto.RandomLockString()
	if err != nil {
		fail(err)
	}

	salt, err := icrypto.GenerateSalt()
	if err != nil {
		fail(err)
	}

	rootKey, err := icrypto.DeriveRootKey(password, salt)
	if err != nil {
		fail(err)
	}

	env, err := icrypto.EncryptWithKey(rootKey, []byte(lockValue))
	if err != nil {
		fail(err)
	}

	lock := lockFile{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      env.Nonce,
		Ciphertext: env.Ciphertext,
	}

	payload, err := json.Marshal(lock)
	if err != nil {
		fail(err)
	}

	if err := store.WriteFile(ifs.LockPath(dir), payload); err != nil {
		fail(err)
	}

	fmt.Println(dir)
}

func handleAdd(name string) {
	if name == "" {
		fmt.Fprintln(os.Stderr, "name is required for add")
		os.Exit(1)
	}

	dir, err := ifs.EnsureDataDir()
	if err != nil {
		fail(err)
	}

	if err := ensureInitialized(dir); err != nil {
		fail(err)
	}

	rootKey, err := getRootKeyWithFallback(dir)
	if err != nil {
		handleMasterKeyError(err)
	}

	secretValue, err := promptSecretValue()
	if err != nil {
		fail(err)
	}

	now := time.Now().UTC()
	s := store.Secret{
		Name:      name,
		Secret:    secretValue,
		CreatedAt: now,
		UpdatedAt: now,
	}

	encrypted, err := store.EncryptSecret(rootKey, s)
	if err != nil {
		fail(err)
	}

	id, err := uuid.NewV7()
	if err != nil {
		fail(err)
	}

	if err := store.WriteFile(filepath.Join(dir, id.String()), encrypted); err != nil {
		fail(err)
	}

	fmt.Fprintf(os.Stdout, "secret saved under %s\n", name)
}

func handleList() {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		fail(err)
	}

	if err := ensureInitialized(dir); err != nil {
		fail(err)
	}

	rootKey, err := getRootKeyWithFallback(dir)
	if err != nil {
		handleMasterKeyError(err)
	}

	files, err := ifs.ListSecretFiles(dir)
	if err != nil {
		fail(err)
	}

	for _, path := range files {
		data, err := store.ReadFile(path)
		if err != nil {
			fail(err)
		}

		secret, err := store.DecryptSecret(rootKey, data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to decrypt secret %s\n", filepath.Base(path))
			os.Exit(1)
		}

		fmt.Fprintln(os.Stdout, secret.Name)
	}
}

func handleFetch(name string) {
	if name == "" {
		fmt.Fprintln(os.Stderr, "name is required")
		os.Exit(1)
	}

	dir, err := ifs.EnsureDataDir()
	if err != nil {
		fail(err)
	}

	if err := ensureInitialized(dir); err != nil {
		fail(err)
	}

	rootKey, err := getRootKeyWithFallback(dir)
	if err != nil {
		handleMasterKeyError(err)
	}

	files, err := ifs.ListSecretFiles(dir)
	if err != nil {
		fail(err)
	}

	for _, path := range files {
		data, err := store.ReadFile(path)
		if err != nil {
			fail(err)
		}

		secret, err := store.DecryptSecret(rootKey, data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to decrypt secret %s\n", filepath.Base(path))
			os.Exit(1)
		}

		if strings.EqualFold(secret.Name, name) {
			// Avoid adding a trailing newline when piping
			if term.IsTerminal(int(os.Stdout.Fd())) {
				fmt.Fprintln(os.Stdout, secret.Secret)
			} else {
				fmt.Fprint(os.Stdout, secret.Secret)
			}
			return
		}
	}

	fmt.Fprintln(os.Stderr, "secret not found")
	os.Exit(1)
}

func handleUnlock() {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		fail(err)
	}

	if err := ensureInitialized(dir); err != nil {
		fail(err)
	}

	sock := agent.SocketPath(dir)

	if _, ok, _ := agent.FetchRootKey(sock); ok {
		fmt.Fprintf(os.Stdout, "agent already running at %s\n", sock)
		return
	}

	password := mustPromptMasterPassword()
	rootKey, err := unlockRootKey(dir, password)
	if err != nil {
		handleMasterKeyError(err)
	}

	ttl := 5 * time.Minute

	cmd := exec.Command(os.Args[0], "agent")
	cmd.Env = append(os.Environ(), fmt.Sprintf("QAULT_AGENT_TTL=%d", int64(ttl.Seconds())))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fail(err)
	}

	go func() {
		defer stdin.Close()
		_ = json.NewEncoder(stdin).Encode(base64.StdEncoding.EncodeToString(rootKey))
	}()

	if err := cmd.Start(); err != nil {
		fail(err)
	}

	fmt.Fprintf(os.Stdout, "agent started: socket at %s, TTL %s\n", sock, ttl)
}

func handleLock() {
	dir, err := ifs.EnsureDataDir()
	if err != nil {
		fail(err)
	}
	sock := agent.SocketPath(dir)

	if err := agent.Lock(sock); err != nil {
		fmt.Fprintln(os.Stderr, "agent not running")
		return
	}

	fmt.Fprintln(os.Stdout, "agent locked")
}

func serveAgent() error {
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
		return errors.New("vault is not initialized")
	}

	return nil
}

func getRootKeyWithFallback(dir string) ([]byte, error) {
	sock := agent.SocketPath(dir)
	if key, ok, _ := agent.FetchRootKey(sock); ok {
		return key, nil
	}

	password, err := promptMasterPassword()
	if err != nil {
		return nil, err
	}

	rootKey, err := unlockRootKey(dir, password)
	if err != nil {
		return nil, err
	}

	return rootKey, nil
}

func promptMasterPassword() (string, error) {
	return promptNonEmpty("Master password: ")
}

func mustPromptMasterPassword() string {
	p, err := promptMasterPassword()
	if err != nil {
		fail(err)
	}
	return p
}

func promptNewMasterPassword() (string, error) {
	for {
		first, err := promptNonEmpty("Master password: ")
		if err != nil {
			return "", err
		}

		second, err := promptNonEmpty("Confirm master password: ")
		if err != nil {
			return "", err
		}

		if first == second {
			return first, nil
		}

		fmt.Fprintln(os.Stderr, "passwords do not match")
	}
}

func promptSecretValue() (string, error) {
	return promptNonEmpty("Secret: ")
}

func promptNonEmpty(prompt string) (string, error) {
	for {
		value, err := readHiddenInput(prompt)
		if err != nil {
			return "", err
		}

		if value != "" {
			return value, nil
		}

		fmt.Fprintln(os.Stderr, "input cannot be empty")
	}
}

// Hidden input capture with restore functionality on SIGTERM,
// so that terminal doesn't get stuck with hidden input.
func readHiddenInput(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
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
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	return string(input), nil
}

func handleMasterKeyError(err error) {
	if errors.Is(err, errWrongMasterKey) {
		fmt.Fprintln(os.Stderr, "master key is wrong")
		os.Exit(1)
	}

	fail(err)
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

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
