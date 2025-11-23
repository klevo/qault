package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/term"

	icrypto "qault/internal/crypto"
	ifs "qault/internal/fs"
	"qault/internal/store"
)

var errWrongMasterKey = errors.New("master key is wrong")

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

		if args[0] == "add" {
			fmt.Fprintln(os.Stderr, "name is required for add")
			os.Exit(1)
		}

		handleFetch(args[0])
	case len(args) == 2 && args[0] == "add":
		handleAdd(args[1])
	default:
		fmt.Fprintln(os.Stderr, "usage: qault init | qault add [NAME] | qault [NAME]")
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

	password, err := promptNewMasterPassword()
	if err != nil {
		fail(err)
	}

	lockValue, err := icrypto.RandomLockString()
	if err != nil {
		fail(err)
	}

	encrypted, err := icrypto.Encrypt(password, []byte(lockValue))
	if err != nil {
		fail(err)
	}

	if err := store.WriteFile(ifs.LockPath(dir), encrypted); err != nil {
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

	password, err := promptMasterPassword()
	if err != nil {
		fail(err)
	}

	if err := verifyMasterPassword(dir, password); err != nil {
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

	encrypted, err := store.EncryptSecret(password, s)
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

	password, err := promptMasterPassword()
	if err != nil {
		fail(err)
	}

	if err := verifyMasterPassword(dir, password); err != nil {
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

		secret, err := store.DecryptSecret(password, data)
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

	password, err := promptMasterPassword()
	if err != nil {
		fail(err)
	}

	if err := verifyMasterPassword(dir, password); err != nil {
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

		secret, err := store.DecryptSecret(password, data)
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

func verifyMasterPassword(dir, password string) error {
	data, err := store.ReadFile(ifs.LockPath(dir))
	if err != nil {
		return err
	}

	if _, err := icrypto.Decrypt(password, data); err != nil {
		return errWrongMasterKey
	}

	return nil
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

func promptMasterPassword() (string, error) {
	return promptNonEmpty("Master password: ")
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

func readHiddenInput(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
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

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
