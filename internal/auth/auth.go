package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"qault/internal/crypto"
	ifs "qault/internal/fs"
	"qault/internal/store"
)

// ErrWrongMasterPassword is returned when the provided master password fails to decrypt the lock file.
var ErrWrongMasterPassword = errors.New("Incorrect master password")

type LockFile struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type SecretRecord struct {
	Secret store.Secret
	Path   string
}

func EnsureInitialized(dir string) error {
	hasLock, err := ifs.HasLock(dir)
	if err != nil {
		return err
	}

	if !hasLock {
		return errors.New("Vault is not initialized")
	}

	return nil
}

func UnlockRootKey(dir, password string) ([]byte, error) {
	lock, salt, err := ReadLockFile(dir)
	if err != nil {
		return nil, err
	}

	rootKey, _, err := DeriveLockValue(lock, salt, password)
	return rootKey, err
}

func ReadLockFile(dir string) (LockFile, []byte, error) {
	data, err := store.ReadFile(ifs.LockPath(dir))
	if err != nil {
		return LockFile{}, nil, err
	}

	var lock LockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return LockFile{}, nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(lock.Salt)
	if err != nil {
		return LockFile{}, nil, err
	}

	return lock, salt, nil
}

func DeriveLockValue(lock LockFile, salt []byte, password string) ([]byte, string, error) {
	rootKey, err := crypto.DeriveRootKey(password, salt)
	if err != nil {
		return nil, "", err
	}

	env := crypto.Envelope{
		Nonce:      lock.Nonce,
		Ciphertext: lock.Ciphertext,
	}

	value, err := crypto.DecryptWithKey(rootKey, env)
	if err != nil {
		return nil, "", ErrWrongMasterPassword
	}

	return rootKey, string(value), nil
}

func WriteLockFile(dir, lockValue string, salt, rootKey []byte) error {
	env, err := crypto.EncryptWithKey(rootKey, []byte(lockValue))
	if err != nil {
		return err
	}

	lock := LockFile{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      env.Nonce,
		Ciphertext: env.Ciphertext,
	}

	payload, err := json.Marshal(lock)
	if err != nil {
		return err
	}

	return store.WriteFile(ifs.LockPath(dir), payload)
}

func LoadSecrets(dir string, rootKey []byte) ([]store.Secret, error) {
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

func LoadSecretRecords(dir string, rootKey []byte) ([]SecretRecord, error) {
	files, err := ifs.ListSecretFiles(dir)
	if err != nil {
		return nil, err
	}

	var secrets []SecretRecord
	for _, path := range files {
		data, err := store.ReadFile(path)
		if err != nil {
			return nil, err
		}

		secret, err := store.DecryptSecret(rootKey, data)
		if err != nil {
			return nil, fmt.Errorf("Failed to decrypt secret %s", filepath.Base(path))
		}

		secrets = append(secrets, SecretRecord{Secret: secret, Path: path})
	}

	return secrets, nil
}
