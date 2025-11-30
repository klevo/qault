package auth

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"qault/internal/crypto"
	"qault/internal/store"
)

func TestUnlockRootKey(t *testing.T) {
	dir := t.TempDir()

	password := "pw"
	lockValue := "lock-value"

	rootKey, salt := deriveRootKey(t, password)
	if err := WriteLockFile(dir, lockValue, salt, rootKey); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	unlocked, err := UnlockRootKey(dir, password)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if string(unlocked) == "" || string(unlocked) != string(rootKey) {
		t.Fatalf("unexpected root key after unlock")
	}

	if _, err := UnlockRootKey(dir, "wrong"); err == nil {
		t.Fatalf("expected unlock to fail with wrong password")
	} else if err != ErrWrongMasterPassword {
		t.Fatalf("expected ErrWrongMasterPassword, got %v", err)
	}
}

func TestEnsureInitialized(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureInitialized(dir); err == nil {
		t.Fatalf("expected uninitialized vault error")
	}

	rootKey, salt := deriveRootKey(t, "pw")
	if err := WriteLockFile(dir, "lock", salt, rootKey); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	if err := EnsureInitialized(dir); err != nil {
		t.Fatalf("expected initialized vault, got: %v", err)
	}
}

func TestLoadSecrets(t *testing.T) {
	dir := t.TempDir()
	rootKey, _ := deriveRootKey(t, "pw")

	now := time.Unix(1000, 0).UTC()
	secret := store.Secret{
		Name:      []string{"personal", "email"},
		Secret:    "s3cr3t",
		CreatedAt: now,
		UpdatedAt: now,
	}

	payload, err := store.EncryptSecret(rootKey, secret)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}

	path := filepath.Join(dir, uuid.Must(uuid.NewV7()).String())
	if err := store.WriteFile(path, payload); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	secrets, err := LoadSecrets(dir, rootKey)
	if err != nil {
		t.Fatalf("load secrets: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].Secret != secret.Secret || secrets[0].Name[0] != "personal" {
		t.Fatalf("unexpected secret contents: %+v", secrets[0])
	}

	records, err := LoadSecretRecords(dir, rootKey)
	if err != nil {
		t.Fatalf("load secret records: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Path != path {
		t.Fatalf("unexpected record path: %s", records[0].Path)
	}
}

func deriveRootKey(t *testing.T, password string) ([]byte, []byte) {
	t.Helper()

	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}

	rootKey, err := crypto.DeriveRootKey(password, salt)
	if err != nil {
		t.Fatalf("derive root key: %v", err)
	}

	return rootKey, salt
}
