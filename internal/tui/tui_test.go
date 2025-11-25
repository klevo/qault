package tui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	icrypto "qault/internal/crypto"
	ifs "qault/internal/fs"
	"qault/internal/store"
)

func TestUnlockAndLoadReturnsSecrets(t *testing.T) {
	dir := setupVault(t)

	secrets, err := unlockAndLoad(dir, "pw")
	if err != nil {
		t.Fatalf("unlockAndLoad returned error: %v", err)
	}

	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}

	secret := secrets[0]
	if secret.Secret != "alpha-secret" {
		t.Fatalf("unexpected secret value: %q", secret.Secret)
	}
	if secret.Name[0] != "personal" || secret.Name[1] != "email" {
		t.Fatalf("unexpected secret name: %v", secret.Name)
	}
}

func TestUnlockAndLoadFailsWithWrongPassword(t *testing.T) {
	dir := setupVault(t)

	if _, err := unlockAndLoad(dir, "wrong"); !errors.Is(err, errIncorrectPassword) {
		t.Fatalf("expected incorrect password error, got: %v", err)
	}
}

func setupVault(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	dir := filepath.Join(root, "qault")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	lockValue, err := icrypto.RandomLockString()
	if err != nil {
		t.Fatalf("lock string: %v", err)
	}

	salt, err := icrypto.GenerateSalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}

	rootKey, err := icrypto.DeriveRootKey("pw", salt)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	env, err := icrypto.EncryptWithKey(rootKey, []byte(lockValue))
	if err != nil {
		t.Fatalf("encrypt lock: %v", err)
	}

	lock := lockFile{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      env.Nonce,
		Ciphertext: env.Ciphertext,
	}

	payload, err := json.Marshal(lock)
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}

	if err := store.WriteFile(ifs.LockPath(dir), payload); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	secret := store.Secret{
		Name:      []string{"personal", "email"},
		Secret:    "alpha-secret",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	encrypted, err := store.EncryptSecret(rootKey, secret)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}

	if err := store.WriteFile(filepath.Join(dir, id.String()), encrypted); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	return dir
}
