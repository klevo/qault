package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptDecryptSecret(t *testing.T) {
	secret := Secret{
		Name:      "email",
		Secret:    "hunter2",
		CreatedAt: time.Unix(100, 0),
		UpdatedAt: time.Unix(200, 0),
	}

	password := "password"

	encrypted, err := EncryptSecret(password, secret)
	if err != nil {
		t.Fatalf("EncryptSecret error: %v", err)
	}

	decrypted, err := DecryptSecret(password, encrypted)
	if err != nil {
		t.Fatalf("DecryptSecret error: %v", err)
	}

	if decrypted != secret {
		t.Fatalf("round trip mismatch: %+v != %+v", decrypted, secret)
	}
}

func TestWriteAndReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	content := []byte("data")

	if err := WriteFile(path, content); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	read, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	if string(read) != string(content) {
		t.Fatalf("expected %q, got %q", content, read)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat error: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected file mode 0600, got %v", info.Mode().Perm())
	}
}
