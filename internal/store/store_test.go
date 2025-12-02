package store

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	icrypto "qault/internal/crypto"
	"qault/internal/otp"
)

func TestRemoteURIFromNames(t *testing.T) {
	tests := []struct {
		name    string
		parts   []string
		wantURI string
		wantOK  bool
	}{
		{"basic", []string{"qault", "remote", "git@github.com:example/repo.git"}, "git@github.com:example/repo.git", true},
		{"with username", []string{"qault", "remote", "https://example.com/r.git", "alice"}, "https://example.com/r.git", true},
		{"case-insensitive", []string{"QaUlT", "ReMoTe", "https://example.com/r.git", "ALICE"}, "https://example.com/r.git", true},
		{"trim whitespace", []string{" qault ", " remote ", "  https://example.com/r.git  ", "  alice  "}, "https://example.com/r.git", true},
		{"too short", []string{"qault", "remote"}, "", false},
		{"missing prefix", []string{"other", "remote", "git@host/repo"}, "", false},
		{"missing remote marker", []string{"qault", "something", "git@host/repo"}, "", false},
		{"empty uri", []string{"qault", "remote", "   ", "user"}, "", false},
		{"empty username", []string{"qault", "remote", "https://example.com/r.git", "   "}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURI, ok := RemoteURIFromNames(tt.parts)
			if ok != tt.wantOK || gotURI != tt.wantURI {
				t.Fatalf("RemoteURIFromNames(%v) = (%q, %v), want (%q, %v)", tt.parts, gotURI, ok, tt.wantURI, tt.wantOK)
			}
		})
	}
}

func TestRemoteDefinitionsFromSecrets(t *testing.T) {
	secrets := []Secret{
		{Name: []string{"qault", "remote", "https://example.com/one.git"}, Secret: "ignored"},
		{Name: []string{"qault", "remote", "https://example.com/two.git", "alice"}, Secret: "password"},
		{Name: []string{"qault", "remote", "https://example.com/two.git", "bob"}, Secret: ""}, // missing password, should not override credentials
		{Name: []string{"other", "remote", "https://example.com/three.git"}, Secret: "password"},
		{Name: []string{"qault", "remote", "https://example.com/one.git", "carol"}, Secret: "secret"}, // overrides first with credentials
	}

	got := RemoteDefinitionsFromSecrets(secrets)
	want := []RemoteDefinition{
		{URI: "https://example.com/one.git", Username: "carol", Password: "secret"},
		{URI: "https://example.com/two.git", Username: "alice", Password: "password"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RemoteDefinitionsFromSecrets mismatch:\n got  %+v\n want %+v", got, want)
	}
}

func TestEncryptDecryptSecret(t *testing.T) {
	secret := Secret{
		Name:   []string{"email"},
		Secret: "hunter2",
		OTP: &otp.Config{
			Issuer:      "Example",
			AccountName: "user@example.com",
			Secret:      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			Digits:      6,
			Period:      30,
			Algorithm:   "SHA1",
		},
		CreatedAt: time.Unix(100, 0),
		UpdatedAt: time.Unix(200, 0),
	}

	salt, err := icrypto.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt error: %v", err)
	}

	rootKey, err := icrypto.DeriveRootKey("password", salt)
	if err != nil {
		t.Fatalf("DeriveRootKey error: %v", err)
	}

	encrypted, err := EncryptSecret(rootKey, secret)
	if err != nil {
		t.Fatalf("EncryptSecret error: %v", err)
	}

	decrypted, err := DecryptSecret(rootKey, encrypted)
	if err != nil {
		t.Fatalf("DecryptSecret error: %v", err)
	}

	if !reflect.DeepEqual(decrypted.Name, secret.Name) {
		t.Fatalf("names mismatch: %+v != %+v", decrypted.Name, secret.Name)
	}
	if decrypted.Secret != secret.Secret {
		t.Fatalf("secret mismatch: %q != %q", decrypted.Secret, secret.Secret)
	}
	if (decrypted.OTP == nil) != (secret.OTP == nil) {
		t.Fatalf("otp nil mismatch: %+v vs %+v", decrypted.OTP, secret.OTP)
	}
	if decrypted.OTP != nil && !reflect.DeepEqual(*decrypted.OTP, *secret.OTP) {
		t.Fatalf("otp mismatch: %+v != %+v", decrypted.OTP, secret.OTP)
	}
	if !decrypted.CreatedAt.Equal(secret.CreatedAt) {
		t.Fatalf("created at mismatch: %v != %v", decrypted.CreatedAt, secret.CreatedAt)
	}
	if !decrypted.UpdatedAt.Equal(secret.UpdatedAt) {
		t.Fatalf("updated at mismatch: %v != %v", decrypted.UpdatedAt, secret.UpdatedAt)
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
