package crypto

import (
	"encoding/base64"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt error: %v", err)
	}

	key, err := DeriveRootKey("correct horse", salt)
	if err != nil {
		t.Fatalf("DeriveRootKey error: %v", err)
	}

	plaintext := []byte("secret payload")

	env, err := EncryptWithKey(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithKey error: %v", err)
	}

	decrypted, err := DecryptWithKey(key, env)
	if err != nil {
		t.Fatalf("DecryptWithKey error: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("want %q, got %q", plaintext, decrypted)
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt error: %v", err)
	}

	key, err := DeriveRootKey("correct horse", salt)
	if err != nil {
		t.Fatalf("DeriveRootKey error: %v", err)
	}

	wrongKey, err := DeriveRootKey("wrong battery", salt)
	if err != nil {
		t.Fatalf("DeriveRootKey wrong error: %v", err)
	}

	env, err := EncryptWithKey(key, []byte("secret payload"))
	if err != nil {
		t.Fatalf("EncryptWithKey error: %v", err)
	}

	if _, err := DecryptWithKey(wrongKey, env); err == nil {
		t.Fatalf("DecryptWithKey should fail with wrong key")
	}
}

func TestRandomLockString(t *testing.T) {
	lock, err := RandomLockString()
	if err != nil {
		t.Fatalf("RandomLockString error: %v", err)
	}

	if len(lock) != 128 {
		t.Fatalf("expected base64 string length 128, got %d", len(lock))
	}

	if _, err := base64.StdEncoding.DecodeString(lock); err != nil {
		t.Fatalf("lock string should be valid base64: %v", err)
	}
}
