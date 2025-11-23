package crypto

import (
	"encoding/base64"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	password := "correct horse"
	plaintext := []byte("secret payload")

	ciphertext, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decrypted, err := Decrypt(password, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("want %q, got %q", plaintext, decrypted)
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	password := "correct horse"
	wrong := "wrong battery"
	plaintext := []byte("secret payload")

	ciphertext, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	if _, err := Decrypt(wrong, ciphertext); err == nil {
		t.Fatalf("Decrypt should fail with wrong password")
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
