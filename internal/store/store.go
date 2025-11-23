package store

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	icrypto "qault/internal/crypto"
)

type Secret struct {
	Name      string    `json:"name"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func EncryptSecret(password string, s Secret) ([]byte, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	return icrypto.Encrypt(password, payload)
}

func DecryptSecret(password string, data []byte) (Secret, error) {
	plaintext, err := icrypto.Decrypt(password, data)
	if err != nil {
		return Secret{}, err
	}

	var s Secret
	if err := json.Unmarshal(plaintext, &s); err != nil {
		return Secret{}, fmt.Errorf("secret: %w", err)
	}

	return s, nil
}

func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
