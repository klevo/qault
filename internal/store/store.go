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

func EncryptSecret(rootKey []byte, s Secret) ([]byte, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}

	env, err := icrypto.EncryptWithKey(rootKey, payload)
	if err != nil {
		return nil, err
	}

	return json.Marshal(env)
}

func DecryptSecret(rootKey []byte, data []byte) (Secret, error) {
	var env icrypto.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Secret{}, fmt.Errorf("payload: %w", err)
	}

	plaintext, err := icrypto.DecryptWithKey(rootKey, env)
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
