package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize    = 16
	nonceSize   = 12
	keySize     = 32
	argonTime   = 3
	argonMemory = 64 * 1024 // in KiB
)

type Envelope struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func GenerateSalt() ([]byte, error) {
	buf := make([]byte, saltSize)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	return buf, nil
}

func DeriveRootKey(password string, salt []byte) ([]byte, error) {
	if len(salt) != saltSize {
		return nil, errors.New("salt: invalid length")
	}
	key := deriveKey([]byte(password), salt)
	return key, nil
}

func EncryptWithKey(key []byte, plaintext []byte) (Envelope, error) {
	if len(key) != keySize {
		return Envelope{}, errors.New("key length invalid")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return Envelope{}, fmt.Errorf("cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return Envelope{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func DecryptWithKey(key []byte, env Envelope) ([]byte, error) {
	if len(key) != keySize {
		return nil, errors.New("key length invalid")
	}

	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	if len(nonce) != nonceSize {
		return nil, errors.New("nonce: invalid length")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

func RandomLockString() (string, error) {
	buf := make([]byte, 96)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func deriveKey(password, salt []byte) []byte {
	threads := runtime.NumCPU()
	if threads < 1 {
		threads = 1
	}
	if threads > 255 {
		threads = 255
	}

	return argon2.IDKey(password, salt, argonTime, argonMemory, uint8(threads), keySize)
}
