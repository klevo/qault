package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

type envelope struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func Encrypt(password string, plaintext []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}

	key := deriveKey([]byte(password), salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	payload := envelope{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	return json.Marshal(payload)
}

func Decrypt(password string, data []byte) ([]byte, error) {
	var payload envelope
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(payload.Salt)
	if err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	if len(salt) != saltSize {
		return nil, errors.New("salt: invalid length")
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	if len(nonce) != nonceSize {
		return nil, errors.New("nonce: invalid length")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ciphertext: %w", err)
	}

	key := deriveKey([]byte(password), salt)

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
