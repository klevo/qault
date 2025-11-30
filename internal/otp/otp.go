package otp

import (
	"encoding/base32"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type Config struct {
	Issuer      string `json:"issuer"`
	AccountName string `json:"account"`
	Secret      string `json:"secret"`
	Digits      int    `json:"digits"`
	Period      uint   `json:"period"`
	Algorithm   string `json:"algorithm"`
}

// DecodeImage reads a QR code image and returns its payload as text.
func DecodeImage(r io.Reader) (string, error) {
	img, _, err := image.Decode(r)
	if err != nil {
		return "", fmt.Errorf("decode image: %w", err)
	}

	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("bitmap: %w", err)
	}

	result, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("qr decode: %w", err)
	}

	return result.GetText(), nil
}

// ConfigFromImagePath opens the QR image at the given path and parses it into a Config.
func ConfigFromImagePath(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		if unescaped, changed := unescapePath(path); changed {
			file, err = os.Open(unescaped)
		}
	}
	if err != nil {
		return Config{}, fmt.Errorf("open otp image: %w", err)
	}
	defer file.Close()

	return ConfigFromImage(file)
}

// ConfigFromImage parses a QR image reader into an OTP configuration.
func ConfigFromImage(r io.Reader) (Config, error) {
	uri, err := DecodeImage(r)
	if err != nil {
		return Config{}, err
	}
	return ParseURI(uri)
}

// ParseURI parses an otpauth URI into an internal configuration.
func ParseURI(uri string) (Config, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return Config{}, fmt.Errorf("otpauth uri: %w", err)
	}
	if u.Scheme != "otpauth" {
		return Config{}, fmt.Errorf("otpauth uri: invalid scheme %q", u.Scheme)
	}
	if u.Host != "totp" {
		return Config{}, fmt.Errorf("otpauth uri: unsupported type %q", u.Host)
	}

	label, err := url.PathUnescape(strings.TrimPrefix(u.Path, "/"))
	if err != nil {
		return Config{}, fmt.Errorf("otpauth label: %w", err)
	}
	issuer, account := parseLabel(label)

	q := u.Query()
	if v := q.Get("issuer"); v != "" {
		issuer = v
	}

	secretRaw := q.Get("secret")
	if secretRaw == "" {
		return Config{}, fmt.Errorf("otpauth uri: missing secret")
	}

	secret, err := normalizeSecret(secretRaw)
	if err != nil {
		return Config{}, err
	}

	digits, err := parseDigits(q.Get("digits"))
	if err != nil {
		return Config{}, err
	}

	period, err := parsePeriod(q.Get("period"))
	if err != nil {
		return Config{}, err
	}

	algorithm, err := parseAlgorithm(q.Get("algorithm"))
	if err != nil {
		return Config{}, err
	}

	return Config{
		Issuer:      issuer,
		AccountName: account,
		Secret:      secret,
		Digits:      digits,
		Period:      period,
		Algorithm:   algorithm,
	}, nil
}

// GenerateCode produces a TOTP code for the provided time using the configuration.
func GenerateCode(cfg Config, t time.Time) (string, error) {
	if cfg.Secret == "" {
		return "", fmt.Errorf("otp config missing secret")
	}

	alg, err := toAlgorithm(cfg.Algorithm)
	if err != nil {
		return "", err
	}

	digits, err := toDigits(cfg.Digits)
	if err != nil {
		return "", err
	}

	period := cfg.Period
	if period == 0 {
		period = 30
	}

	return totp.GenerateCodeCustom(cfg.Secret, t, totp.ValidateOpts{
		Period:    period,
		Skew:      0,
		Digits:    digits,
		Algorithm: alg,
	})
}

func parseLabel(label string) (string, string) {
	if label == "" {
		return "", ""
	}
	parts := strings.SplitN(label, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return "", strings.TrimSpace(label)
}

func normalizeSecret(secret string) (string, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized); err != nil {
		return "", fmt.Errorf("secret: %w", err)
	}
	return normalized, nil
}

func parseDigits(raw string) (int, error) {
	if raw == "" {
		return 6, nil
	}
	switch raw {
	case "6":
		return 6, nil
	case "8":
		return 8, nil
	default:
		return 0, fmt.Errorf("digits: unsupported value %q", raw)
	}
}

func toDigits(n int) (otp.Digits, error) {
	switch n {
	case 6, 0:
		return otp.DigitsSix, nil
	case 8:
		return otp.DigitsEight, nil
	default:
		return 0, fmt.Errorf("digits: unsupported value %d", n)
	}
}

func parsePeriod(raw string) (uint, error) {
	if raw == "" {
		return 30, nil
	}

	var period uint
	_, err := fmt.Sscanf(raw, "%d", &period)
	if err != nil {
		return 0, fmt.Errorf("period: %w", err)
	}
	if period == 0 {
		return 0, fmt.Errorf("period: must be greater than zero")
	}
	return period, nil
}

func parseAlgorithm(raw string) (string, error) {
	if raw == "" {
		return "SHA1", nil
	}
	switch strings.ToUpper(raw) {
	case "SHA1", "SHA256", "SHA512":
		return strings.ToUpper(raw), nil
	default:
		return "", fmt.Errorf("algorithm: unsupported value %q", raw)
	}
}

func toAlgorithm(name string) (otp.Algorithm, error) {
	switch strings.ToUpper(name) {
	case "SHA1", "":
		return otp.AlgorithmSHA1, nil
	case "SHA256":
		return otp.AlgorithmSHA256, nil
	case "SHA512":
		return otp.AlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("algorithm: unsupported value %q", name)
	}
}

func unescapePath(path string) (string, bool) {
	var b strings.Builder
	changed := false

	for i := 0; i < len(path); i++ {
		if path[i] == '\\' {
			if i+1 >= len(path) {
				b.WriteByte(path[i])
				break
			}
			changed = true
			i++
			b.WriteByte(path[i])
			continue
		}
		b.WriteByte(path[i])
	}

	if !changed {
		return path, false
	}

	return b.String(), true
}
