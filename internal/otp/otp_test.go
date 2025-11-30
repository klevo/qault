package otp

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

func TestParseURIAndGenerateCode(t *testing.T) {
	uri := "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30"

	cfg, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI error: %v", err)
	}

	if cfg.Issuer != "Example" || cfg.AccountName != "alice@example.com" {
		t.Fatalf("unexpected issuer/account: %+v", cfg)
	}
	if cfg.Secret != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("unexpected secret normalization: %q", cfg.Secret)
	}
	if cfg.Digits != 6 || cfg.Period != 30 || cfg.Algorithm != "SHA1" {
		t.Fatalf("unexpected config fields: %+v", cfg)
	}

	code, err := GenerateCode(cfg, time.Unix(59, 0).UTC())
	if err != nil {
		t.Fatalf("GenerateCode error: %v", err)
	}
	if code != "287082" {
		t.Fatalf("expected code 287082, got %q", code)
	}
}

func TestDecodeImage(t *testing.T) {
	payload := "otpauth://totp/Test:otp@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	writer := qrcode.NewQRCodeWriter()
	matrix, err := writer.Encode(payload, gozxing.BarcodeFormat_QR_CODE, 200, 200, nil)
	if err != nil {
		t.Fatalf("encode qr: %v", err)
	}

	img := bitMatrixToImage(matrix)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}

	result, err := DecodeImage(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("DecodeImage error: %v", err)
	}

	if result != payload {
		t.Fatalf("decoded payload mismatch: %q", result)
	}
}

func TestConfigFromImagePath(t *testing.T) {
	payload := "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30"
	writer := qrcode.NewQRCodeWriter()
	matrix, err := writer.Encode(payload, gozxing.BarcodeFormat_QR_CODE, 200, 200, nil)
	if err != nil {
		t.Fatalf("encode qr: %v", err)
	}

	path := t.TempDir() + "/otp.png"
	img := bitMatrixToImage(matrix)
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := png.Encode(file, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	cfg, err := ConfigFromImagePath(path)
	if err != nil {
		t.Fatalf("ConfigFromImagePath: %v", err)
	}
	if cfg.AccountName != "alice@example.com" || cfg.Issuer != "Example" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestConfigFromImageInvalidData(t *testing.T) {
	_, err := ConfigFromImage(bytes.NewBufferString("not-an-image"))
	if err == nil {
		t.Fatal("expected error for invalid image data")
	}
}

func bitMatrixToImage(m *gozxing.BitMatrix) image.Image {
	img := image.NewGray(image.Rect(0, 0, m.GetWidth(), m.GetHeight()))
	for y := 0; y < m.GetHeight(); y++ {
		for x := 0; x < m.GetWidth(); x++ {
			if m.Get(x, y) {
				img.SetGray(x, y, color.Gray{Y: 0})
			} else {
				img.SetGray(x, y, color.Gray{Y: 255})
			}
		}
	}
	return img
}
