package fs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestDataDirPrefersXDG(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", temp)
	t.Setenv("HOME", filepath.Join(temp, "home"))

	dir, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir error: %v", err)
	}

	if dir != filepath.Join(temp, "qault") {
		t.Fatalf("expected XDG-based dir, got %s", dir)
	}
}

func TestEnsureDataDirCreatesDirectory(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", temp)

	dir, err := EnsureDataDir()
	if err != nil {
		t.Fatalf("EnsureDataDir error: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat error: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected directory, got file")
	}
}

func TestListSecretFilesFiltersUUIDv7(t *testing.T) {
	dir := t.TempDir()

	validID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid error: %v", err)
	}

	validPath := filepath.Join(dir, validID.String())
	if err := os.WriteFile(validPath, []byte("data"), 0o600); err != nil {
		t.Fatalf("write error: %v", err)
	}

	noiseFiles := []string{".lock", "not-a-uuid", uuid.New().String()}
	for _, name := range noiseFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write noise %s: %v", name, err)
		}
	}

	files, err := ListSecretFiles(dir)
	if err != nil {
		t.Fatalf("ListSecretFiles error: %v", err)
	}

	if len(files) != 1 || files[0] != validPath {
		t.Fatalf("expected only valid v7 file, got %v", files)
	}
}
