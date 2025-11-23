package fs

import (
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/uuid"
)

const lockFileName = ".lock"

func DataDir() (string, error) {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "qault"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".qault"), nil
}

func EnsureDataDir() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}

	return dir, nil
}

func LockPath(dir string) string {
	return filepath.Join(dir, lockFileName)
}

func HasLock(dir string) (bool, error) {
	_, err := os.Stat(LockPath(dir))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	return false, err
}

func ListSecretFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if name == lockFileName {
			continue
		}

		id, err := uuid.Parse(name)
		if err != nil || id.Version() != uuid.Version(7) {
			continue
		}

		files = append(files, filepath.Join(dir, name))
	}

	sort.Strings(files)

	return files, nil
}
