package gitrepo

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Init ensures the directory is a git repository with basic user identity set.
func Init(dir string) error {
	isRepo, err := repositoryExists(dir)
	if err != nil {
		return err
	}
	if !isRepo {
		if err := run(dir, "init"); err != nil {
			return fmt.Errorf("git init: %w", err)
		}
	}
	if err := ensureIdentity(dir); err != nil {
		return err
	}
	return nil
}

// CommitFiles stages the provided files and commits them with the given message.
func CommitFiles(dir, message string, paths ...string) error {
	if len(paths) == 0 {
		return nil
	}
	if err := Init(dir); err != nil {
		return err
	}

	relative := make([]string, 0, len(paths))
	for _, p := range paths {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return fmt.Errorf("git relpath: %w", err)
		}
		relative = append(relative, rel)
	}

	if err := run(dir, append([]string{"add", "--"}, relative...)...); err != nil {
		return fmt.Errorf("git add: %w", err)
	}
	if err := run(dir, "commit", "-m", message); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	return nil
}

func repositoryExists(dir string) (bool, error) {
	err := run(dir, "rev-parse", "--is-inside-work-tree")
	if err == nil {
		return true, nil
	}
	// If git reports fatal, treat as not a repo instead of failing.
	return false, nil
}

func ensureIdentity(dir string) error {
	if err := run(dir, "config", "--local", "--get", "user.email"); err != nil {
		if err := run(dir, "config", "--local", "user.email", "qault@example.com"); err != nil {
			return fmt.Errorf("git config email: %w", err)
		}
	}
	if err := run(dir, "config", "--local", "--get", "user.name"); err != nil {
		if err := run(dir, "config", "--local", "user.name", "qault"); err != nil {
			return fmt.Errorf("git config name: %w", err)
		}
	}
	return nil
}

func run(dir string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}
