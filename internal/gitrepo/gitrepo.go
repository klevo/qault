package gitrepo

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// Push attempts to push the current HEAD to each remote provided.
func Push(dir string, remotes []string) error {
	if len(remotes) == 0 {
		return nil
	}
	if err := Init(dir); err != nil {
		return err
	}

	for _, remote := range remotes {
		if err := run(dir, "push", remote, "HEAD"); err != nil {
			return fmt.Errorf("git push %s: %w", remote, err)
		}
	}
	return nil
}

// RemoteBehind reports whether any of the provided remotes has commits that the local HEAD does not.
// It fetches each remote's HEAD to compare ancestry. Returns true if local is behind any remote.
func RemoteBehind(dir string, remotes []string) (bool, error) {
	if len(remotes) == 0 {
		return false, nil
	}
	if err := Init(dir); err != nil {
		return false, err
	}

	head, err := runOutput(dir, "rev-parse", "HEAD")
	if err != nil {
		return false, err
	}

	for _, remote := range remotes {
		if err := run(dir, "fetch", "--no-tags", remote, "HEAD"); err != nil {
			return false, fmt.Errorf("git fetch %s: %w", remote, err)
		}

		remoteHead, err := runOutput(dir, "rev-parse", "FETCH_HEAD")
		if err != nil {
			return false, fmt.Errorf("git fetch-head %s: %w", remote, err)
		}

		if remoteHead == head {
			continue
		}

		_, exitCode, err := runWithExitCode(dir, "merge-base", "--is-ancestor", head, remoteHead)
		if err != nil {
			return false, err
		}
		if exitCode == 0 {
			return true, nil
		}
		if exitCode != 1 {
			return false, fmt.Errorf("git merge-base --is-ancestor %s %s exit %d", head, remoteHead, exitCode)
		}
	}

	return false, nil
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
	output, code, err := runWithExitCode(dir, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("git %s: %s", strings.Join(args, " "), output)
	}
	return nil
}

func runOutput(dir string, args ...string) (string, error) {
	output, code, err := runWithExitCode(dir, args...)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(output))
	}
	return strings.TrimSpace(output), nil
}

func runWithExitCode(dir string, args ...string) (string, int, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")

	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(output), exitErr.ExitCode(), nil
	}
	return "", 0, fmt.Errorf("%v: %s", err, string(output))
}
