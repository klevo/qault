package gitrepo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qault/internal/store"
)

func TestPushUsesHTTPCredentials(t *testing.T) {
	dir := t.TempDir()

	mockGit := filepath.Join(dir, "git-mock")
	script := `#!/bin/sh
set -eu

if [ "$1" = "-C" ]; then
  workdir="$2"
  shift 2
else
  echo "missing -C" >&2
  exit 1
fi

cmd="$1"
shift

case "$cmd" in
  rev-parse)
    if [ -f "$workdir/.git-initialized" ]; then
      echo "true"
      exit 0
    fi
    echo "fatal: not a git repository" >&2
    exit 1
    ;;
  init)
    touch "$workdir/.git-initialized"
    exit 0
    ;;
  config)
    exit 0
    ;;
  push)
    remote="$1"
    log_path="${MOCK_GIT_LOG:?}"
    askpass="${GIT_ASKPASS:-}"
    if [ -z "$askpass" ]; then
      echo "askpass missing" >&2
      exit 1
    fi
    user1="$("$askpass" "Username for '$remote':")"
    pass1="$("$askpass" "Password for '$remote':")"
    user2="$("$askpass" "Username for '$remote': (again)")"
    pass2="$("$askpass" "Password for '$remote': (again)")"
    printf "remote:%s\nuser1:%s\npass1:%s\nuser2:%s\npass2:%s\n" "$remote" "$user1" "$pass1" "$user2" "$pass2" > "$log_path"
    exit 0
    ;;
  *)
    echo "unexpected command $cmd" >&2
    exit 1
    ;;
esac
`

	if err := os.WriteFile(mockGit, []byte(script), 0o700); err != nil {
		t.Fatalf("write mock git: %v", err)
	}

	mockLog := filepath.Join(dir, "git.log")
	t.Setenv("MOCK_GIT_LOG", mockLog)

	remote := store.RemoteDefinition{
		URI:      "https://example.com/repo.git",
		Username: "alice",
		Password: "s3cret",
	}

	origGit := gitBinary
	gitBinary = mockGit
	t.Cleanup(func() { gitBinary = origGit })

	if err := Push(dir, []store.RemoteDefinition{remote}); err != nil {
		t.Fatalf("Push error: %v", err)
	}

	data, err := os.ReadFile(mockLog)
	if err != nil {
		t.Fatalf("read mock log: %v", err)
	}

	got := strings.TrimSpace(string(data))
	want := strings.TrimSpace(`
remote:https://example.com/repo.git
user1:alice
pass1:s3cret
user2:alice
pass2:s3cret
`)
	if got != want {
		t.Fatalf("unexpected git push log:\n%s", got)
	}
}
