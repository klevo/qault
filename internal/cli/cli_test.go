package cli

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

type fakePrompter struct {
	master    []string
	newMaster []string
	secrets   []string
}

func (p *fakePrompter) MasterPassword() (string, error) {
	return pop(&p.master)
}

func (p *fakePrompter) NewMasterPassword() (string, error) {
	return pop(&p.newMaster)
}

func (p *fakePrompter) SecretValue() (string, error) {
	return pop(&p.secrets)
}

func (p *fakePrompter) SecretValueWithPrompt(_ string) (string, error) {
	return pop(&p.secrets)
}

func pop(values *[]string) (string, error) {
	if len(*values) == 0 {
		return "", errors.New("no input provided")
	}
	v := (*values)[0]
	*values = (*values)[1:]
	return v, nil
}

func runCommand(t *testing.T, dataDir string, prompter Prompter, args ...string) (int, string, string) {
	t.Helper()

	t.Setenv("XDG_DATA_HOME", dataDir)
	t.Setenv("QAULT_INLINE_AGENT", "1")

	var out bytes.Buffer
	var err bytes.Buffer

	c := &CLI{
		Out:      &out,
		Err:      &err,
		Prompter: prompter,
	}

	exit := c.Run(args)

	return exit, out.String(), err.String()
}

func TestInitCreatesLockFile(t *testing.T) {
	dataDir := t.TempDir()

	prompter := &fakePrompter{
		newMaster: []string{"strong-password", "strong-password"},
	}

	exit, _, errOut := runCommand(t, dataDir, prompter, "init")
	if exit != 0 {
		t.Fatalf("init returned exit code %d, stderr: %s", exit, errOut)
	}

	lockPath := filepath.Join(dataDir, "qault", ".lock")
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file not created: %v", err)
	}
}

func TestAddListAndFetch(t *testing.T) {
	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addEmailPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"alpha-secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addEmailPrompter, "add", "personal", "email"); exit != 0 {
		t.Fatalf("add email failed: %s", errOut)
	}

	addBankPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"beta-secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addBankPrompter, "add", "work account", "bank"); exit != 0 {
		t.Fatalf("add bank failed: %s", errOut)
	}

	listPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	exit, listOut, errOut := runCommand(t, dataDir, listPrompter)
	if exit != 0 {
		t.Fatalf("list failed: %s", errOut)
	}

	if !strings.Contains(listOut, "personal email") || !strings.Contains(listOut, "\"work account\" bank") {
		t.Fatalf("list output missing expected entries: %q", listOut)
	}

	fetchPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	exit, fetchOut, errOut := runCommand(t, dataDir, fetchPrompter, "personal", "email")
	if exit != 0 {
		t.Fatalf("fetch failed: %s", errOut)
	}

	if fetchOut != "alpha-secret" {
		t.Fatalf("unexpected fetch output: %q", fetchOut)
	}

	fetchBankPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	exit, fetchBankOut, errOut := runCommand(t, dataDir, fetchBankPrompter, "WORK ACCOUNT", "BANK")
	if exit != 0 {
		t.Fatalf("fetch with whitespace name failed: %s", errOut)
	}
	if fetchBankOut != "beta-secret" {
		t.Fatalf("unexpected fetch output for bank: %q", fetchBankOut)
	}
}

func TestAddFailsOnDuplicateNameCaseInsensitive(t *testing.T) {
	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	firstPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"secret-1"},
	}
	if exit, _, errOut := runCommand(t, dataDir, firstPrompter, "add", "shared", "login"); exit != 0 {
		t.Fatalf("first add failed: %s", errOut)
	}

	secondPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"secret-2"},
	}
	exit, _, errOut := runCommand(t, dataDir, secondPrompter, "add", "SHARED", "LOGIN")
	if exit == 0 {
		t.Fatalf("expected duplicate add to fail")
	}
	if !strings.Contains(errOut, "Name already exists") {
		t.Fatalf("expected duplicate name message, got: %q", errOut)
	}
}

func TestFetchWithIncorrectPassword(t *testing.T) {
	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "email"); exit != 0 {
		t.Fatalf("add failed: %s", errOut)
	}

	fetchPrompter := &fakePrompter{
		master: []string{"wrong"},
	}
	exit, _, errOut := runCommand(t, dataDir, fetchPrompter, "email")
	if exit == 0 {
		t.Fatalf("expected fetch to fail with incorrect password")
	}

	if !strings.Contains(errOut, "Incorrect master password") {
		t.Fatalf("expected incorrect password message, got: %q", errOut)
	}
}

func TestUnlockAndLockFlow(t *testing.T) {
	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "email"); exit != 0 {
		t.Fatalf("add failed: %s", errOut)
	}

	unlockPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, unlockPrompter, "unlock"); exit != 0 {
		t.Fatalf("unlock failed: %s", errOut)
	}

	agentFetchPrompter := &fakePrompter{
		master: []string{"unused"},
	}
	exit, fetchOut, errOut := runCommand(t, dataDir, agentFetchPrompter, "email")
	if exit != 0 {
		t.Fatalf("fetch via agent failed: %s", errOut)
	}
	if fetchOut != "secret" {
		t.Fatalf("unexpected fetch output via agent: %q", fetchOut)
	}

	if exit, _, errOut := runCommand(t, dataDir, &fakePrompter{}, "lock"); exit != 0 {
		t.Fatalf("lock failed: %s", errOut)
	}

	wrongPrompter := &fakePrompter{
		master: []string{"wrong"},
	}
	exit, _, errOut = runCommand(t, dataDir, wrongPrompter, "email")
	if exit == 0 {
		t.Fatalf("expected fetch to fail with incorrect password after locking")
	}
	if !strings.Contains(errOut, "Incorrect master password") {
		t.Fatalf("expected incorrect password message after locking, got: %q", errOut)
	}

	correctPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	exit, fetchOut, errOut = runCommand(t, dataDir, correctPrompter, "email")
	if exit != 0 {
		t.Fatalf("fetch after relock failed: %s", errOut)
	}
	if fetchOut != "secret" {
		t.Fatalf("unexpected fetch output after relock: %q", fetchOut)
	}
}

func TestAddOTPAndFetchCode(t *testing.T) {
	originalNow := timeNow
	timeNow = func() time.Time { return time.Unix(59, 0).UTC() }
	defer func() { timeNow = originalNow }()

	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "email"); exit != 0 {
		t.Fatalf("add secret failed: %s", errOut)
	}

	uri := "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30"
	qrPath := filepath.Join(dataDir, "qr.png")
	if err := writeQRImage(qrPath, uri); err != nil {
		t.Fatalf("write qr: %v", err)
	}

	addOtpPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addOtpPrompter, "add", "email", "-o", qrPath); exit != 0 {
		t.Fatalf("add otp failed: %s", errOut)
	}

	fetchOtpPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	exit, out, errOut := runCommand(t, dataDir, fetchOtpPrompter, "email", "-o")
	if exit != 0 {
		t.Fatalf("fetch otp failed: %s", errOut)
	}
	if strings.TrimSpace(out) != "287082" {
		t.Fatalf("unexpected otp output: %q", out)
	}
}

func TestRemoveSecret(t *testing.T) {
	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "personal", "email"); exit != 0 {
		t.Fatalf("add failed: %s", errOut)
	}

	removePrompter := &fakePrompter{
		master: []string{"pw"},
	}
	exit, out, errOut := runCommand(t, dataDir, removePrompter, "rm", "PERSONAL", "EMAIL")
	if exit != 0 {
		t.Fatalf("rm failed: %s", errOut)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("expected no removal message, got: %q", out)
	}

	listPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, listOut, errOut := runCommand(t, dataDir, listPrompter); exit != 0 {
		t.Fatalf("list failed: %s", errOut)
	} else if strings.Contains(listOut, "personal") {
		t.Fatalf("expected secret to be removed, got list: %q", listOut)
	}

	fetchPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	exit, _, errOut = runCommand(t, dataDir, fetchPrompter, "personal", "email")
	if exit == 0 {
		t.Fatalf("expected fetch to fail after removal")
	}
	if !strings.Contains(errOut, "Secret not found") {
		t.Fatalf("unexpected fetch error after removal: %q", errOut)
	}
}

func TestAddWithEditor(t *testing.T) {
	dataDir := t.TempDir()
	editor := writeEditorScript(t, "editor-secret")
	t.Setenv("EDITOR", editor)

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "-e", "personal", "email"); exit != 0 {
		t.Fatalf("add failed: %s", errOut)
	}

	fetchPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, out, errOut := runCommand(t, dataDir, fetchPrompter, "personal", "email"); exit != 0 {
		t.Fatalf("fetch failed: %s", errOut)
	} else if out != "editor-secret" {
		t.Fatalf("unexpected fetch output: %q", out)
	}
}

func TestRecentListsByUpdated(t *testing.T) {
	originalNow := timeNow
	clock := []time.Time{
		time.Unix(1, 0).UTC(), // created foo
		time.Unix(2, 0).UTC(), // created bar
		time.Unix(3, 0).UTC(), // edit foo
	}
	idx := 0
	timeNow = func() time.Time {
		if idx >= len(clock) {
			return clock[len(clock)-1]
		}
		v := clock[idx]
		idx++
		return v
	}
	defer func() { timeNow = originalNow }()

	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addFoo := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"foo-secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addFoo, "add", "foo"); exit != 0 {
		t.Fatalf("add foo failed: %s", errOut)
	}

	addBar := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"bar-secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addBar, "add", "bar"); exit != 0 {
		t.Fatalf("add bar failed: %s", errOut)
	}

	editFoo := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"foo-updated"},
	}
	if exit, _, errOut := runCommand(t, dataDir, editFoo, "edit", "foo"); exit != 0 {
		t.Fatalf("edit foo failed: %s", errOut)
	}

	recentPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, out, errOut := runCommand(t, dataDir, recentPrompter, "recent"); exit != 0 {
		t.Fatalf("recent failed: %s", errOut)
	} else {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 lines, got %d: %q", len(lines), out)
		}
		if !strings.Contains(lines[0], "foo") || !strings.Contains(lines[1], "bar") {
			t.Fatalf("recent not ordered by updated time: %q", out)
		}
		if !strings.HasPrefix(lines[0], "1970-01-01T00:00:03Z") {
			t.Fatalf("expected timestamp prefix, got: %q", lines[0])
		}
	}
}

func TestEditSecret(t *testing.T) {
	originalNow := timeNow
	timeNow = func() time.Time { return time.Unix(1000, 0).UTC() }
	defer func() { timeNow = originalNow }()

	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"first-secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "personal", "email"); exit != 0 {
		t.Fatalf("add failed: %s", errOut)
	}

	timeNow = func() time.Time { return time.Unix(2000, 0).UTC() }
	editPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"updated-secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, editPrompter, "edit", "PERSONAL", "EMAIL"); exit != 0 {
		t.Fatalf("edit failed: %s", errOut)
	}

	fetchPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, out, errOut := runCommand(t, dataDir, fetchPrompter, "personal", "email"); exit != 0 {
		t.Fatalf("fetch failed: %s", errOut)
	} else if out != "updated-secret" {
		t.Fatalf("unexpected fetch output after edit: %q", out)
	}

	// Ensure listing shows name unchanged
	listPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, listOut, errOut := runCommand(t, dataDir, listPrompter); exit != 0 {
		t.Fatalf("list failed: %s", errOut)
	} else if !strings.Contains(listOut, "personal email") {
		t.Fatalf("list missing updated entry: %q", listOut)
	}
}

func TestChangeMasterPassword(t *testing.T) {
	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"oldpw", "oldpw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master:  []string{"oldpw"},
		secrets: []string{"secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "email"); exit != 0 {
		t.Fatalf("add failed: %s", errOut)
	}

	changePrompter := &fakePrompter{
		master:    []string{"oldpw"},
		newMaster: []string{"newpw", "newpw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, changePrompter, "change-master-password"); exit != 0 {
		t.Fatalf("change-master-password failed: %s", errOut)
	}

	oldFetchPrompter := &fakePrompter{
		master: []string{"oldpw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, oldFetchPrompter, "email"); exit == 0 {
		t.Fatalf("expected fetch with old password to fail")
	} else if !strings.Contains(errOut, "Incorrect master password") {
		t.Fatalf("unexpected error with old password: %q", errOut)
	}

	newFetchPrompter := &fakePrompter{
		master: []string{"newpw"},
	}
	if exit, out, errOut := runCommand(t, dataDir, newFetchPrompter, "email"); exit != 0 {
		t.Fatalf("fetch with new password failed: %s", errOut)
	} else if out != "secret" {
		t.Fatalf("unexpected fetch output with new password: %q", out)
	}
}

func TestChangeMasterPasswordRejectsWrongCurrent(t *testing.T) {
	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"oldpw", "oldpw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master:  []string{"oldpw"},
		secrets: []string{"secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "email"); exit != 0 {
		t.Fatalf("add failed: %s", errOut)
	}

	changePrompter := &fakePrompter{
		master:    []string{"wrong"},
		newMaster: []string{"newpw", "newpw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, changePrompter, "change-master-password"); exit == 0 {
		t.Fatalf("expected change-master-password to fail with wrong current password")
	} else if !strings.Contains(errOut, "Incorrect master password") {
		t.Fatalf("unexpected error: %q", errOut)
	}

	fetchPrompter := &fakePrompter{
		master: []string{"oldpw"},
	}
	if exit, out, errOut := runCommand(t, dataDir, fetchPrompter, "email"); exit != 0 {
		t.Fatalf("fetch with original password failed after failed change: %s", errOut)
	} else if out != "secret" {
		t.Fatalf("unexpected fetch output after failed change: %q", out)
	}
}

func TestEditSecretWithEditor(t *testing.T) {
	dataDir := t.TempDir()
	editor := writeEditorScript(t, "edited-via-editor")
	t.Setenv("EDITOR", editor)

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"first-secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "personal", "email"); exit != 0 {
		t.Fatalf("add failed: %s", errOut)
	}

	editPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, editPrompter, "edit", "-e", "personal", "email"); exit != 0 {
		t.Fatalf("edit failed: %s", errOut)
	}

	fetchPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, out, errOut := runCommand(t, dataDir, fetchPrompter, "personal", "email"); exit != 0 {
		t.Fatalf("fetch failed: %s", errOut)
	} else if out != "edited-via-editor" {
		t.Fatalf("unexpected fetch output after edit: %q", out)
	}
}

func TestMoveSecret(t *testing.T) {
	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	addPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"alpha"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addPrompter, "add", "personal", "email"); exit != 0 {
		t.Fatalf("add failed: %s", errOut)
	}

	movePrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, movePrompter, "mv", "PERSONAL", "EMAIL", "--to", "personal", "login"); exit != 0 {
		t.Fatalf("mv failed: %s", errOut)
	}

	listPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, listOut, errOut := runCommand(t, dataDir, listPrompter); exit != 0 {
		t.Fatalf("list failed: %s", errOut)
	} else if !strings.Contains(listOut, "personal login") {
		t.Fatalf("expected renamed entry in list, got: %q", listOut)
	} else if strings.Contains(listOut, "personal email") {
		t.Fatalf("old name still present in list: %q", listOut)
	}

	fetchPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, out, errOut := runCommand(t, dataDir, fetchPrompter, "personal", "login"); exit != 0 {
		t.Fatalf("fetch new name failed: %s", errOut)
	} else if out != "alpha" {
		t.Fatalf("unexpected fetch output: %q", out)
	}

	fetchOldPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, fetchOldPrompter, "personal", "email"); exit == 0 {
		t.Fatalf("expected old name fetch to fail")
	} else if !strings.Contains(errOut, "Secret not found") {
		t.Fatalf("unexpected error for old fetch: %q", errOut)
	}
}

func TestMoveSecretConflicts(t *testing.T) {
	dataDir := t.TempDir()

	initPrompter := &fakePrompter{
		newMaster: []string{"pw", "pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, initPrompter, "init"); exit != 0 {
		t.Fatalf("init failed: %s", errOut)
	}

	firstPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"one"},
	}
	if exit, _, errOut := runCommand(t, dataDir, firstPrompter, "add", "foo"); exit != 0 {
		t.Fatalf("add first failed: %s", errOut)
	}

	secondPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"two"},
	}
	if exit, _, errOut := runCommand(t, dataDir, secondPrompter, "add", "bar"); exit != 0 {
		t.Fatalf("add second failed: %s", errOut)
	}

	movePrompter := &fakePrompter{
		master: []string{"pw"},
	}
	if exit, _, errOut := runCommand(t, dataDir, movePrompter, "mv", "foo", "--to", "BAR"); exit == 0 {
		t.Fatalf("expected move conflict to fail")
	} else if !strings.Contains(errOut, "Name already exists") {
		t.Fatalf("unexpected conflict error: %q", errOut)
	}
}

func writeQRImage(path, payload string) error {
	writer := qrcode.NewQRCodeWriter()
	matrix, err := writer.Encode(payload, gozxing.BarcodeFormat_QR_CODE, 200, 200, nil)
	if err != nil {
		return err
	}

	img := image.NewGray(image.Rect(0, 0, matrix.GetWidth(), matrix.GetHeight()))
	for y := 0; y < matrix.GetHeight(); y++ {
		for x := 0; x < matrix.GetWidth(); x++ {
			if matrix.Get(x, y) {
				img.SetGray(x, y, color.Gray{Y: 0})
			} else {
				img.SetGray(x, y, color.Gray{Y: 255})
			}
		}
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return png.Encode(file, img)
}

func writeEditorScript(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "editor.sh")
	script := "#!/bin/sh\nprintf \"%s\" > \"$1\"\n"
	if err := os.WriteFile(path, []byte(fmt.Sprintf(script, content)), 0o700); err != nil {
		t.Fatalf("write editor script: %v", err)
	}
	return path
}
