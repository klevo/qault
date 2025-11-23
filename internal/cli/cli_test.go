package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if exit, _, errOut := runCommand(t, dataDir, addEmailPrompter, "add", "email"); exit != 0 {
		t.Fatalf("add email failed: %s", errOut)
	}

	addBankPrompter := &fakePrompter{
		master:  []string{"pw"},
		secrets: []string{"beta-secret"},
	}
	if exit, _, errOut := runCommand(t, dataDir, addBankPrompter, "add", "bank"); exit != 0 {
		t.Fatalf("add bank failed: %s", errOut)
	}

	listPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	exit, listOut, errOut := runCommand(t, dataDir, listPrompter)
	if exit != 0 {
		t.Fatalf("list failed: %s", errOut)
	}

	if !strings.Contains(listOut, "email") || !strings.Contains(listOut, "bank") {
		t.Fatalf("list output missing expected entries: %q", listOut)
	}

	fetchPrompter := &fakePrompter{
		master: []string{"pw"},
	}
	exit, fetchOut, errOut := runCommand(t, dataDir, fetchPrompter, "email")
	if exit != 0 {
		t.Fatalf("fetch failed: %s", errOut)
	}

	if fetchOut != "alpha-secret" {
		t.Fatalf("unexpected fetch output: %q", fetchOut)
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
