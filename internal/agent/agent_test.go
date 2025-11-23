package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketPathUsesDataDir(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "agent.sock")

	if got := SocketPath(dir); got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestServeFetchAndLock(t *testing.T) {
	dir := t.TempDir()
	sock := SocketPath(dir)

	rootKey := make([]byte, 32)
	ttl := time.Second

	done := make(chan struct{})
	go func() {
		_ = Serve(rootKey, ttl, sock)
		close(done)
	}()

	waitForSocket(t, sock)

	key, ok, err := FetchRootKey(sock)
	if err != nil {
		t.Fatalf("FetchRootKey error: %v", err)
	}
	if !ok {
		t.Fatalf("expected agent to be available")
	}
	if string(key) != string(rootKey) {
		t.Fatalf("unexpected key returned")
	}

	if err := Lock(sock); err != nil {
		t.Fatalf("Lock error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent did not stop after lock")
	}
}

func TestFetchRootKeyWhenAgentMissing(t *testing.T) {
	dir := t.TempDir()
	sock := SocketPath(dir)

	_, ok, err := FetchRootKey(sock)
	if err != nil {
		t.Fatalf("FetchRootKey error: %v", err)
	}
	if ok {
		t.Fatalf("expected agent to be unavailable")
	}
}

func waitForSocket(t *testing.T, sock string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s not created in time", sock)
}
