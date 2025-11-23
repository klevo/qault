package agent

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

type request struct {
	Action string `json:"action"`
}

type response struct {
	RootKey   string `json:"root_key,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

func Serve(rootKey []byte, ttl time.Duration, sockPath string) error {
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	_ = os.Chmod(sockPath, 0o600)

	expiry := time.Now().Add(ttl)

	for {
		if time.Now().After(expiry) {
			return nil
		}

		if err := ln.(*net.UnixListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}

		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed) {
				continue
			}
			return err
		}

		go func(c net.Conn) {
			defer c.Close()

			var req request
			if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
				return
			}

			switch req.Action {
			case "get":
				expiry = time.Now().Add(ttl)
				resp := response{
					RootKey:   base64.StdEncoding.EncodeToString(rootKey),
					ExpiresAt: expiry.Unix(),
				}
				_ = json.NewEncoder(c).Encode(resp)
			case "lock":
				_ = json.NewEncoder(c).Encode(response{})
				_ = ln.Close()
			default:
				_ = json.NewEncoder(c).Encode(response{Error: "unknown action"})
			}
		}(conn)
	}
}

func FetchRootKey(sockPath string) ([]byte, bool, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, nil
	}
	defer conn.Close()

	req := request{Action: "get"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, false, err
	}

	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, false, err
	}
	if resp.Error != "" {
		return nil, false, fmt.Errorf("%s", resp.Error)
	}

	key, err := base64.StdEncoding.DecodeString(resp.RootKey)
	if err != nil {
		return nil, false, err
	}

	return key, true, nil
}

func Lock(sockPath string) error {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	req := request{Action: "lock"}
	return json.NewEncoder(conn).Encode(req)
}

func SocketPath(dir string) string {
	return filepath.Join(dir, "agent.sock")
}
