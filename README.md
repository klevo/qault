# qault

Personal, post-quantum-conscious keychain/password manager written in Go, with a beautiful TUI and using standard library crypto.

<img width="1112" height="699" alt="qault-tui" src="https://github.com/user-attachments/assets/b705c2e5-14b0-4919-9f13-04b9f099beaa" />

This project is not intended for production use and is published for research purposes only.

## 🧭 Installation (macOS, Linux)

Install via [Homebrew](https://brew.sh/) (yup, you can use it on Linux too):

```sh
brew install klevo/qault/qault
```

### Build from source (needs Go 1.25+)

```sh
git clone https://github.com/klevo/qault.git
cd qault
go build -ldflags "-s -w" ./cmd/qault
./qault version
```

## 🔍 Motivation

I want a simple replacement for cloud-based password managers from big vendors. I’d like to recover access to all my services even if I lose every device, by remembering one master password and reaching a remote Git repository.

While at it, I aim for post-quantum-safe storage/encryption, assuming AES-GCM with an Argon2id-derived key holds up—something we can’t verify until quantum computers are commonplace.

## 🎯 Goals

* Command-line interface that follows simple UNIX philosophy.
* Unlock with a master password.
* Favor post-quantum-friendly crypto from Go’s standard library.
* TOTP MFA Authentication support.

## 🧠 Design

* Secrets plus metadata are stored as encrypted JSON files in the data directory; filenames are UUID v7 from `github.com/google/uuid`.
* Secret JSON layout: `{name: [string], secret, created_at, updated_at}`; `name` preserves the ordered path of labels you provide.
* Data directory lives under `$XDG_DATA_HOME/qault` if set, otherwise `$HOME/.qault`.
* Password-based key derivation uses [Argon2id](https://pkg.go.dev/golang.org/x/crypto/argon2#hdr-Argon2id) with high memory/time cost and CPU-tuned parallelism to slow offline attacks; a strong master password is still required.

## 🛠️ Command Line Interface (CLI)

Running `qault` with no arguments launches the interactive TUI. Provide a subcommand to use the CLI flows below.

### Vault initialization

```sh
qault init
```

1. Create the data directory if needed.
2. If `.lock` is missing, prompt for a non-empty master password twice, generate salt, encrypt the lock value, and write `.lock`.

Outputs the location of the data directory to stdout.

### Adding secrets to the vault

```sh
qault add NAME... [-e]
```

Name components are required; each argument becomes one element in the stored name array (quote an argument to embed spaces inside a single element).

1. Ask for the master password and validate by decrypting `.lock`; fail with exit code 1 if it’s wrong.
2. Prompt for the secret value (non-empty) or open `$EDITOR` when `-e` is provided (initially empty).
3. Generate a UUID v7, create the secret JSON payload, encrypt it with the root key, and save it.
4. Confirm the secret was saved under the provided name path.

### Editing an existing secret

```sh
qault edit NAME... [-e]
```

Replaces the secret value (prompted as `New secret:` or edited via `$EDITOR` when `-e` is used) for the matched entry without altering the name or OTP.

#### Adding TOTP MFA authentication to existing secret

```sh
qault add NAME... -o [PATH_TO_QR_CODE_IMAGE]
```

Adds the OTP authentication object to secret JSON.

### Removing a secret

```sh
qault rm NAME...
```

Deletes the secret that matches the provided name components (case-insensitive).

### Renaming a secret

```sh
qault mv OLD... --to NEW...
```

Renames the secret from the old name components to the new ones (case-insensitive match on the source, destination must not already exist).

### Changing the master password

```sh
qault change-master-password
```

Asks for the current master password, then prompts twice for the new one, and re-encrypts every secret plus the lock file with the new key. Fails if the current password is incorrect.

### Listing secrets

```sh
qault list
```

1. Ask for the master password and validate by decrypting `.lock`; fail with exit code 1 if it’s wrong.
2. Decrypt all UUID v7 files in the data directory and print each `name` array on its own line, space-separated; any element containing whitespace is wrapped in double quotes. When run in a terminal and the name has multiple components, non-leaf components alternate blue/teal for readability; entries with OTP append a faint `-o` marker (plain `-o` when piped). Exit with code 1 if any decrypt fails.

### Listing secrets by recent update

```sh
qault recent
```

Same output format as `qault list` but sorted by `updated_at` descending, and each line is prefixed with the `updated_at` timestamp (faint in terminal).

### Fetching a secret

```sh
qault NAME...
```

1. Ask for the master password and validate by decrypting `.lock`; fail with exit code 1 if it’s wrong.
2. Decrypt UUID v7 files until a case-insensitive match for the provided name elements is found, then print `secret` and exit.
3. If the name is not found, exit with code 1 and note it on stderr.

#### Fetching an OTP

```sh
qault NAME... -o
```

Outputs the OTP if present; otherwise notify the user and exit with code 1.

## 🔗 Remote sync

Background git pushes run after each commit when the vault contains one or more remote definitions. Add a secret whose name starts with `qault`, `remote`, followed by the remote URI and HTTP username (each on separate line); use the secret value as the password. For example:

```
qault
remote
https://example.com/qault-vault.git
username@example.com
```

When git asks for HTTP credentials during push, qault feeds the stored username and password—even if git prompts multiple times during a push. Remove or rename the remote entry to stop pushing to that URI.

The TUI will discover all such entries (case-insensitive on `qault`/`remote`), aggregate the URIs, and push `HEAD` to each after add/edit/delete operations.

## 🧪 Development

### Running the CLI

```sh
go run ./cmd/qault
```

Run `go run ./cmd/qault -- list` (or any other subcommand) to exercise the CLI directly instead of starting the TUI.

### Running tests

```sh
go test ./...
```

### HTTP git server for testing pushes

Build and run a minimal HTTP git server with basic auth:

```sh
docker build -t qault/git-http ./server

BCRYPT_PASSWORD=$(htpasswd -nbBC 12 alice 'plain-password' | cut -d: -f2)
docker run -p 8080:8080 \
  -e USERNAME=alice \
  -e BCRYPT_PASSWORD="$BCRYPT_PASSWORD" \
  -e REPO_NAME=qault-vault \
  -v "$(pwd)/git-data:/var/lib/git" \
  qault/git-http
```

Clone or push with your plain password; the server checks it against the bcrypt hash you supplied:

```sh
git clone http://alice:plain-password@localhost:8080/qault-vault.git
```

The container logs (`docker logs`) surface nginx access/error logs. Basic auth endpoints are rate limited per client IP (5 req/minute with a burst of 10) to slow brute-force attempts.

Mount `/var/lib/git` to persist the bare repository between runs. The container initializes the repo only when the target directory is missing or empty, so existing data on the mount is left intact.
