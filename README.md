# qault

Personal, post-quantum-conscious keychain/password manager written in Go using standard library crypto.

This project is not intended for production use and is published for research purposes only.

Command line interface inspired by [pass](https://www.passwordstore.org/).

## 🔍 Motivation

I want a simple replacement for cloud-based password managers from big vendors. I’d like to recover access to all my services even if I lose every device, by remembering one master password and reaching a remote Git repository.

While at it, I aim for post-quantum-safe storage/encryption, assuming AES-GCM with an Argon2id-derived key holds up—something we can’t verify until quantum computers are commonplace.

## 🎯 Goals

* Command-line interface that follows simple UNIX philosophy.
* Unlock with a master password.
* Favor post-quantum-friendly crypto from Go’s standard library.
* Optional agent mode to keep the vault unlocked briefly.
* TOTP MFA Authentication support.

## 🧠 Design

* Secrets plus metadata are stored as encrypted JSON files in the data directory; filenames are UUID v7 from `github.com/google/uuid`.
* Secret JSON layout: `{name: [string], secret, created_at, updated_at}`; `name` preserves the ordered path of labels you provide.
* Data directory lives under `$XDG_DATA_HOME/qault` if set, otherwise `$HOME/.qault`.
* Password-based key derivation uses [Argon2id](https://pkg.go.dev/golang.org/x/crypto/argon2#hdr-Argon2id) with high memory/time cost and CPU-tuned parallelism to slow offline attacks; a strong master password is still required.

## 🛠️ Command Line Interface (CLI)

### Vault initialization

```sh
qault init
```

1. Create the data directory if needed.
2. If `.lock` is missing, prompt for a non-empty master password twice, generate salt, encrypt the lock value, and write `.lock`.

Outputs the location of the data directory to stdout.

### Adding secrets to the vault

```sh
qault add NAME...
```

Name components are required; each argument becomes one element in the stored name array (quote an argument to embed spaces inside a single element).

1. Ask for the master password and validate by decrypting `.lock`; fail with exit code 1 if it’s wrong.
2. Prompt for the secret value (non-empty).
3. Generate a UUID v7, create the secret JSON payload, encrypt it with the root key, and save it.
4. Confirm the secret was saved under the provided name path.

#### Adding TOTP MFA authentication to existing secret

```sh
qault add NAME... -o [PATH_TO_QR_CODE_IMAGE]
```

Adds the OTP authentication object to secret JSON.

### Listing secrets

```sh
qault
```

1. Ask for the master password and validate by decrypting `.lock`; fail with exit code 1 if it’s wrong.
2. Decrypt all UUID v7 files in the data directory and print each `name` array on its own line, space-separated; any element containing whitespace is wrapped in double quotes. When run in a terminal and the name has multiple components, non-leaf components alternate blue/teal for readability; entries with OTP append a faint `-o` marker (plain `-o` when piped). Exit with code 1 if any decrypt fails.

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

### Unlocking the vault for 5 minutes (agent mode)

```sh
qault unlock
```

Upon entering and validating the master key, spawn an agent that caches the derived encryption key and listens on a socket in the data dir. The agent self-terminates after 5 minutes. You can terminate it manually to lock your vault with:

```sh
qault lock
```

## 🧪 Development

### Running the CLI

```sh
go run ./cmd/qault
```

### Running tests

```sh
go test ./...
```
