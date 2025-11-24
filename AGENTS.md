# Repository Guidelines

This repository hosts **qault**, a Go-based CLI password manager hardened for post-quantum cryptography. Keep contributions small, reviewed, and security-conscious.

## Project Structure & Module Organization
- Place the CLI entrypoint in `cmd/qault/`; keep reusable logic under `internal/` (e.g., `internal/crypto` for PQ primitives, `internal/store` for secret metadata, `internal/fs` for data-dir access). Reusable-but-public packages can live in `pkg/` if needed.
- Co-locate tests with source files (`foo.go` alongside `foo_test.go`); fixture data lives under `testdata/`.
- Integration/e2e tests live under `test/`.
- Use go >= 1.25
- After making changes to functionality update `README.md` if any of the user facing instructions changed. 

## Build, Test, and Development Commands
- `go test ./...` — run all unit tests.
- `go vet ./...` — catch common correctness issues.
- `gofmt -w ./...` — enforce canonical formatting before commits.
- `go run ./cmd/qault --help` — exercise the CLI during development; add flags for specific flows.
- When downloading dependencies or doing `go mod tidy`, give generous timeout to allow for the downloads to complete.

## Coding Style & Naming Conventions
- Follow standard Go style: tabs for indentation, `CamelCase` for exported identifiers, `snake_case` for file names when grouping variants, and short, imperative package doc comments.
- Keep packages cohesive; avoid stutter (`store.Secret`, not `store.StoreSecret`).
- Avoid panics in library code; return errors with context (`fmt.Errorf("unlock: %w", err)`).
- Do not log secrets or master passwords; prefer structured logs with redacted fields when logging is necessary.

## Testing Guidelines
- Prefer table-driven tests and `_test.go` files adjacent to code.
- Use deterministic inputs for crypto-related tests; isolate entropy use behind interfaces for mocking.
- Add regression tests for every bug fix; include coverage for error paths, especially around file I/O and git integration.

## Commit & Pull Request Guidelines
- History uses short, imperative summaries (`design`, `README`); keep that style: one focused change per commit.
- For PRs, include: goal/approach, notable trade-offs, test commands run, and any follow-up TODOs. Add screenshots or CLI transcripts when changing user-visible behavior.
- Reference related issues in descriptions; prefer small, reviewable PRs over large batches.

## Security & Configuration Tips
- Assume the data directory may sync via git; never commit real secrets and avoid writing plaintext to disk.
- Validate paths and permissions before touching the data directory; fail closed if storage is not writable.
- Keep dependencies minimal; prefer Go stdlib crypto and PQ primitives already in use. When needing extra packages, prefer `github.com/google` as source when available.
