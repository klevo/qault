# TUI implementation

This document describes how to transform `qault` into a TUI application.

1. Add package `github.com/charmbracelet/bubbletea v1.3.10`.
2. On launching the program without arguments, launch the TUI application. All TUI logic should be placed into it's own package, don't pollute the current `cli.go` with TUI related helpers.
3. The first, full screen, asks for master password to unlock the secrets. Keep the decrypted secrets list in the application state / memory.
4. After successful unlock with master password, screen switches to a filterable list view of secrets. Use [Fancy List example](https://github.com/charmbracelet/bubbletea/tree/main/examples/list-fancy) as a basis for this.
