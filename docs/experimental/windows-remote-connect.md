# Experimental: Windows remote connect (`nono-connect`)

Status: **exploration on a fork branch**. Not proposed for upstream. Before
this merges upstream it needs an accepted NEP, because it adds a new
platform and a new place where credentials are handled.

## Goal

Let a Windows user attach their **local terminal** to an agent session that
**runs on the nono enterprise platform**. Windows supplies only the keyboard
and screen. The agent, its PTY, and its sandbox all stay on the platform.
This is the client half of [remote-attach-v1](../protocols/remote-attach-v1.md)
and nothing else.

This avoids the open questions in
[NEP-0005](../../neps/0005-windows-enforcement-backend.md). Nothing runs
locally that needs confining, so no Windows enforcement backend is needed.

## Why a separate crate

`nono-cli` does not build on Windows today. `nix` and most modules assume
Unix, and the `nono` library has no Windows backend. Making the whole CLI
build on Windows just to reach `nono connect` would mean gating many modules
for a single command. Instead, `crates/nono-connect` is a small library and
binary that:

- does not depend on the `nono` sandbox library or `nono-cli`
- uses only `ring` for crypto (no `aws-lc-rs`), so it cross-compiles with
  mingw
- keeps the protocol, URL policy, detach matching and terminal handling in
  separate modules, so `nono-cli` could later use the same code instead of
  its own copy in `connect_client.rs`

Build for Windows from Linux:

```sh
apt-get install gcc-mingw-w64-x86-64
rustup target add x86_64-pc-windows-gnu
cargo build -p nono-connect --release --target x86_64-pc-windows-gnu
```

## What "local PTY" means on Windows

No ConPTY is created, because no local child process runs. The client
switches the console it is running in (Windows Terminal, or conhost on
Windows 10 1809 and later) into virtual-terminal mode:

| Console setting | Change |
|---|---|
| Input mode | clear `ECHO`, `LINE` and `PROCESSED` input and Quick Edit; set `ENABLE_VIRTUAL_TERMINAL_INPUT`. Ctrl-C reaches the remote PTY as `0x03`. Quick Edit is off because a mouse selection would freeze output and stall the attachment. |
| Output mode | set `ENABLE_VIRTUAL_TERMINAL_PROCESSING` and `DISABLE_NEWLINE_AUTO_RETURN` |
| Code pages | input and output both set to UTF-8 (65001) |

Implementation details:

- **Input** is read with `ReadConsoleW` and re-encoded as UTF-8. If a
  surrogate pair is split across two reads, it is carried over to the next
  read. `std::io::Stdin` is not used because it treats Ctrl-Z as end of file.
- **Output** is written with `WriteFile`. A UTF-8 character split across
  WebSocket frames is held back until its remaining bytes arrive.
- **Resize** is detected by polling the window size every 250 ms. Resize
  events are only delivered through `ReadConsoleInput`, which would compete
  with the input reader.
- **Restore**: the original modes and code pages are restored on drop. The
  client waits at most 2 s for queued output first, so a stalled console
  cannot keep raw mode on.
- **Ctrl-Break** detaches cleanly, the same as SIGTERM, SIGHUP, SIGINT or
  SIGQUIT on Unix. The hosted session keeps running.
- **Window close, logoff and shutdown**: the console control handler resets
  the VT state, then restores modes and code pages, before Windows ends the
  process.
- **Unsupported terminals**: mintty and MSYS pipes are not consoles, so
  `GetConsoleMode` fails on them. The client refuses to run there instead of
  half-working.

## Security posture (phase 1)

- **Credentials.** The only credential is a bearer token in
  `NONO_CONNECT_TOKEN`. `--token-file` works on Unix only, with a 0600 mode
  check. On Windows it is refused, because the client cannot yet verify the
  file's DACL. Accepting the file anyway would weaken the check without
  saying so.
- **Token handling.** Tokens must be visible ASCII. They are zeroized, and
  their `Debug` output is redacted. The `Authorization` header is marked
  sensitive. The HTTP and WebSocket libraries make their own copies of the
  header that are not zeroized; those copies live only for the request.
- **Token file (Unix).** The file is opened once, and the open handle is
  checked: it must be a regular file, mode 0600, at most 64 KiB. The read is
  capped at 64 KiB as well. A FIFO is refused without blocking.
- **Transport.** Connections use WSS or HTTPS. Both the session listing and
  the terminal WebSocket use the operating system's certificate verifier
  (`rustls-platform-verifier`; CryptoAPI on Windows), so they always agree,
  and roots deployed by enterprise policy work. Plain WS or HTTP is allowed
  only on loopback. There is no insecure TLS flag.
- **Where the token goes.** The token is sent only to the `--console` origin.
  Origins are compared by parsed host and port, never by string prefix. A
  direct `wss://` target must match `--console`. HTTP redirects are not
  followed.
- **Untrusted console data.** Session names, error messages and other console
  text are sanitized before they are printed. So is every error the client
  prints, because errors can quote console text. PTY output is passed through
  unchanged, as in `nono connect`. That means the hosted application can send
  escape sequences to the local terminal, including OSC 52 clipboard writes
  if the terminal allows them. On exit, the client resets keyboard, mouse,
  paste, focus and win32-input modes, and leaves the alternate screen.
- **Frame size.** Frames are capped at 4 MiB.

## Not yet done

1. **`nono login` on Windows.** This means storing the refresh token with
   DPAPI or Credential Manager. Ideally the DPoP key would be a
   non-exportable CNG key, backed by the TPM where one is available. This
   needs its own design, because it is the main new credential surface.
2. **Console discovery and enrolled-device authorization.** These depend on
   the device key store (`trust_keystore`).
3. **Windows token-file support,** with a check that the DACL grants access
   only to the owner, SYSTEM and Administrators.
4. **Configurable detach keys** (`--detach-keys` or config). Windows Terminal
   keybindings may intercept Ctrl-].
5. **Sharing code with `nono-cli`.** Move `nono connect` onto this crate and
   delete the duplicated protocol and detach code.
6. **Windows CI.** A `windows-latest` job that runs the unit tests, plus a
   smoke test against the mock console.

## Trying it

```sh
cargo run -p nono-connect --example mock_console -- 127.0.0.1:8765
NONO_CONNECT_TOKEN=test-token nono-connect --console http://127.0.0.1:8765 ps
NONO_CONNECT_TOKEN=test-token nono-connect --console http://127.0.0.1:8765 demo
```

In the mock session, type `exit` to end it with status 3, or press Ctrl-]
then `d` to detach.
