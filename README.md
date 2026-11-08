# wmng

UNIX-style Windows management applets. PowerShell's replacement surface for
system administration: UNIX command shape, Windows mechanisms, no emulation.

**Status:** D1 (ACL), power actions, and the D2 process set (ps/pgrep/
pkill/kill) are implemented; services are the next P0 block. Nothing here
is stable.

## Design contract

The governing documents are **[../DESIGN.md](../DESIGN.md)** ("UNIX style,
Windows semantics") and **[DESIGN.md](DESIGN.md)** (domain plan, API paths,
per-domain pitfalls). Read them before adding anything.

The one-line version:

- Style (command names, options, output, exit codes) is UNIX — FreeBSD is
  the reference implementation wherever it has one.
- Semantics (mechanisms, capabilities, limits) are native Win32, reached
  through `windows-sys`. No emulation, no fake POSIX.
- A command whose entire referent does not exist on Windows does not exist
  here either — no aliases, no refusal stubs (`halt` is the worked example).
- Options of an existing command that name a missing mechanism are refused
  with an explanation (`setfacl -d`).

## Applets

| Applet | Domain | Replaces |
|---|---|---|
| `getfacl` | D1 ACL | `Get-Acl`, `icacls` (read) |
| `setfacl` | D1 ACL | `Set-Acl`, `icacls` (write) |
| `shutdown` / `reboot` / `poweroff` | power | `Stop-Computer`, `Restart-Computer`, `shutdown.exe` |
| `ps` / `pgrep` / `pkill` / `kill` | D2 processes | `Get-Process`, `Stop-Process` (procstat pending) |

Multi-call binary: the applet is the basename of argv[0] — hard-link
`wmng.exe` to `getfacl.exe` etc. and put those on PATH. `wmng --list` shows
what exists.

## Layers

```
src/lib.rs        model.rs ops.rs time.rs   pure Rust, unit-tested on WSL
src/main.rs       applets/                  CLI parsing, output
                  providers/                the ONLY Win32 calls
tests/            integration (Win32 round trips) + diff harness
```

The layering invariant: `src/lib.rs` and everything under it must stay free
of Win32 imports — that is what keeps the model testable off-Windows.

## Build and test

```
cargo build --release
cargo test            # unit + integration
python3 tests/diff/run.py   # differential vs PowerShell Get-Acl
```

`windows-sys` is the only dependency.

## Sources note

`reference/freebsd/` holds the FreeBSD C sources used as the behavioural
reference for the ACL grammar and algorithms (BSD-2-Clause, notices intact;
see `reference/freebsd/NOTICE`). wmng code is a fresh implementation.
