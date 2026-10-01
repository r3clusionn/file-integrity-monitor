# File integrity monitor

`fim` records cryptographic hashes of the files you choose, then tells you when any of them is changed, added or removed, either on demand or live as it happens. For anyone who wants to know whether configuration files, binaries or scripts on a machine were altered since a known-good moment.

**Status:** v0.1.0, working on Windows. The Linux and macOS code paths use the same libraries but have not been run.

## Features

- Baseline of SHA-256 or BLAKE3 hashes, size, modification time and permissions, stored as JSON.
- `check` compares the files with the baseline and exits 1 if anything differs, so it fits in cron or a scheduled task.
- `watch` uses operating system notifications (`ReadDirectoryChangesW` on Windows, inotify on Linux) and reports changes within a debounce interval, to the terminal, a JSON-lines log, and an optional command.
- Optional HMAC-SHA256 signature on the baseline, so a tampered baseline is rejected instead of trusted.
- Exclude globs, a `--fast` mode that skips unchanged files by size and time, and an `accept` command to adopt a reviewed state as the new baseline.
- Files that cannot be read are reported as unreadable, not as removed.

## How to install

Needs a Rust toolchain.

```sh
git clone https://github.com/r3clusionn/file-integrity-monitor
cd file-integrity-monitor
cargo install --path .
```

## How to use

```sh
fim init /etc/myapp -b baseline.json --exclude "**/*.log" --key-file baseline.key
fim check -b baseline.json --key-file baseline.key
fim watch -b baseline.json --key-file baseline.key --log changes.jsonl
fim accept -b baseline.json --key-file baseline.key
```

Example, after editing one file, deleting one and adding one:

```text
$ fim check -b base.json
baseline base.json from 2026-10-01T08:10:21Z, 2 files
modified  C:/Users/me/etc/app.conf  (c7b6162cb07a -> 7a63fe6a9720, 9 -> 21 bytes)
added     C:/Users/me/etc/backdoor.sh  (7 bytes, d4d77a08677b)
removed   C:/Users/me/etc/users.db  (was c3a4756b369e)
1 modified, 1 added, 1 removed, 0 metadata, 0 unreadable
```

| Command or option | What it does |
|---|---|
| `init PATHS` | Hash the files and write the baseline. `--algo sha256\|blake3`, `-e GLOB`, `--force`. |
| `check` | Compare with the baseline. `--fast` trusts unchanged size and time, `--strict-time` also reports touches, `--json` for scripts. |
| `watch` | Live monitoring. `--debounce-ms N`, `--log FILE`, `--exec COMMAND`. |
| `accept` | Rescan and replace the baseline after you have reviewed a check. |
| `-b FILE`, `--key-file FILE` | Baseline path; HMAC key (signs on `init` and `accept`, verifies otherwise). |

`--exec` splits the command on spaces and runs it without a shell, with `FIM_KIND`, `FIM_PATH`
and `FIM_HASH` in its environment, so a hostile file name cannot inject anything into the command.
Exit status for `check`: 0 clean, 1 changes found, 2 error.

## Threat model

`fim` detects modification of files by comparing them with a baseline taken while the machine was
in a state you trusted. What it covers and what it does not:

- It detects changes to content, additions, removals and permission changes, including edits that
  keep the size the same. It does not detect a change that is made and reverted between two checks;
  `watch` narrows that window to the debounce interval.
- An attacker who can write the baseline can make it say anything. Sign it with `--key-file` and
  keep the key somewhere the monitored machine cannot rewrite. Without a key, `check` trusts the
  baseline file as it is.
- An attacker with kernel or administrator control can hide changes from any user-space tool,
  `fim` included. It is a tripwire, not a defence against a fully compromised host.
- `--fast` assumes a file with an unchanged size and modification time is unchanged. Anyone who can
  set modification times can defeat it, and the tests show a same-size edit with a restored time
  passing a fast check while the full check catches it. Use full checks for security decisions.
- Notifications only name the paths to look at. Each named path is read and hashed again, so a
  dropped or repeated event cannot hide a change the next event on that path would show.
- Symlinks are not followed or hashed; the number skipped is reported.

## How it works

`src/baseline.rs` builds a snapshot (a parallel walk, with every file hashed on a rayon pool) and
diffs two snapshots. `src/watch.rs` turns notifications into a set of paths, waits for the debounce
interval, then re-reads each path and compares it with the last known state, which starts as the
baseline and follows the files afterwards. Files that are locked or half-written are retried a few
times. If the operating system drops events, the whole tree is compared.

## Verification and benchmarks

Hashes were checked against PowerShell's `Get-FileHash` on a set of generated files (no
mismatches) and against the standard test vectors for SHA-256 and BLAKE3 in the tests.

Timing on Windows 11, Intel Core i9-14900KF (24 threads), NVMe SSD, warm cache, with the tree
`C:\Projects\portfolio\projects`: 17,797 files, 4.05 GB. Median of 3 runs after a warm-up.

| Command | Time | Throughput |
|---|---|---|
| `init`, SHA-256 | 1.18 s | 3.4 GB/s |
| `init`, BLAKE3 | 1.17 s | 3.5 GB/s |
| `check`, SHA-256 (full) | 1.17 s | 3.5 GB/s |
| `check`, BLAKE3 (full) | 1.14 s | 3.6 GB/s |
| `check --fast`, nothing changed | 0.15 s | stat only |

The two algorithms are equal here, so on this machine the limit is not the hash function. Results
for cold files read from disk will be lower.

## Tests

`cargo test` runs 23 tests: known-answer hashes, files larger than the read buffer, snapshots and
diffs, same-size edits, metadata-only changes, fast mode, exclusions, signing and tampering,
baseline load and save, a locked file reported as unreadable (Windows), and the command line. Three tests start `fim watch` as a child process,
change real files and wait for the reports (modified, added, removed, new directory, ignored
files, and the `--exec` command on Windows), with a timeout.

## License

MIT (see `LICENSE`).
