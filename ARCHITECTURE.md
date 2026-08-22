# Architecture

## The shape of the thing

```
   cred (CLI)                    Import-Module Cred
   bin/cred.ps1                  src/Cred/Public/*.ps1
        │                                │
        └────────────┬───────────────────┘
                     │   one set of behaviour, two front ends
        ┌────────────▼───────────────┐
        │  Config.ps1   Store.ps1    │   projects, definitions, values,
        │  Secrets.ps1  Errors.ps1   │   locking, atomic writes
        └────────────┬───────────────┘
        ┌────────────▼───────────────┐
        │      Providers.ps1         │   the crypto seam
        └────────────┬───────────────┘
        ┌────────────▼───────────────┐
        │  Process.ps1  Platform.ps1 │   the only OS-aware code
        └────────────────────────────┘
```

Three rules hold the design together:

1. **The CLI contains no behaviour.** `bin/cred.ps1` parses argv, calls exactly
   one exported function, prints, and picks an exit code. The PowerShell API and
   the CLI therefore cannot drift.
2. **All crypto is behind the provider contract.** Nothing above
   `Providers.ps1` knows what encryption is. Swapping backends is one file.
3. **All OS knowledge lives in `Platform.ps1` and `Process.ps1`.** Nothing else
   asks what operating system it is on. This is what makes the port cheap.

## Why age

`age` is the default provider. The full comparison is in the README; the short
version is that age is the only candidate that is simultaneously small enough to
audit, modern enough to have no footguns, portable enough to make a Linux port
trivial, and file-format-stable enough to trust with data committed to a repo
for years.

Concretely:

- **One algorithm, no configuration.** X25519 key agreement, ChaCha20-Poly1305
  AEAD, HKDF. There is no cipher to choose badly, no mode to misuse, no
  compression oracle.
- **Authenticated.** A corrupted store fails to decrypt rather than producing
  plausible garbage. There is a test that flips a byte and asserts this.
- **Public keys are one line and safe to commit.** That is what makes
  `recipients` a plaintext field in `config.json`, which in turn is what makes
  "add a colleague" a single command.
- **Multiple recipients natively.** Sharing is a first-class operation, not a
  re-encryption scheme we had to invent.
- **`--armor` produces text.** The store diffs, merges and reviews as text in
  git rather than as an opaque binary blob.
- **A second implementation exists.** `rage` (Rust) reads the same format, so
  the data outlives the Go binary.
- **Identical on every platform.** Same binary behaviour, same file format, same
  key file, on Windows, Linux and macOS.

What we deliberately did *not* use, and why:

- **Passphrase mode (`age -p`).** age prompts for passphrases on the terminal
  rather than reading them from a pipe, on purpose, and its own documentation
  warns against passphrases in scripts because they leak into process lists and
  shell history. Key-based encryption is the right shape for automation. If you
  want a passphrase, encrypt the *identity file* itself (`age -p identity.txt`);
  age accepts a passphrase-protected file as an identity, which puts the prompt
  in exactly one place instead of on every operation.
- **DPAPI.** Machine- and account-bound. The whole requirement is that the
  encrypted file travels with the code; DPAPI makes that impossible, and does
  not exist off Windows.
- **Raw OpenSSL.** Using it correctly means designing a KDF choice, an AEAD
  mode, a nonce policy and a versioned header by hand. That is writing a crypto
  format rather than using one, and it is not a thing to do underneath someone's
  production passwords.
- **sops.** The strongest alternative, and per-value encryption would give nicer
  diffs. But its real value is cloud KMS integration we do not need, it is a
  much larger dependency, and it would still need age or gpg underneath. More
  moving parts for a benefit that does not apply here.

`gpg` ships as a second provider — both because it proves the seam is real and
because people with an established GnuPG keyring should not have to abandon it.

## The provider contract

A provider is a `PSCustomObject`:

| Member | Signature | Purpose |
| --- | --- | --- |
| `Name` | string | identifier used in `config.json` |
| `Summary` | string | one line for `cred doctor` |
| `StoreFileName` | string | default ciphertext filename |
| `InstallHint` | string | what to tell the user when it is missing |
| `Test` | `() -> @{Available; Path; Detail}` | is the backend usable right now |
| `NewIdentity` | `($Path) -> @{Path; Recipient}` | create a key |
| `GetRecipient` | `($Config) -> string` | this machine's public key |
| `Encrypt` | `($PlainBytes, $Config) -> byte[]` | |
| `Decrypt` | `($CipherBytes, $CipherPath, $Config) -> byte[]` | |

Two invariants a provider must not break:

- **No plaintext to disk.** Encryption and decryption stream over pipes.
- **No secret on a command line.** Anything on argv is visible to every process
  on the machine.

Register your own with `Register-CredProvider`. The contract is exercised by a
test that registers a toy backend and drives the whole stack through it, so a
change that quietly breaks the seam fails the suite.

## Data model

Two files per repository, both committed:

`.creds/config.json` — plaintext. Which credentials exist, what they are for,
which environment variables they map to. Deliberately readable: a colleague can
see what they need without holding a key. Usernames are *not* here; they are in
the encrypted store, because a username is half a credential.

`.creds/store.age` — ciphertext. The plaintext inside is:

```json
{ "version": 1, "values": { "db": { "user": "svc", "secret": "..." },
                            "stripe": { "secret": "..." } } }
```

That is the whole format. A shell reimplementation needs to understand exactly
this, which is the point.

Outside every repository, in `%APPDATA%\cred` or `$XDG_CONFIG_HOME/cred`:

`identity.txt` — your secret key, permissions restricted to you.
`projects.json` — name → path, so `cred get acme-api/x` works from anywhere.

## Concurrency and durability

Writes take an exclusive lock on `.creds/.lock` (`FileShare.None`, with backoff
and a timeout that produces an actionable error rather than a hang). Reads take
no lock at all, because every write is an atomic replace: a reader either sees
the old store or the new one, never a partial one.

The write path is: encrypt in memory → **decrypt it again and check** → write to
a temp file in the same directory → flush to physical disk → `File.Replace`.
The read-back check matters: if you have somehow produced a store you cannot
open, the old one is still on disk and still good, and you get told why.

Two subtleties that cost real debugging and are worth not rediscovering:

- **The lock file is created once and never deleted.** Releasing it with
  `FileOptions.DeleteOnClose` looks tidier but is racy: a waiter can obtain a
  handle to a file already pending deletion while a third process creates a
  fresh file under the same name, at which point two processes both believe they
  hold the lock and one silently loses its update.
- **`File.Replace` needs a backup path.** Passing `$null` through PowerShell's
  marshalling arrives as an empty string and throws. We name a backup next to
  the file and delete it immediately; if we die in between, what survives is the
  *previous* contents, which is the safe direction to fail in.

## Encoding

Everything internal is bytes. Strings become bytes with an explicit
`UTF8Encoding($false)` and back again; nothing relies on a default.

This is not fussiness. Windows PowerShell 5.1 has three separate traps, all of
which silently corrupt data rather than failing:

- `Set-Content -Encoding UTF8` writes a byte order mark.
- `ConvertTo-Json` defaults to `-Depth 2` and truncates deeper structures
  without a word, and there is no `-AsHashtable` on `ConvertFrom-Json`.
- **`Process.StandardInput` writes the console encoding's preamble into the
  child's stdin** the moment the property is touched — before anything you write
  to `BaseStream`. On a UTF-8 console (`chcp 65001`, which many people set
  precisely so Unicode works) that is `EF BB BF` prepended to every payload, and
  age rightly rejects it. PowerShell 7 can set `StandardInputEncoding`
  declaratively; 5.1 cannot, so `Invoke-CredProcess` swaps in a preamble-free
  encoding for the duration of the call. There is a regression test.

`Json.ps1` exists to make the first two impossible to hit; `Process.ps1` handles
the third.

## Not leaking

- Interactive entry uses `Read-Host -AsSecureString`. Nothing echoes and nothing
  reaches shell history.
- `cred get` writes to `[Console]::Out`, the raw handle, not the PowerShell
  pipeline. `Start-Transcript` captures the pipeline; it does not capture this.
  Piping and redirection still behave normally. There is a test that starts a
  transcript, gets a secret, and asserts the canary is in stdout but not in the
  transcript.
- Error messages name projects and keys — both already plaintext in the repo —
  and never values. Tests assert that a canary value cannot be provoked into
  stderr or into `--verbose` output.
- Values are never arguments to a child process.

The honest limits are in the README's security section. The main one: .NET
strings are immutable and garbage-collected, so once a secret is a `[string]` it
cannot be reliably scrubbed from memory. Values stay `SecureString` where the
API permits and byte buffers are zeroed after use, but that is a ceiling. A
PowerShell-hosted tool claiming more would be lying.

## The Linux port

Most of it is already done: PowerShell 7 runs natively on Linux and macOS, so
`bin/cred` (a POSIX `sh` shim) plus the module *is* a working `cred` on any
Unix today. `Platform.ps1` already resolves `$XDG_CONFIG_HOME/cred` and applies
`chmod 600`; `age` is the same binary everywhere.

The remaining question is whether you want a `cred` that does not require
PowerShell at all. That is a small job rather than a rewrite, because the
formats are the contract:

- `.creds/config.json` is plain JSON — `jq` reads it.
- `.creds/store.age` is a standard age file — `age -d -i ~/.config/cred/identity.txt`
  decrypts it. The plaintext is the small JSON object documented above.
- The project registry is plain JSON.
- Nothing is Windows-specific in any file that gets committed.

So a POSIX `cred` is roughly:

```sh
cred_get() {                       # cred get <project>/<key>
  root=$(cred_project_root "${1%%/*}")
  age -d -i "${CRED_IDENTITY_FILE:-$HOME/.config/cred/identity.txt}" \
      "$root/.creds/store.age" | jq -r --arg k "${1#*/}" '.values[$k].secret'
}
```

...plus `exec` (`env $(...) "$@"`), `list` (`jq` over `config.json`), and `add`
(`jq` to build the new plaintext, pipe through `age -a -R`, write via a temp file
and `mv`). Call it 200 lines of `sh`, with `jq` and `age` as the only
dependencies. Completions for bash/zsh/fish are then ordinary shell work.

What such a port must not skip, because these are where correctness lives and
not where it looks like it lives:

- the exclusive lock around read-modify-write (`flock` on `.creds/.lock`);
- the atomic replace (`mv` within the same filesystem, after `sync`);
- the decrypt-before-replace read-back check;
- keeping values off argv (`age` reads stdin; `jq --arg` reads argv, so build
  the plaintext with `jq --rawfile` or a here-doc on stdin instead).

If you want to keep exactly one implementation, don't port: install PowerShell 7
and use the `sh` shim. The module already runs there unmodified.

## Directory map

```
bin/
  cred.ps1        CLI: argv parsing, output, exit codes. No behaviour.
  cred.cmd        Windows launcher (prefers pwsh, falls back to 5.1)
  cred            POSIX sh launcher
src/Cred/
  Cred.psd1       manifest; explicit exports, both editions
  Cred.psm1       loader; private files in dependency order, then public
  Private/
    Platform.ps1  OS detection, config paths, ACLs, Windows argv quoting
    Errors.ps1    error records with next steps; code → exit code
    Json.ps1      UTF-8 no-BOM I/O, atomic writes, JSON that behaves on 5.1
    Process.ps1   child processes: byte pipes in, byte pipes out
    Secrets.ps1   SecureString conversion, prompting, raw stdout
    Providers.ps1 the crypto seam: age, gpg
    Config.ps1    project discovery, registry, config read/write
    Store.ps1     locking, decrypt/encrypt of the value set
  Public/         one file per area; every function has help and examples
tests/
  Unit.Tests.ps1         pure functions, file plumbing, provider contract
  Integration.Tests.ps1  real age, three access paths, encoding
  Failure.Tests.ps1      every documented failure mode and its advice
  Concurrency.Tests.ps1  multi-process races against the real lock
  Cli.Tests.ps1          the CLI as a process: argv, exit codes, leak hygiene
  Invoke-Tests.ps1       runs everything under both editions
```
