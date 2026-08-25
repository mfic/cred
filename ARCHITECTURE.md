# Architecture

## The shape of the thing

```
   cred (the CLI)            cred-ps (peer CLI)      Import-Module Cred
   bin/cred -> cred.py       bin/cred-ps             src/Cred/Public/*.ps1
        |                          |                        |
        |                          +-----------+------------+
        |                                      |
  python/cred_store.py            src/Cred/Private/*.ps1
        |                                      |
        |   providers, store, locking, atomic writes, OS-aware code
        |                                      |
        +--------- the files are the contract -+
```

Four rules hold the design together:

1. **A CLI contains no behaviour.** `python/cred.py` and `bin/cred-ps.ps1` both
   parse argv, call one function, print, and pick an exit code. Nothing else.
2. **All crypto is behind the provider contract.** Nothing above
   `Providers.ps1` knows what encryption is. Swapping backends is one file.
3. **All OS knowledge lives in `Platform.ps1` and `Process.ps1`.** Nothing else
   asks what operating system it is on.
4. **The formats are the contract, not the code.** The Python and PowerShell
   implementations share no code; they agree because they agree about the
   files. See "One CLI, two implementations".

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

`python/cred_store.py` mirrors this exactly, as a dict of the same members in
`PROVIDERS`, reached through `get_provider(name)`. Both ship `age` and `gpg`.

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

The write path is: encrypt in memory → write the ciphertext to a temp file in
the same directory → flush to physical disk → **decrypt that file and check** →
`File.Replace`. Verifying the staged file rather than the in-memory bytes proves
that what is about to become the store is readable. Until the replace the old
store is untouched, so a failure here costs nothing and tells you why.

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
- `cred get` writes raw bytes to the real stdout handle -- `sys.stdout.buffer`
  in Python, `[Console]::Out` in PowerShell -- never through the PowerShell
  pipeline. `Start-Transcript` captures the pipeline; it does not capture this.
  Piping and redirection still behave normally. There is a test that starts a
  transcript, gets a secret, and asserts the canary is in stdout but not in the
  transcript. Writing bytes rather than text is also what makes a non-ASCII
  password survive a console whose code page cannot represent it.
- Error messages name projects and keys — both already plaintext in the repo —
  and never values. Tests assert that a canary value cannot be provoked into
  stderr or into `--verbose` output.
- Values are never arguments to a child process.

The honest limits are in the README's security section. The main one: .NET
strings are immutable and garbage-collected, so once a secret is a `[string]` it
cannot be reliably scrubbed from memory. Values stay `SecureString` where the
API permits and byte buffers are zeroed after use, but that is a ceiling. A
PowerShell-hosted tool claiming more would be lying.

## One CLI, two implementations

`cred` is the Python program. It is the default interface everywhere and carries
the whole command surface:

    bin/cred, bin/cred.cmd      ->  python/cred.py      Python 3.8+     [default]
    bin/cred-ps, cred-ps.cmd    ->  bin/cred-ps.ps1     PowerShell 5.1 / 7
    Import-Module Cred          ->  src/Cred/           PowerShell library

The PowerShell CLI script is called `cred-ps.ps1` and not `cred.ps1` for a
reason worth writing down: when PowerShell resolves a bare `cred` on PATH it
prefers a `.ps1` in that directory over the `.cmd`. A file named `bin/cred.ps1`
therefore quietly made `cred` mean *the PowerShell edition* in every PowerShell
session, which is the opposite of what the launcher table says. With the `-ps`
suffix, `cred` is Python in every shell and `cred-ps` is the opt-in.

Python is the default for three reasons, in order of weight: it keeps the CLI to
*one* implementation people have to reason about; it is the runtime most likely
to already exist on a Linux host or in a container, where pwsh would be a
~100 MB install; and it starts faster.

PowerShell keeps the job it is actually better at. `Get-CredCredential`,
`Get-CredEnvironment` and `Get-Cred -AsSecureString` hand *live objects* to a
PowerShell script. A CLI cannot do that without serialising the secret to text
and re-parsing it, which would add a leak surface for no gain. That is why the
module is not a wrapper around the CLI and never shells out to it.

`bin/cred-ps` is the same CLI implemented in PowerShell, kept for machines with
pwsh but no Python. It is not a fallback that degrades: it is a full peer, and
it is the one that ships `gpg` support in the same seam.

Neither implementation calls the other. They interoperate because the *files*
are the contract, and nothing else is:

- `.creds/config.json` -- plain JSON
- `.creds/store.age` -- a standard age file whose plaintext is the small object
  documented above
- `<CRED_HOME>/identity.txt` or `identity.wrapped.json` -- the key, plain or
  keystore-wrapped, in a self-describing format both sides read
- `<CRED_HOME>/projects.json` -- plain JSON
- `.creds/.lock` -- an exclusive lock, taken the same way by both

`tests/Interop.Tests.ps1` drives both against a single store and asserts
byte-exact round trips in each direction, identical exit codes, identical
default environment-variable names, and that neither loses the other's writes.
`tests/PythonCli.Tests.ps1` covers the Python CLI on its own. Those two files
are what stop the implementations drifting.

The only remaining asymmetry is deliberate: `gpg` is implemented in both, but
`cred-ps` is the one with the PowerShell-native object API, because that is not
a CLI concern.

A third implementation in `sh` would need nothing new from this codebase: `jq`
over `config.json`, `age -d -i` over the store, `flock` on `.creds/.lock`, and
`mv` within the same filesystem for the atomic replace. What it must not skip,
because this is where correctness lives and not where it looks like it lives:

- the exclusive lock around read-modify-write, and **not** deleting the lock
  file on release;
- the atomic replace, after an fsync;
- staging the ciphertext and decrypting *that file* before it becomes the store;
- keeping values off argv entirely.

## Confirmation belongs to one question

Destructive commands ask once, about the thing the user named. Getting that
right in PowerShell takes two deliberate rules, because `-Confirm` is not a
per-cmdlet flag the way it reads:

1. **The CLI never passes `-Confirm:$true`.** Passing `-Confirm` to a cmdlet
   sets `$ConfirmPreference = 'Low'` for its entire call stack, and preference
   variables are inherited downward. Every `SupportsShouldProcess` cmdlet the
   module touches on the way then stops and asks too, so a single `cred rm`
   became five prompts -- about the credential, about writing `config.json`,
   about deleting the module's own backup files, about scrubbing a variable.
   Answering `[A]` Yes-to-All does not help, because that state is per cmdlet
   invocation. So `bin/cred-ps.ps1` prompts for itself in
   `Confirm-CredCliAction` and always calls the module with `-Confirm:$false`,
   which also makes its wording and its non-interactive behaviour match
   `python/cred.py`.
2. **Every public function resets `$ConfirmPreference = 'None'` once its own
   `ShouldProcess` gate has been passed.** That keeps the same thing from
   happening to someone typing `Remove-Cred foo -Confirm` at a prompt, and it
   holds for code added later. The private helpers additionally pass
   `-Confirm:$false` on the `Remove-Item` and `Remove-Variable` calls that clean
   up temp files, backups and plaintext -- housekeeping in a `finally` block is
   never a question for a user.

## The OS keystore

By default the age key is a file, protected by its ACL (or mode 600). That is
the floor, not the ceiling: anything running as you can read it, and so can
anyone who takes the disk.

`cred key protect` wraps it with DPAPI, bound to the current Windows account.
The mechanism is worth understanding because it is the reason the store stays
portable:

- Only the **key** is OS-bound. The **store** is untouched and stays plain age,
  so it still travels with the code and still opens on Linux. Encrypting the
  store with DPAPI would destroy the entire premise, which is why that was
  rejected as a provider in the first place.
- The unwrapped key never becomes a file. It is unwrapped into memory and piped
  to age on stdin (`-i -`), which forces the *ciphertext* to be the file
  argument instead. That is free, because ciphertext on disk is exactly what the
  store already is.
- That constraint is also why `Write-CredStoreValues` stages the new ciphertext
  beside the store and verifies by decrypting the staged file. It gives the
  wrapped path a real path to point at, and it happens to be the stronger check
  anyway: it proves the bytes that are about to become the store are readable,
  not merely that a byte array in memory was.

Wrapping is detected by file content, not by filename, so renaming a key cannot
misrepresent it. Both implementations wrap and unwrap -- Python through `ctypes`
against `CryptProtectData`/`CryptUnprotectData` -- so a wrapped key never ties
you to one of them.

The trade is stated at the point of use and again here: a DPAPI-wrapped key does
not survive a new machine, a reinstall, or a changed account. `cred key protect`
takes `--backup` and warns when you do not use it.

## The PSCredential boundary

`Import-Cred` and `Export-Cred` exist for migration and for tools that still
want the old shape. They are not part of everyday use and are documented as
such.

The subtlety worth recording: both `Export-Clixml` and `ConvertFrom-SecureString`
are DPAPI-protected on Windows and open **only** for the account that wrote
them. Any bulk import therefore has to run as that user, on that machine, before
anything moves. `Export-Cred` refuses to run off Windows without `-Force`,
because there `Export-Clixml` silently writes the secret in plain text.

`Import-Cred` decodes `ConvertFrom-SecureString` hex through `ProtectedData`
directly rather than `ConvertTo-SecureString`, for the same reason `Get-CredAcl`
avoids `Get-Acl`: `Microsoft.PowerShell.Security` does not autoload on every 5.1
host, and a migration tool that fails on the one machine holding the credentials
is worthless.

The Python CLI implements the same boundary without PowerShell at all.
`Export-Clixml` turns out to be plain XML in which a SecureString is a DPAPI
blob in hex -- exactly what `ConvertFrom-SecureString` emits -- so
`read_clixml_credential` and `write_clixml_credential` handle both directions
with `xml.etree` plus `ctypes`. That is what let the CLI become one program
instead of one program that shells out to another for part of its job. There is
a test asserting PowerShell reads back what Python writes, byte for byte.

## Directory map

```
bin/
  cred            the CLI (POSIX sh launcher -> python/cred.py)
  cred.cmd        the CLI (Windows launcher -> python/cred.py)
  cred-ps         PowerShell implementation, POSIX sh launcher
  cred-ps.cmd     PowerShell implementation, Windows launcher
  cred-ps.ps1     PowerShell CLI: argv parsing, output, exit codes
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
python/
  cred.py         the CLI: argv, output, exit codes. No behaviour.
  cred_store.py   the store as a library: providers, formats, locking, DPAPI,
                  Clixml
tests/
  Unit.Tests.ps1         pure functions, file plumbing, provider contract
  Integration.Tests.ps1  real age, three access paths, encoding
  Failure.Tests.ps1      every documented failure mode and its advice
  Concurrency.Tests.ps1  multi-process races against the real lock
  Cli.Tests.ps1          the CLI as a process: argv, exit codes, leak hygiene
  Keystore.Tests.ps1     wrapping the key, and that it leaves no key on disk
  Migration.Tests.ps1    the PSCredential import/export boundary
  PythonCli.Tests.ps1    the default CLI on its own
  Interop.Tests.ps1      PowerShell and Python against one store
  Invoke-Tests.ps1       runs everything under both editions
```
