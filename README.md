# cred

Per-repository encrypted credentials. One CLI, written in Python, on every
platform.

Your secrets live in an **age-encrypted file committed inside the repo**, so they
travel with the code. The key that opens it lives in your user profile and never
goes near a repository. Plaintext is never written to disk — decryption happens
in memory, on demand.

Three ways to get a credential out:

```bash
cred get acme-api/stripe                 # one secret on stdout, for piping
cred exec acme-api -- npm run deploy     # env vars, nothing on disk
```
```powershell
$c = Get-CredCredential acme-api/db      # a native PSCredential, in PowerShell
```

The first two are the `cred` CLI and run anywhere Python 3.8+ does. The third is
the `Cred` PowerShell module, for when a PowerShell script wants a real object
rather than text.

---

## 60-second quickstart

```powershell
# 0. one-off: install the runtime and the encryption backend, and put cred on your PATH
winget install Python.Python.3.12     # the cred CLI is Python; skip if you have 3.8+
winget install FiloSottile.age
$env:PATH += ";C:\tools\cred\bin"
# No Python on this machine? Use cred-ps instead -- same commands, PowerShell.

# 1. one-off: create your personal key (stored outside every repo, backed up by you)
cred keygen

# 2. in a repository, create the store
cd C:\work\acme-api
cred init

# 3. add credentials — you are prompted, nothing echoes, nothing hits your history
cred add acme-api/stripe --desc "Stripe live key"
cred add acme-api/db --user svc_acme --desc "Postgres, prod"

# 4. commit it. .creds/ is encrypted; that is the point.
git add .creds && git commit -m "Add encrypted credential store"

# 5. use them
cred get acme-api/stripe                             # print one
cred exec acme-api -- psql -h db01                   # inject DB_USER / DB_PASSWORD
cred list acme-api                                   # names only, no decryption needed
```

The same on Linux or macOS -- only step 0 and the path in step 2 change:

```bash
# 0. one-off: runtime, encryption backend, PATH
sudo apt install python3 age          # or: brew install python age / pacman -S python age
export PATH="$HOME/tools/cred/bin:$PATH"

# 2. a repository is just a path
cd ~/work/acme-api
```

Steps 1 and 3 through 5 are the same commands, character for character. So is
the store they produce: it is committed encrypted and opens on either platform.

From then on, from anywhere on the machine:

```powershell
cred get acme-api/stripe
```

Something wrong? `cred doctor` checks every moving part and tells you the exact
command to fix each one.

---

## What is on disk

```
your-repo/
  .creds/
    config.json   plaintext, committed  — which credentials exist, what they are
                                          for, which env vars they map to
    store.age     ciphertext, committed — the values
    .gitignore    keeps the lock file out of git

~/.config/cred/  (or %APPDATA%\cred)     — NOT in any repo
    identity.txt  your secret key, permissions locked to you
    projects.json name → path, so `cred get acme-api/x` works from anywhere
```

`config.json` is deliberately readable:

```json
{
  "version": 1,
  "project": "acme-api",
  "provider": "age",
  "store": "store.age",
  "recipients": ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"],
  "credentials": {
    "db": {
      "type": "userpass",
      "env": { "user": "DB_USER", "secret": "DB_PASSWORD" },
      "description": "Postgres, prod"
    },
    "stripe": {
      "type": "secret",
      "env": { "secret": "STRIPE_API_KEY" },
      "description": "Stripe live key"
    }
  }
}
```

A new colleague can read that file, run `cred list`, and know exactly what
credentials they need — without holding a key and without decrypting anything.
Usernames live in the encrypted store, not here.

**Why JSON and not YAML or TOML?** Both PowerShell editions parse JSON natively.
YAML would mean shipping `powershell-yaml` as a dependency and TOML has no
in-box parser at all — a credential tool that fails to start because a parsing
module is missing is worse than one without comments. The `description` field
covers what comments would have.

---

## The three access paths

### 1. `cred get` — one secret on stdout

```powershell
cred get acme-api/stripe                  # with trailing newline
cred get acme-api/stripe -n               # without, for piping
cred get acme-api/db --field user         # the username half of a pair
```

Output goes to the raw stdout handle, not the PowerShell pipeline, so it is not
captured by `Start-Transcript`. Redirection and piping work normally.

```bash
curl -H "Authorization: Bearer $(cred get acme-api/gh -n)" https://api.github.com/user
```

### 2. `cred exec` — a child process with the secrets in its environment

```powershell
cred exec acme-api -- npm run deploy
cred exec acme-api --only db -- psql -h db01
cred exec acme-api --prefix TF_VAR_ -- terraform apply
```

Everything after `--` runs verbatim. The child inherits your console, so
interactive programs work. Nothing is written to disk, the variables exist only
for that process's lifetime, and its exit code becomes cred's exit code.

### 3. PowerShell objects

```powershell
Import-Module Cred

$cred = Get-CredCredential acme-api/db          # PSCredential, password a SecureString
Invoke-Sqlcmd -ServerInstance db01 -Credential $cred

$env  = Get-CredEnvironment acme-api            # hashtable of env-var name → value
$env.STRIPE_API_KEY

$key  = Get-Cred acme-api/stripe -AsSecureString

Export-CredFile acme-api/ssl-key -OutFile D:\tmp\server.key   # a file credential

# The two that answer a whole question in one decryption:
$r = Get-CredEnvironmentReport acme-api         # .Variables and .Skipped together
$v = Read-CredValue acme-api/ssl-key            # .Bytes with .Kind and .IsBinary
```

---

## Command reference

| Command | Does |
| --- | --- |
| `cred init [name]` | Create `.creds/` here and register the project |
| `cred add <p>/<k>` | Add or replace a credential (prompts, no echo) |
| `cred add <p>/<k> --file <path>` | Store a file's exact bytes (key, certificate) |
| `cred get <p>/<k>` | Print one secret |
| `cred get <p>/<k> --out <path>` | Write it back out as a file |
| `cred list [p]` | Credential names and descriptions, no decryption |
| `cred exec <p> -- …` | Run a command with the secrets injected |
| `cred rm <p>/<k>` | Delete a credential |
| `cred env [p]` | Print `$env:` / `export` lines for the current shell |
| `cred recipients [p]` | Who can decrypt this project |
| `cred recipients add <key>` | Grant access and re-encrypt |
| `cred recipients rm <key>` | Revoke access and re-encrypt |
| `cred keygen` | Create your key; `--show` prints the public half |
| `cred key` | Where your key is and how it is protected |
| `cred key protect` | Wrap the key with the OS keystore |
| `cred key unprotect` | Unwrap it, before moving machine or account |
| `cred import <path>` | Bring existing PSCredential files into a store |
| `cred export <folder>` | Write credentials back out as PSCredential files |
| `cred project list` | Registered projects on this machine |
| `cred providers` | Encryption backends and their status |
| `cred doctor` | Check everything and say how to fix what is broken |
| `cred claude [p]` | Markdown brief for a Claude Code session |

Exit codes: `0` ok · `2` usage · `3` not found · `4` key or decrypt problem ·
`5` backend missing · `6` corrupt store · `7` locked · `8` child command failed.

Environment: `CRED_HOME`, `CRED_IDENTITY_FILE`, `CRED_PROJECT`, `CRED_AGE_PATH`.

---

## Sharing a project with someone else

They run `cred keygen` and send you the public key it prints. You run:

```powershell
cred recipients add age1theirpublickey...
git commit -am "Grant alice access"
```

The store is re-encrypted for both of you. They pull and it just works.

To revoke, `cred recipients rm <key>` — but note that anyone who held that key
can still read every older version of the store out of git history. Revocation
is a reason to rotate the secrets themselves, not a substitute for it. `cred`
tells you this when you do it.

---

## Why age

Evaluated: **age**, **sops**, **gpg**, **DPAPI**, **raw OpenSSL**.

**age wins.** It is a small, audited, opinionated tool with one modern algorithm
(X25519 + ChaCha20-Poly1305, authenticated), no configuration surface to get
wrong, and no key server, web of trust, or agent to fight. Public keys are one
line of text, safe to commit; the secret key is one line of text you back up
once. `--armor` gives PEM output that diffs and merges as text in git. It runs
identically on Windows, Linux and macOS, which is what makes the Linux port
cheap. It has an independent Rust implementation (`rage`), so the file format
outlives any single binary.

The rest, and why not:

| | Verdict |
| --- | --- |
| **sops** | Genuinely excellent, and the closest competitor — per-value encryption means readable diffs. But it is a much larger dependency whose real strength is cloud KMS integration we do not need, and it would still need age or gpg underneath. Complexity without a matching payoff here. |
| **gpg** | Shipped as a second provider for a while, for people already invested in it, then removed as unused. The keyring, agent, pinentry and trust model are a large surface that fails in confusing ways, key handling differs meaningfully across platforms, and its output is not reproducible. age exists precisely because of this. |
| **DPAPI** | Disqualified. It is machine- and account-bound, so the encrypted file cannot travel with the code — which is the entire requirement — and it does not exist off Windows, so there is no Linux port at all. |
| **raw OpenSSL** | Disqualified for the default. Using it correctly means choosing a KDF, an AEAD mode, a nonce policy and a versioned file format by hand: writing a crypto format rather than using one. Fine as a provider someone adds later; wrong as the thing your passwords depend on. |

Crypto is behind a provider interface (see `src/Cred/Private/Providers.ps1`), so
swapping backends touches one file. `age` is the only provider that ships; the
contract is documented in `Register-CredProvider`'s help and exercised by a test
that registers a fake backend.

Full reasoning, and what a Linux port actually requires, in
[ARCHITECTURE.md](ARCHITECTURE.md).

---

## One CLI, and a PowerShell module

`cred` is a single Python program. It is the interface on Windows, Linux and
macOS, it carries the whole command surface, and it needs Python 3.8+ and the
`age` binary -- nothing from PyPI.

Alongside it, the `Cred` **PowerShell module** exists for the one job a CLI
cannot do: handing a live `PSCredential` or hashtable to a PowerShell script.

```powershell
Import-Module C:\tools\cred\src\Cred\Cred.psd1
$cred = Get-CredCredential acme-api/db
Invoke-Sqlcmd -ServerInstance db01 -Credential $cred
```

There is also `bin/cred-ps`: the same CLI implemented in PowerShell. It is a
peer, not a wrapper -- same files, same formats, same exit codes -- kept for
machines that have PowerShell but no Python. You should not normally need it.
`tests/Interop.Tests.ps1` drives both against one store and asserts byte-exact
round trips in each direction, so the two cannot quietly drift apart.

Why Python is the default: it is the runtime most likely to already be present
on a Linux box or in a container, it starts faster than pwsh, and it keeps the
CLI to one implementation rather than two that have to agree. PowerShell stays
where it is genuinely better -- native objects inside PowerShell scripts.

## Files: private keys and certificates

A TLS private key is a credential like any other, but it is a *file*, and the
things that consume it — openssl, nginx, curl — want bytes, not a string.

```powershell
cred add acme-api/ssl-key --file .\server.key --desc "TLS private key"
cred get acme-api/ssl-key --out D:\tmp\server.key
```

The import is byte-exact: no newline stripping, no line-ending translation, and
binary (`.pfx`, `.p12`, DER) is stored base64 so it survives the JSON store.
What came in is what comes out — there is a test that drives this through both
the Python and PowerShell implementations in each direction.

`config.json` records the type and the original filename, so the readable half
of the store still says what exists:

```json
"ssl-key": { "type": "file", "env": {}, "filename": "server.key",
             "description": "TLS private key" }
```

Two deliberate limits:

- **`cred exec` does not inject file credentials.** A PEM is not usable as an
  environment variable, and `export SSL_KEY=-----BEGIN…` breaks the shell it is
  pasted into. `cred exec` and `cred env` say which ones they skipped.
- **`--out` is the one place cred writes plaintext to disk.** It creates the
  file readable only by you, refuses to overwrite without `--force`, and tells
  you what it did. Delete it when the tool that needed it is done. Everything
  else in cred still keeps plaintext off disk.

Keep files small. The whole store is re-encrypted on every write, so a large
file is paid for again on every unrelated `cred add`; anything over 1 MiB needs
`--force` and probably belongs somewhere else.

In PowerShell the same two operations are `Set-Cred -File` and
`Export-CredFile`.

## Protecting the key itself

By default your age key is a file whose only protection is its permissions.
You can wrap it with the OS keystore instead, which binds it to your account
on that machine:

```powershell
cred key protect --backup D:\safe\age-key.txt
```

The mechanism depends on the platform, and `cred key` names the one in use:

| | Mechanism | Needs |
| --- | --- | --- |
| Windows | DPAPI | nothing installed |
| Linux | `systemd-creds`, scoped to your user | systemd 256 or newer |
| macOS | none yet | -- |

Neither mechanism asks a question, which is the point: a keystore that prompts
cannot be used from a script, and a script is where credentials are actually
needed. Where there is no keystore, `cred key protect` says so and says what to
do instead.

After wrapping, the file on disk contains no key material — cred unwraps it in
memory and pipes it to age, so the plaintext key is never a file again. Back it
up first: a wrapped key does not survive a new machine, a reinstall, or a
changed account. Before you move, run `cred key unprotect`.

This deliberately does **not** touch the store. The store stays OS-independent,
so it still travels with the code and still opens on Linux.

## Migrating from PSCredential files

If your credentials currently live as `Export-Clixml` files:

```powershell
cred import D:\old\creds --dry-run     # see what it would do
cred import D:\old\creds --desc "migrated"
```

Filenames become credential names (`db.cred.xml` → `db`). A `PSCredential`
brings its username along; a bare `SecureString` lands as a plain secret.

Do this on the Windows account that created those files — `Export-Clixml` is
DPAPI-protected and will not open anywhere else.

In PowerShell, one object is enough in either direction:

```powershell
Set-Cred acme-api/db -Credential (Import-Clixml old-db.xml)   # in
$cred = Get-CredCredential acme-api/db                         # out
```

`cred export <folder>` writes the files back out if something still needs them.
It warns you, because that puts secrets on disk — it is a migration tool, not a
way to work.

## Using it with Claude Code

`cred claude` prints a Markdown block describing what a project's credentials
are, without any values. Write it into the repo's `CLAUDE.md`:

```powershell
cd C:\work\acme-api
cred claude --write
git add CLAUDE.md && git commit -m "Tell Claude about the credential store"
```

Now a session in that repo knows `acme-api/stripe` exists, what it is for, and —
importantly — that the right way to use it is

```
cred exec acme-api -- <command>
```

which hands the secret to a child process the agent never sees, rather than

```
cred get acme-api/stripe
```

which puts the value straight into the transcript. See
[docs/claude-code.md](docs/claude-code.md) for a worked example.

---

## Security properties

What this does guarantee:

- Plaintext is never written to disk unless you ask for it in so many words.
  Encryption and decryption stream over pipes to and from the backend process;
  even the temp file used for atomic writes only ever holds ciphertext. The two
  exceptions are explicit and named: `cred get --out` and `cred export`, both of
  which create the file readable only by you and tell you what they did.
- Secrets are never passed as command-line arguments, so they cannot be read out
  of the process list.
- `cred get` writes to the raw console handle, so `Start-Transcript` does not
  capture it. There is a test for this.
- Values never appear in an error message, in `--verbose` output, or in
  `config.json`. There are tests for these.
- Interactive entry uses `Read-Host -AsSecureString`: no echo, no shell history.
- Your key file is created with an ACL granting only you, with inheritance
  disabled (`chmod 600` on Unix). `cred doctor` checks and `cred doctor --repair`
  fixes it.
- Writes are atomic and take an exclusive lock, so concurrent `cred add` runs
  cannot lose an update or leave a half-written store. There are tests for this.
- Corruption is detected: age is authenticated encryption, so a flipped byte
  fails to decrypt rather than yielding garbage.

What it does not:

- `cred exec` puts secrets in a child process's environment, where anything
  running as you (or as an administrator) can read them. That is inherent to
  environment injection and is true of `sops exec-env`, `aws-vault exec` and
  every similar tool. Prefer `--only` to inject the minimum.
- .NET strings are immutable and garbage-collected. Once a secret is a `[string]`
  it cannot be reliably scrubbed from memory. Values are kept as `SecureString`
  where the API allows, and byte buffers are zeroed, but this is a ceiling, not
  a guarantee. Anything stronger in a PowerShell-hosted tool would be theatre.
- Deleting a credential does not remove it from git history. Rotate at the
  source.
- The plaintext `config.json` reveals credential *names* and *purposes* by
  design. If a name is itself sensitive, do not use it as a name.

---

## Requirements

- Python 3.8+ for the `cred` CLI (no PyPI packages)
- Windows PowerShell 5.1 or PowerShell 7+ for the `Cred` module and for
  `bin/cred-ps` -- both editions are supported and both are tested on every
  change
- [age](https://age-encrypted.org) 1.2+ — `winget install FiloSottile.age`,
  `brew install age`, `apt install age`

## Installing

### Windows

```powershell
git clone <this repo> C:\tools\cred
$env:PATH += ";C:\tools\cred\bin"   # cred (Python), cred-ps (PowerShell)

# For native PSCredential / hashtable objects inside PowerShell scripts:
Import-Module C:\tools\cred\src\Cred\Cred.psd1
```

Make the PATH change permanent:

```powershell
[Environment]::SetEnvironmentVariable('PATH',
    [Environment]::GetEnvironmentVariable('PATH','User') + ';C:\tools\cred\bin', 'User')
```

### Linux and macOS

```bash
git clone <this repo> ~/tools/cred
export PATH="$HOME/tools/cred/bin:$PATH"   # cred (Python), cred-ps (PowerShell)
```

Make the PATH change permanent by putting that line in `~/.bashrc` or
`~/.zshrc`. If your dotfiles are a repo shared across machines, put it in
whatever per-machine override file they source instead -- where you cloned to
is a property of this machine, not of the dotfiles.

`cred` is the one to reach for here. It needs Python 3.8+ and nothing from
PyPI, which almost every distribution already satisfies. `cred-ps` is on your
PATH too and speaks the same commands, but it needs PowerShell 7+ installed
separately; the store it reads is byte-for-byte the same either way.

For the module -- `Get-Credential`-shaped objects inside PowerShell scripts --
from a `pwsh` session:

```powershell
Import-Module ~/tools/cred/src/Cred/Cred.psd1
```

If `cred` is found on your PATH but the shell refuses to run it, the clone
predates the launchers being marked executable: `chmod +x bin/cred bin/cred-ps`.

## Testing

```powershell
.\tests\Invoke-Tests.ps1              # both editions
.\tests\Invoke-Tests.ps1 -ThisEditionOnly
```

The suite covers pure functions, a real age round trip, all three access paths,
every documented failure mode, multi-process concurrency, leak hygiene
(transcripts, process arguments, error text, files on disk), the OS keystore,
the PSCredential migration boundary, the Python CLI on its own, and
interoperability between the Python and PowerShell implementations.

Note that `tests/` is Pester, so running it needs PowerShell even though the
CLI under test is Python. That is deliberate: the same harness drives both
implementations, which is what keeps them honest about each other.
