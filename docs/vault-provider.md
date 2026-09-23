# A Vault provider, or just the Vault tools?

The question: would building HashiCorp Vault support into `cred` buy anything
over a user simply reaching Vault through the tools that already exist? Those
tools are the PowerShell SecretManagement extension for Vault
(`SecretManagement.Hashicorp.Vault.KV` on top of
`Microsoft.PowerShell.SecretManagement`), and HashiCorp's own `vault` CLI and
Vault Agent.

**Nothing Vault-shaped exists in this repository yet.** Every mention of Vault
in the tree is a comment saying where a later backend would plug in
(`ARCHITECTURE.md:110-114`, `ARCHITECTURE.md:139-143`,
`src/Cred/Private/Providers.ps1:26-29`, `src/Cred/Public/Providers.ps1:57-59`).
The `vault.age` in `tests/fixtures/custom-store-name/.creds/config.json:5` is
just a store filename. `age` is the only provider in either implementation
(`python/cred_store.py:788`). The design is planned in the GitHub tracker, on
the map [#1 Vault-backed cred: KV v2 as the source of
truth](https://github.com/mfic/cred/issues/1) and its tickets #2–#13. Two
research notes sit on local branches: `research/kv-v2-cas`
(`docs/research/kv-v2-check-and-set.md`) and `research/powershell-51-http`
(`docs/research/powershell-51-http.md`). Everything below that describes cred's
Vault behaviour is **planned**, not built, and is labelled that way.

Every claim is cited to the repo file and line, to a GitHub issue, to
HashiCorp's or Microsoft's own documentation, or to the extension's source at
commit `94ff8da` (2026-07-14, the archival commit) of
[joshcorr/SecretManagement.Hashicorp.Vault.KV](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV).
Claims taken from source rather than documentation are marked **[source]**.
They describe how that version behaves and are not a promise. Nothing here was
run against a live Vault.

## First, what "a Vault provider" would even be

In this codebase a *provider* is a narrow thing: the crypto seam. It is
`Encrypt`/`Decrypt` over the whole store blob, plus `Test`, `NewIdentity` and
`GetRecipient`, and an optional key half (`ARCHITECTURE.md:116-143`). Vault
could sit behind the `cred` name in three different ways, and only one of them
is a provider in that sense:

| Shape | Fits the provider contract? | Status |
| --- | --- | --- |
| **Vault Transit as a provider.** Vault encrypts and decrypts the store blob, and the store stays committed. | Yes, exactly. It is the "remote vault or KMS" the optional key half was written for. | Ruled **out of scope** in [#1](https://github.com/mfic/cred/issues/1): "a genuinely good idea for later; not this". |
| **Vault KV as a provider.** Vault holds the values. | No. KV is a store, not a cipher. It has nothing to put behind `Encrypt(bytes) -> bytes`. | Not proposed anywhere. |
| **Vault KV as a sync layer above the store.** KV v2 is authoritative, and `.creds/store.age` becomes a gitignored mirror. | Not a provider. It sits at `read_values`/`update_store`. | **The planned design**, [#1](https://github.com/mfic/cred/issues/1) decisions 1–9. |

The map says this outright: "This map is **not** about that seam. It adds a
**sync layer above the store**" ([#1](https://github.com/mfic/cred/issues/1),
Notes). Ticket [#9](https://github.com/mfic/cred/issues/9) asks the spec to
"say plainly whether `--provider` has anything to do with Vault — otherwise
someone will assume it does." So "the Vault provider" in the question is taken
here to mean **the planned KV v2 sync layer**, with Transit covered briefly at
the end. That is the one someone would actually be choosing between.

## The alternatives, as they actually are

### The SecretManagement extension: archived, and on a retired base

Both halves of that stack have stopped moving.

- **SecretManagement is feature complete and archived.** Microsoft's reference
  page: "The PowerShell team has decided that Secret modules are feature
  complete and will no longer be actively developed. The modules will continue
  to be supported for security and critical bug fixes. The code repository has
  been archived." The last release is 1.1.2
  ([Register-SecretVault](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.secretmanagement/register-secretvault)).
- **The Vault extension is archived too, and gets no security fixes.** Its
  README, updated 2026-07-14, says the last Gallery version "remains available
  for use, but no further updates, bug fixes, or security patches will be
  provided". It points readers at the Terraform/OpenTofu provider and at Vault
  Agent instead
  ([README](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV)).
  The last stable release, 2.0.0, dates from 2021-11-12. The last prerelease,
  2.0.1-Preview, dates from 2022-01-14
  ([PowerShell Gallery](https://www.powershellgallery.com/packages/SecretManagement.Hashicorp.Vault.KV)).
- **It is not maintained by HashiCorp.** The README says "This project is not
  maintained by Hashicorp."
- **2.x does not run on Windows PowerShell 5.1.** Its manifest declares
  `CompatiblePSEditions = @('Core')` and `PowershellVersion = '6.0'`. The
  changelog for 2.0.0 says "Powershell 5.1 is no longer a supported version".
  1.3.0 reintroduced 5.1 support but is not the line anyone downloads: it has
  199 downloads, against 37,281 for 2.0.0. `cred` supports 5.1 and 7, and
  Python 3.8+ (`ARCHITECTURE.md:433-435`).

What the extension does is a thin mapping from the five SecretManagement verbs
onto KV REST calls, made with `Invoke-RestMethod`. Reading its 769-line
extension module, **[source]**, turned up the following. Line numbers are in
`SecretManagement.Hashicorp.Vault.KV.Extension.psm1`:

- **KV v1, v2 and cubbyhole.** The default is v2 (`:22`, `:76-82`). The README
  says it "does not currently support all of the version 2 features like
  versioned secrets": `Get-Secret` returns only the latest version, and
  `Remove-Secret` only soft-deletes the latest version (`:110-112`, with the
  TODO left in place).
- **Auth: Token, AppRole, LDAP, userpass, and token renewal** (`:8-15`,
  `:150-291`). It never reads `VAULT_ADDR`, `VAULT_TOKEN` or `~/.vault-token`.
  A grep for `env:` and `vault-token` finds nothing. The token lives in module
  scope for the session, or in `VaultParameters` as a `ConvertFrom-SecureString`
  string (`:468-470`). Microsoft documents that "the contents of a SecureString
  aren't encrypted on non-Windows systems"
  ([ConvertFrom-SecureString](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)).
  SecretManagement keeps that registry at `$HOME/.secretmanagement` off Windows
  ([SecretManagement README](https://github.com/PowerShell/SecretManagement)).
- **The read path can prompt.** Every `Get-Secret`, `Set-Secret`,
  `Remove-Secret` and `Get-SecretInfo` first calls `Test-SecretVault` (`:490`,
  `:563`, `:597`, `:623`). That function uses `Read-Host` for a missing server
  URL or auth type (`:673-681`). It then calls `sys/health` and `sys/mounts`
  (`:105`), and if it cannot see the mount it asks "Attempt to create it?"
  (`:723-727`). A missing AppRole secret falls through to `Get-Credential`
  (`:204-206`). A script with no console gets a prompt instead of an error.
- **`Get-SecretInfo` reads every secret to list metadata.** It walks `LIST`
  (`:437-450`), then issues a request against the `data/` URI, not
  `metadata/`, for every name, and keeps only `.data.metadata` (`:572`).
  Enumerating a vault therefore fetches every secret value.
- **CAS exists only as a side channel, and it leaks into the secret.** The
  README says `Set-Secret` "Adds/Updates without CheckAndSet", with
  `-Metadata @{cas=<n>}` as the opt-in. `New-VaultAPIBody` does move `cas` into
  `options` (`:356-358`), but the next line copies it into `data`
  unconditionally (`:359`). The version number is therefore written into the
  secret as a field named `cas`.
- **Errors are flattened.** `Invoke-VaultAPIQuery` turns any failure into a
  non-terminating `Write-Error "Received an error: …"` (`:143-145`). A CAS
  conflict, which KV v2 reports as a `400` identified only by its body text
  (`docs/research/kv-v2-check-and-set.md`, "The table", branch
  `research/kv-v2-cas`), gets no special handling.
- **Redirects are followed.** It uses `Invoke-RestMethod` with no
  `-MaximumRedirection` (`:123-141`). This repo's own measurement found that
  following a `302` **re-sends `X-Vault-Token` to the redirect target** on both
  PowerShell editions (`docs/research/powershell-51-http.md`, "Where
  `Invoke-RestMethod` genuinely cannot go", branch `research/powershell-51-http`;
  also [#2](https://github.com/mfic/cred/issues/2)). That is exactly the
  Cloudflare Access case this Vault has
  ([#13](https://github.com/mfic/cred/issues/13)).
- **Secret shape.** A string secret is stored as `{<leaf name>: value}`
  (`:96-100`). `Get-Secret` returns a `Hashtable` by default, or a
  `PSCredential` when `OutputType = 'PSCredential'` (`:497-548`). There is no
  byte-exact file type, and there is no username/secret pair beyond what
  `PSCredential` implies.

What SecretManagement provides on top is one verb set across many vaults:
`Get-Secret`, `Set-Secret`, `Get-SecretInfo`, `Remove-Secret`, and five data
types. It is PowerShell-only by construction. It has no process runner, no
environment injection, no per-repository scoping, and no health report beyond
`Test-SecretVault`.

### The `vault` CLI and Vault Agent: HashiCorp's own, and current

- **`vault kv get -field=<name>`** "Print only the field with the given name…
  The result will not have a trailing newline making it ideal for piping to
  other processes." Its `-version` flag reads any retained version
  ([kv get](https://developer.hashicorp.com/vault/docs/commands/kv/get)).
- **`vault kv put -cas=<n>`**: "In order for a write to be successful, `cas`
  must be set to the current version of the secret". A value can come from
  stdin with `key=-`, which keeps it off argv
  ([kv put](https://developer.hashicorp.com/vault/docs/commands/kv/put)).
- **Token handling.** The default token helper caches the token in
  `~/.vault-token`
  ([token helper](https://developer.hashicorp.com/vault/docs/commands/token-helper)).
- **Vault Agent process supervisor mode** is HashiCorp's `cred exec`: "allows
  Vault secrets to be injected into a process via environment variables". It
  waits for every `env_template` to render before starting the child and, by
  default, "will restart the process whenever an update to an injected secret is
  detected", dynamic secrets nearing expiry included
  ([process supervisor](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/process-supervisor)).
  `cred exec` does not restart anything, and no ticket on the map proposes that
  it should.

This is the real alternative. It exposes every Vault feature: versions,
rollback, custom metadata, every secrets engine, dynamic credentials, leases.
The costs are a Go binary on every machine, an agent config file per process
you want to wrap, and no notion of which credentials a *repository* needs.

## What cred would add that neither of those has

These properties come from the architecture that already ships. Under the
plan they would carry over to a Vault-backed project unchanged, because the
sync layer sits *below* them, at `read_values` and `update_store`
([#1](https://github.com/mfic/cred/issues/1), "The seams the sync layer plugs
into").

1. **The repository declares its credentials.** `.creds/config.json` is
   committed and plaintext. It records which credentials a project needs, what
   each one is for, and which environment variables it becomes
   (`ARCHITECTURE.md:162-166`). Descriptions can be edited without a key
   (`set_metadata`, `python/cred_store.py:1736`; `ARCHITECTURE.md:199-214`).
   Vault has paths and `custom_metadata`, but nothing in a clone says "this repo
   needs `db` and `stripe`, as `DATABASE_URL` and `STRIPE_API_KEY`". The plan
   keeps this file committed and only adds `{"vault": {"mount": …}}`
   ([#1](https://github.com/mfic/cred/issues/1), decision 5).
2. **One command surface, whatever holds the values.** `cred get`, `cred exec`,
   `cred env`, `cred list` and the PowerShell object API (`Get-CredCredential`
   returns a `PSCredential`) are the same for an age-only project and a
   Vault-backed one (`README.md:132-181`). The extension gives PowerShell only.
   The CLI and Agent give shell only, and need an Agent config per process.
3. **Agent-safe usage is built in.** `cred claude` writes a brief that tells
   an agent to use `cred exec` so the value never reaches the transcript
   (`README.md:422-449`). Ticket [#9](https://github.com/mfic/cred/issues/9)
   plans to have it say that a project is Vault-backed.
4. **The credential model is richer than a KV map.** There are three types:
   `secret`, `userpass`, and `file` holding exact bytes with a `base64`
   fallback. All of them are resolved in one place
   (`resolve_entry`, `python/cred_store.py:1880`; `ARCHITECTURE.md:177-233`).
   `file` credentials are never injected as environment variables. The
   extension has no byte-exact type (see above). `vault kv put key=@file` can
   store a file, but nothing records that the value is one.
5. **Two implementations are held to one contract.** Python 3.8+ with only the
   stdlib, and PowerShell 5.1 and 7. They are pinned by
   `tests/Conformance.Tests.ps1` and `tests/Interop.Tests.ps1`
   (`ARCHITECTURE.md:458-515`). The plan keeps the Vault client stdlib-only:
   `urllib` and `System.Net`
   ([#1](https://github.com/mfic/cred/issues/1), decision 7). So the only
   dependency is the network, with no `vault` binary and no PowerShell 7. The
   extension cannot run on 5.1 at all in its current line.
6. **`cred doctor` covers everything.** One report of rows, identical across
   both implementations (`health_rows`, `python/cred_store.py:2321`;
   `ARCHITECTURE.md:482-501`). The planned Vault rows are endpoint, token
   present, reachable, mount present, policy, and mirror in step
   ([#9](https://github.com/mfic/cred/issues/9)). Neither alternative checks the
   repo side and the Vault side together.
7. **Offline reads come from a mirror** (planned). Vault here seals on every
   reboot with 3-of-5 Shamir and no auto-unseal, "so the most likely instance of
   'Vault unreachable' is routine" ([#1](https://github.com/mfic/cred/issues/1),
   "Two facts"). With the mirror, `cred get` and `cred exec` keep working
   against the last pull. The CLI, the extension and the Agent all fail closed
   while Vault is sealed. For this particular Vault, that is the most concrete
   gain on the list.
8. **Conflict detection is on by default** (planned). Every write uses CAS
   ([#1](https://github.com/mfic/cred/issues/1), decision 2), which the
   research shows is opt-in everywhere else: `cas_required` defaults to `false`
   (`docs/research/kv-v2-check-and-set.md`, "What the sync design assumes that
   does not hold", item 8). The extension's CAS path writes the version into the
   secret, as described above.

## What it would cost, or hide

- **Most of Vault disappears.** The plan covers KV v2 only: one secret per
  credential, `{user, secret, encoding}`
  ([#1](https://github.com/mfic/cred/issues/1), decision 3). Dynamic secrets,
  leases, other engines, version history and rollback, and `custom_metadata`
  are not reachable through `cred`. Rotation made directly in Vault is still
  "not yet specified" ([#1](https://github.com/mfic/cred/issues/1)). Vault
  Agent restarts a child when a secret changes; `cred exec` would not.
- **A second copy of every secret on disk.** The mirror is an age store on each
  machine. After a laptop is lost and its AppRole revoked, "the stale mirror on
  that laptop" is "still readable by whoever holds the machine and its age key"
  ([#10](https://github.com/mfic/cred/issues/10)). Plain Vault tools hold no
  local copy.
- **Writes need the network, and the conflict signal is fragile.** "Offline
  reads work, offline writes do not"
  ([#1](https://github.com/mfic/cred/issues/1), decision 2). A CAS conflict is
  a `400` recognisable only by an undocumented English error string, so the
  spec "must commit to substring-matching" it
  (`docs/research/kv-v2-check-and-set.md`, items 1–2). There is no batch write:
  a push of *N* credentials is *N* independent writes that cannot roll back
  (item 10).
- **Teammates without Vault lose access.** A Vault-backed mirror is
  gitignored, so "a colleague with no Vault access can no longer read anything,
  which today they can with an age key"
  ([#1](https://github.com/mfic/cred/issues/1), decision 6).
- **The two implementations would no longer match.** `cred-ps` is planned to
  pull but "refuse to **push**, permanently"
  (`docs/research/powershell-51-http.md`, section 7). This is a choice, made
  because on 5.1 `Invoke-RestMethod` silently transcodes non-ASCII request
  bodies to the ANSI code page.
- **Creating a project needs admin.** Decision 4 was amended on 2026-09-19 to
  one mount per project, and `sys/mounts/*` is an admin capability
  ([#1](https://github.com/mfic/cred/issues/1), decision 4;
  [#12](https://github.com/mfic/cred/issues/12)).
- **It is the first network code in the project**
  ([#1](https://github.com/mfic/cred/issues/1), "Two facts"). That means TLS,
  proxy, private CA and redirect handling, and the token-leak-on-redirect
  hazard above, all maintained twice.

## The comparison

"Unattended" means it works in a script with no console and never prompts.
Rows for cred on Vault are **planned**.

| | Repo declares its creds | `exec` with env injection | Offline while Vault is sealed | CAS by default | Unattended | Windows PS 5.1 | Python, no binary | Full Vault features | Maintained |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **SecretManagement + Vault.KV 2.0** | no | no | no | no, and the opt-in leaks into data | **no**, `Read-Host` on the read path | **no** (1.3.0 only) | no | no, latest version only | **archived** |
| **`vault` CLI** | no | no | no | opt-in `-cas` | yes | yes, a Go binary | no | yes | yes |
| **Vault Agent, supervisor mode** | per Agent config file | yes, and restarts on change | no | n/a, read-only | yes | yes, a Go binary | no | yes, dynamic secrets included | yes |
| **cred, age only (today)** | yes | yes | yes, no Vault involved | n/a, git plus a lock | yes | yes | yes | n/a | this repo |
| **cred on Vault (planned)** | yes | yes | **yes, from the mirror** | **yes** | yes | pull only | yes | KV v2 only | this repo |

## Verdict

**Against the SecretManagement extension: yes, it buys a lot, but that is not
the comparison that decides anything.** The extension is archived, sits on a
framework Microsoft has archived, will not run on Windows PowerShell 5.1 in the
line people use, and prompts in the read path. Its CAS path writes the version
number into the secret, and it follows redirects with the token attached.
Nobody should build on it, and nobody should be pointed at it as the
alternative to building something. Its own author points to Vault Agent
instead.

**Against the `vault` CLI plus Vault Agent: a modest yes, for a specific user,
and mostly for reasons that are not about Vault.** What cred buys over
HashiCorp's own tools:

1. **The repository says what it needs.** Declarations, env mapping and
   descriptions stay committed and readable, and the tools that consume them
   (`exec`, `env`, `claude`, `doctor`) keep working with no change.
2. **Reads survive a sealed Vault.** Given a Vault that seals on every reboot
   and needs a human to unseal, this is the one gain that changes day-to-day
   behaviour.
3. **One interface across age-only and Vault-backed projects, and across
   Python and PowerShell 5.1**, with no `vault` binary to install.
4. **CAS on every write**, where every other client leaves it off.

What it gives up is most of Vault: dynamic secrets, restart on rotation,
history. It also leaves a local plaintext-equivalent copy on every machine and
adds a network layer to maintain twice. That trade is worth it for **a `cred`
user who already organises credentials per repository** and wants Vault as the
system of record behind that. It is not worth it for someone who wants Vault's
features. For them the right advice is Vault Agent's process supervisor mode,
and `cred` adds nothing they would miss.

One more point, which is analysis rather than a cited fact. For the stated
scope of two interactive machines ([#1](https://github.com/mfic/cred/issues/1),
decision 9), the problem "one known source across machines" is already solved
today. Both machines can be recipients of a committed age store, and git is the
sync (`README.md:249-263`). What Vault adds beyond that is:

- values out of git history, which the README itself says revocation
  requires (`README.md:260-263`);
- Vault's audit log;
- one source that systems *other than* `cred` can also read.

If none of those three is wanted, neither the sync layer nor the Vault tools
buy much over what already ships.

## What to do

- **Do not wrap or depend on the SecretManagement extension**, not even as an
  optional path for `cred-ps`. It is frozen with known defects. The plan's
  stdlib HTTP client is the better base, and research shows it can be done
  without a dependency (`docs/research/powershell-51-http.md`, section 7).
- **Do not call the sync layer a provider.** In this codebase that word means
  the crypto seam, and [#9](https://github.com/mfic/cred/issues/9) already asks
  for `--provider` to be disowned explicitly in the spec.
- **Write down why cred-on-Vault beats Vault Agent before building it.** The
  map lists sealed-Vault reads as a constraint. It should be stated as the main
  benefit, along with repo-scoped declarations. If the spec cannot name a
  benefit beyond "the same verbs", recommend Vault Agent in the README and stop.
- **Keep Transit-as-a-provider on the list.** It is the one Vault integration
  that fits the provider contract as written (`ARCHITECTURE.md:116-143`). It
  keeps the store committed, so teammates and git history still work. It needs
  no mirror, no CAS and no merge semantics. It buys central revocation of
  *decryption* without Vault holding the values. [#1](https://github.com/mfic/cred/issues/1)
  already calls it "the cheaper answer to a *different* problem (key
  distribution)". If the underlying wish turns out to be "revoke a lost
  laptop", that is the problem it solves.

## Sources

Repository: `ARCHITECTURE.md`, `README.md`, `src/Cred/Private/Providers.ps1`,
`src/Cred/Public/Providers.ps1`, `python/cred_store.py`,
`tests/fixtures/custom-store-name/.creds/config.json`, and the two research
notes on branches `research/kv-v2-cas` and `research/powershell-51-http`.
Issues [#1](https://github.com/mfic/cred/issues/1),
[#2](https://github.com/mfic/cred/issues/2),
[#9](https://github.com/mfic/cred/issues/9),
[#10](https://github.com/mfic/cred/issues/10),
[#12](https://github.com/mfic/cred/issues/12) and
[#13](https://github.com/mfic/cred/issues/13) on mfic/cred.

External, all fetched 2026-09-23:
[joshcorr/SecretManagement.Hashicorp.Vault.KV](https://github.com/joshcorr/SecretManagement.Hashicorp.Vault.KV)
at `94ff8da` (README, CHANGELOG, manifest, extension `.psm1`) ·
[PowerShell Gallery listing](https://www.powershellgallery.com/packages/SecretManagement.Hashicorp.Vault.KV) ·
[PowerShell/SecretManagement](https://github.com/PowerShell/SecretManagement) ·
[Register-SecretVault](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.secretmanagement/register-secretvault) ·
[ConvertFrom-SecureString](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) ·
[vault kv get](https://developer.hashicorp.com/vault/docs/commands/kv/get) ·
[vault kv put](https://developer.hashicorp.com/vault/docs/commands/kv/put) ·
[token helper](https://developer.hashicorp.com/vault/docs/commands/token-helper) ·
[Vault Agent process supervisor mode](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/process-supervisor).
