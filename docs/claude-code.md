# Pointing a Claude Code session at a project's credentials

A worked example. Say you have `C:\work\acme-api`, a Node service that talks to
Stripe, Postgres and GitHub, and you want Claude Code to be able to run its
deploy and its tests without you pasting secrets into the chat.

## 1. Put the credentials in the repo

```powershell
cd C:\work\acme-api
cred init

cred add acme-api/stripe --desc "Stripe live secret key" --env STRIPE_SECRET_KEY
cred add acme-api/db --user svc_acme --desc "Postgres, prod replica"
cred add acme-api/gh --desc "GitHub PAT, repo scope" --env GITHUB_TOKEN
```

Each `add` prompts without echoing. Nothing lands in your shell history.

```powershell
cred list acme-api
```

```
Key    Type     Environment          Description
---    ----     -----------          -----------
db     userpass DB_USER, DB_PASSWORD Postgres, prod replica
gh     secret   GITHUB_TOKEN         GitHub PAT, repo scope
stripe secret   STRIPE_SECRET_KEY    Stripe live secret key
```

Commit it. `.creds/store.age` is ciphertext; `.creds/config.json` is a manifest
with no values in it.

```powershell
git add .creds
git commit -m "Add encrypted credential store"
```

## 2. Tell Claude the store exists

```powershell
cred claude --write
```

This writes a block into `C:\work\acme-api\CLAUDE.md`, delimited by
`<!-- cred:begin -->` / `<!-- cred:end -->` so re-running updates it in place:

```markdown
## Credentials

This repository's secrets live encrypted in `.creds/` and are handed out by the
`cred` CLI. Never write a secret into a file, a commit, or your reply.

| Credential | Type | Environment variables | What it is |
| --- | --- | --- | --- |
| `acme-api/db` | userpass | `DB_USER, DB_PASSWORD` | Postgres, prod replica |
| `acme-api/gh` | secret | `GITHUB_TOKEN` | GitHub PAT, repo scope |
| `acme-api/stripe` | secret | `STRIPE_SECRET_KEY` | Stripe live secret key |

**Preferred — run a command with the secrets injected.** The value never enters
this conversation:

    cred exec acme-api -- <command> [args]

**To verify a value you already have a candidate for, with zero characters of
the real one crossing in either direction:**

    echo "$candidate" | cred get acme-api/<key> --check

Prints `match` or `no match` and exits 0/1. The candidate must come via stdin,
never as an argument — an argument lands in shell history.

**To sanity-check a value without holding it** — catch an empty paste or an
obviously wrong one:

    cred get acme-api/<key> --stat      # length and character classes, no characters
    cred get acme-api/<key> --reveal partial   # a few trailing characters and the length

**Only when a value must actually be read** (and then treat the output as poison
— do not echo it back). `--reveal full` is an explicit name for this; the bare
command does the same thing:

    cred get acme-api/<key>
    cred get acme-api/<key> --reveal full

A `file`-kind credential (a cert, a key, a keytab) has no meaningful masked or
partial form, so `--check`, `--stat` and `--reveal partial` all refuse it — use
`--reveal full` or `--out <path>` instead.

**To see what exists without decrypting anything:**

    cred list acme-api
```

Commit that too, so every future session — and every colleague — starts knowing.

```powershell
git add CLAUDE.md && git commit -m "Tell Claude about the credential store"
```

## 3. Work

Now you can say things like:

> Run the integration tests against the prod replica.

and Claude runs

```
cred exec acme-api --only db -- npm run test:integration
```

The child process gets `DB_USER` and `DB_PASSWORD`. **Claude never sees either
value** — they exist only inside a process it spawned and cannot read back. Its
transcript contains the command, not the secret. `--only db` means the Stripe
key and the GitHub token are not injected at all.

Or:

> Deploy to staging.

```
cred exec acme-api -- npm run deploy:staging
```

Or, when something genuinely needs the value in the open — a one-off `curl`
against an API you are debugging:

```
curl -H "Authorization: Bearer $(cred get acme-api/gh -n)" https://api.github.com/user
```

Here the token *does* pass through the session. That is why the brief tells the
agent to prefer `cred exec`, and why `cred get` is described as the exception.

Or, when the task is "is this the right value", not "run something with it" —
say a deploy just failed and you want Claude to rule out a stale secret without
ever holding the real one:

```
cred get acme-api/stripe --stat
```

```
32 characters — lower, digit
```

That alone might be enough ("it's 32 characters, that's the right shape").
If Claude already has a candidate value from somewhere else in the
conversation — a value the user pasted, or one read from a `.env.example` —
and the question is whether it's the *same* one, `--check` answers that
without exposing either value:

```
echo "$candidate" | cred get acme-api/stripe --check
```

```
no match
```

And if a human eyeballing it is what's needed — "does this look like the key
in the dashboard" — `--reveal partial` shows a masked shape instead of the
value:

```
cred get acme-api/stripe --reveal partial
```

```
********xyz (32 characters)
```

None of these three ever put the full secret in Claude's context. `cred get`
without a flag is the one command in this table that does, which is why it is
last on the list, not first.

## Why this shape

The interesting property is that **the agent's capability and the agent's
knowledge are separated.**

- It can *use* every credential, because it can run `cred exec`.
- It knows *what exists and what each one is for*, because `config.json` is
  plaintext and `cred list` needs no key at all.
- It does not *hold* any of them, unless you ask for something that requires it.

Compare the alternatives. A `.env` file means the values are in the working
tree, one `Read` tool call from being in the context window, and one careless
`git add` from being in a public repo. Pasting a secret into the chat puts it in
the transcript permanently. Both give the agent knowledge it does not need in
order to do the job.

## Running the session itself with credentials

If you would rather the whole session have the environment set — for a long
task, or for tooling that reads env vars at startup — launch Claude Code
through `cred exec`:

```bash
cd /work/acme-api      # or C:\work\acme-api
cred exec acme-api -- claude
```

Everything the session spawns inherits the variables. This is more convenient
and strictly less contained: the agent can now read `$env:STRIPE_SECRET_KEY`
directly. Use it when the task warrants it, and prefer `--only` to narrow what
is in scope:

```powershell
cred exec acme-api --only db,gh -- claude
```

## Onboarding a colleague

They clone the repo and run:

```bash
cred keygen              # prints their public key
cred list                # works immediately: they can see what they need
```

`cred list` succeeds without a key, so they can see what the project requires
before anyone grants them anything. You then run:

```powershell
cred recipients add age1theirpublickey...
git commit -am "Grant sam access to acme-api credentials"
git push
```

They pull, and `cred get` / `cred exec` work. No secret was ever sent over any
channel — you exchanged a public key.

## When it goes wrong

`cred doctor` from inside the repo checks every moving part and prints a fix for
each problem it finds:

```
Check                Status  Detail                                   Fix
-------------------  ------  ---------------------------------------  ---
python               Ok      3.14.0 (win32)
provider:age         Ok      age and age-keygen found.
identity             Ok      ...cred\identity.txt
identity protection  Ok      file-permissions
project              Ok      acme-api at C:\work\acme-api
store                Ok      ...acme-api\.creds\store.age
decrypt              Ok      3 credential(s) readable.
recipients           Ok      2 recipient(s); you are one.
```

If a session reports it cannot decrypt, that is the agent correctly refusing to
guess: either the key is missing on that machine or it is not a recipient. The
brief tells it to stop and say so rather than work around it.
