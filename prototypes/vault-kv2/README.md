# PROTOTYPE: a stdlib-only KV v2 client

Throwaway. Answers [mfic/cred#11](https://github.com/mfic/cred/issues/11); nothing
here is shipped, and this branch is not meant to be merged.

```
python prototypes/vault-kv2/probe.py
```

Needs the localhost store (`vault-role-id`, `vault-secret-id`, `vault-admin`) and
reachability to `https://vault.qn.questnet.eu`. Everything it writes goes under
the scratch mount `cred/test` behind a timestamped prefix, and step 14 erases it.

- `vault_kv2.py` — the client. **This is the claim under test**, so its size is
  part of the answer and the harness is deliberately not in it.
- `probe.py` — the harness. Prints the status and body of every step.
- `transcript.txt` — a full run, 2026-09-22, against Vault `2.1.1` build
  `2026-09-15T21:21:56Z`.
- `policy_probe.py` — mints a throwaway token per candidate policy to derive the
  minimal capability set empirically. Written after `probe.py` found the
  provisioned policy denies undelete and destroy.

## Verdict

**Stdlib-only holds, comfortably.** The client is **140 lines, 77 of them code**,
and covers AppRole login, read, CAS write, list, metadata, soft-delete, undelete,
destroy and metadata-erase, plus an error type that keeps the response bytes
intact. No dependency is warranted. Nothing was fiddly enough to be worth a
library: `urllib.request.Request(method="LIST")` takes Vault's non-standard verb
without complaint, and `json.dumps(..., ensure_ascii=False).encode("utf-8")` puts
real UTF-8 on the wire with no transcoding step to get wrong.

The one piece of care the client needs is structural, not incidental: `urllib`
raises on non-2xx and gives you the body **once**, through `HTTPError.read()`, so
the error has to be captured at the transport boundary or it is gone. That is
five lines, and it is why `VaultError` holds `bytes` rather than a parsed dict.

## What the wire actually said

Confirming or refuting the ticket's bullets, and the nine `curl -i` checks that
close out `docs/research/kv-v2-check-and-set.md` (branch `research/kv-v2-cas`).

| Claim | Result |
| --- | --- |
| Authenticate with no credential on a command line | **Confirmed.** Ids come out of the localhost store on a pipe; the AppRole token is `orphan: true`, `ttl=300s`, policies `['cred-test','default']` |
| `PUT` `cas=0` twice | **Confirmed create-only** — second attempt is a `400` |
| `GET` returns value and version in one request | **Confirmed** at `data.metadata.version` |
| Stale `cas` — exact status and body | **Confirmed byte for byte:** `400 {"errors":["check-and-set parameter did not match the current version"]}` |
| `cas` omitted under `cas_required=true` | `400 {"errors":["check-and-set parameter required for this call"]}` — distinct string, same status |
| `LIST` a prefix | **Confirmed.** `LIST cred/test/metadata/<prefix>` → `['api','db']`; at mount root, sub-prefixes come back with a trailing `/` |
| Soft-delete / undelete / destroy | **Confirmed**, with a correction — see below |
| `cas=0` against soft-deleted and destroyed | **Confirmed failing.** `cas=0` is "no metadata entry", not "if absent" |
| Version numbering after `DELETE .../metadata/<path>` | **Confirmed restarts at 1** |
| `mount_type` in `404` bodies | **Confirmed `""`** on errors, `"kv"` on a `200`. Still don't depend on it |
| Non-ASCII byte-exact through `urllib` | **Confirmed.** `tok-äöü-🔑` and `a/b c  d` round-trip identical, bytes compared |
| `403` next to `404` | **Distinguishable** — see below |
| Does `urllib` re-send `X-Vault-Token` through a `302`? | **Yes.** See below |

### The three absence states

All three are `404`. They are separated by the body, and `deletion_time` is
**not** the discriminator:

| State | Body |
| --- | --- |
| Soft-deleted | `data.data: null`, `deletion_time` set, `destroyed: false` |
| Destroyed | `data.data: null`, **`deletion_time: ""`**, `destroyed: true` |
| Never existed | `{"errors":[]}` — no `data` key at all |

Destroying **clears** `deletion_time`, so a reader that checks it first will call
a destroyed secret "present". Check `destroyed`, then `deletion_time`, then fall
back to absent. This is exactly the ordering the ticket's first comment warned
about, and it is now observed rather than inferred.

### `403` and `404` are distinguishable, and that is a leak

With a policy granting nothing on the path:

```
403 {"errors":["1 error occurred:\n\t* permission denied\n\n"]}   existing secret
403 {"errors":["1 error occurred:\n\t* permission denied\n\n"]}   nonexistent secret
404 {"errors":[]}                                                 nonexistent, WITH capability
```

Good for diagnostics: `403` means "your policy", `404` means "your path", and
`cred doctor` can say which. But note the direction — the `403`/`404` split tells
an *authorised* caller that a path does not exist, and tells an unauthorised one
nothing. That is the safe direction, and it contradicts the research note's worry
that `404` might mask denial. It does not, here.

### `urllib` re-sends `X-Vault-Token` across a cross-host redirect

`#4` observed this on both PowerShell editions and the map declined to assert it
of `urllib` without evidence. Evidence, on Python 3.11.15:

```
302 -> https://questnet.cloudflareaccess.com/cdn-cgi/access/login/vault.questnet.eu
headers carried onto the redirect: {'User-agent': ..., 'X-vault-token': 'hvs.CANARY...',
                                    'Authorization': 'Bearer CANARY-BEARER'}
final host: questnet.cloudflareaccess.com status: 200
```

`HTTPRedirectHandler` strips only the content headers. Both the Vault token and
an `Authorization` header are handed to Cloudflare. The behaviour is universal,
not a PowerShell quirk, and `_NoRedirects` in the client is therefore not a
precaution but a requirement.

One detour worth recording for [#13](https://github.com/mfic/cred/issues/13):
with `urllib`'s **default** `User-Agent`, `vault.questnet.eu` does not return a
`302` at all. It returns `403 Error 1010 browser_signature_banned` — Cloudflare
blocks `Python-urllib/3.11` by signature before Access is ever reached. Stage 2
will have to set a `User-Agent`, and the first thing it will meet is a bot rule,
not a login page.

## The cred-test policy is short of four grants

`probe.py` step 8b got `403 permission denied` on both undelete and destroy, so
`policy_probe.py` derived the whole matrix by minting one token per candidate
grant. Every row below was observed, not inferred:

| Operation | Grant that allows it |
| --- | --- |
| create a secret | `data/*` `create` |
| update a secret | `data/*` `update` |
| read a secret | `data/*` `read` |
| soft-delete the latest version | `data/*` `delete` |
| soft-delete a *specific* version | `delete/*` `update` |
| undelete | `undelete/*` `update` |
| destroy | `destroy/*` `update` |
| list keys | `metadata/*` `list` |
| read metadata | `metadata/*` `read` |
| erase all history | `metadata/*` `delete` |
| write metadata, path has no metadata entry | `metadata/*` **`create`** (`update` alone → `403`) |
| write metadata, path already has one | `metadata/*` `update` |

Two things fall out.

**`undelete` and `destroy` are their own API paths and the policy names neither.**
`delete` on `data/*` covers only soft-deleting the latest version, which is why
that one step passed and the other two did not. Whether `cred` needs them at all
is [#8](https://github.com/mfic/cred/issues/8)'s question; if it does, the policy
needs `delete/*`, `undelete/*` and `destroy/*`, each with `update`.

**Metadata writes need `create` *and* `update`, not either.** They are not
interchangeable: `update` alone is denied on a path with no metadata entry yet.
So a policy that writes metadata needs both, and one that never does needs
neither — `cred` only needs them if it sets `custom_metadata` or a per-secret
`max_versions`, since mount-level `cas_required` is already set. Undecided, and
it belongs to [#7](https://github.com/mfic/cred/issues/7) and
[#8](https://github.com/mfic/cred/issues/8) rather than here.

The read-and-write-only policy the sync layer needs today is therefore:

```hcl
path "cred/<project>/data/*"     { capabilities = ["create","read","update"] }
path "cred/<project>/metadata/*" { capabilities = ["list","read"] }
path "cred/<project>/config"     { capabilities = ["read"] }
```

with `delete` on `data/*`, the three lifecycle paths, and `delete` on
`metadata/*` added only once #8 says deletion propagates.
