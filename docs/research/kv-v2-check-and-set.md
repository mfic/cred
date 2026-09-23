# What KV v2 actually guarantees for check-and-set

The Vault map stakes the whole sync architecture on one claim: that KV v2's
per-secret version numbers are a conflict-detection scheme good enough to
replace timestamps and a merge engine. This note is the check on that claim,
against HashiCorp's own documentation and, where the documentation is silent,
against the source that owns the behaviour.

**`vault.questnet.eu` could not be used.** It sits behind Cloudflare Access,
every call returns `302` with `Www-Authenticate: Cloudflare-Access`, and no
credentials exist yet. So nothing here was observed on a wire. Every claim is
graded, and the grades matter more than usual:

- **[DOCS]** — stated in HashiCorp's official documentation, quoted and linked.
- **[SOURCE]** — not documented; read out of the plugin or Vault core source,
  cited to file and line at a named tag. Correct for that version, and an
  implementation detail HashiCorp has never promised to keep.
- **[UNCONFIRMED]** — neither documented nor settled by source. Labelled, never
  guessed, with the one-line experiment that would close it.

Versions pinned: the KV v2 API page as rendered for Vault **v1.21.x / v2.x**
(byte-identical between them but for one path placeholder), and
`hashicorp/vault-plugin-secrets-kv` at **`main` = v0.27.0**, commit
`3161a36`, 2026-09-16. The CAS logic and the read handler were checked at tags
v0.11.0, v0.14.2, v0.20.0 and v0.26.2 and are byte-identical, so this is
long-standing behaviour rather than a snapshot of a moving target. Note that
the docs now render from
[`hashicorp/web-unified-docs`](https://github.com/hashicorp/web-unified-docs);
`hashicorp/vault`'s own `website/content/` paths 404.

**The headline.** The mechanism is real and the version numbers behave exactly
as decision 2 needs. What does *not* hold is everything around the edges: a CAS
conflict is an HTTP **400** that is undocumented and distinguishable from an
ordinary bad request only by an error string; a soft-deleted secret reads as
**404** whose body is also undocumented; and `404` officially means *either*
absent *or* denied. The design is sound. Three of the error paths it assumes
are cleanly separable are not.

## The table

Primitive to call to response. Every row is expanded and cited below.

| Primitive | Call | Response |
| --- | --- | --- |
| Write with CAS | `POST <mount>/data/<path>` body `{"options":{"cas":N},"data":{…}}` | `200`, new number at `data.version` [DOCS] |
| Create only | same, `"cas":0` | `200` if no metadata entry exists, else `400` [DOCS] |
| **CAS conflict** | stale `cas` | **`400`** `{"errors":["check-and-set parameter did not match the current version"]}` [SOURCE] |
| CAS omitted, required | no `cas` in `options` | `400` `{"errors":["check-and-set parameter required for this call"]}` [SOURCE] |
| Read | `GET <mount>/data/<path>` | `200`, data *and* `data.metadata.version` in one request [DOCS] |
| Read soft-deleted | same | `404` **with** a body: `data.data: null`, `metadata.deletion_time` set, `destroyed: false` [SOURCE] |
| Read destroyed | same | `404`, same shape, `destroyed: true` [SOURCE] |
| Read absent | same | `404` `{"errors":[]}` — no `metadata` key [SOURCE]; body shape [DOCS] |
| Read denied | same | `403`, *or* `404` — Vault blurs these deliberately [DOCS] |
| Version history | `GET <mount>/metadata/<path>` | `200`, `versions` map, no secret data; separate policy path [DOCS] |
| Enumerate | `LIST <mount>/metadata/<prefix>` | `200` `{"data":{"keys":["foo","foo/"]}}`; one level; `404` `{"errors":[]}` if empty [DOCS] |
| Soft delete latest | `DELETE <mount>/data/<path>` | `204`, recoverable [DOCS] |
| Soft delete versions | `POST <mount>/delete/<path>` body `{"versions":[1,2]}` | `204` [DOCS] |
| Undelete | `POST <mount>/undelete/<path>` same body | `204`; no-op on a destroyed version [SOURCE] |
| Destroy | `PUT <mount>/destroy/<path>` same body | `204`, unrecoverable, metadata entry survives [DOCS] |
| Erase | `DELETE <mount>/metadata/<path>` | `204`; only call that frees `cas=0` again [DOCS] |
| Force CAS | `POST <mount>/config` `{"cas_required":true}` | mount-wide, no per-secret escape [DOCS + SOURCE] |
| Force CAS, one secret | `POST <mount>/metadata/<path>` `{"cas_required":true}` | per-secret, needs no mount admin [DOCS] |

Sources for the whole table: the
[KV v2 API reference](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)
and the
[API overview's status codes](https://developer.hashicorp.com/vault/api-docs),
plus [`path_data.go`](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_data.go)
for the rows marked [SOURCE].

## The CAS write, and the one response that matters

A check-and-set write is an ordinary KV v2 write with one extra key. `POST`
(or `PUT`) to `/:secret-mount-path/data/:path`, and `cas` lives **inside
`options`**, never beside `data`. The API reference's own sample body
([KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)):

```json
{
  "options": {
    "cas": 0
  },
  "data": {
    "foo": "bar",
    "zip": "zap"
  }
}
```

So updating a credential currently at version 7 means
`{"options":{"cas":7},"data":{"user":…,"secret":…,"encoding":…}}`. The docs
describe the parameter as: "`cas` (int: `<optional>`) - This flag is required if
`cas_required` is set to true on either the secret or the engine's config. If
not set the write will be allowed. In order for a write to be successful, `cas`
must be set to the current version of the secret." Note the default: **a write
with no `cas` at all simply succeeds and overwrites.** CAS is opt-in per
request unless something forces it.

`PUT` works as well as `POST` — both `logical.UpdateOperation` and
`logical.CreateOperation` are registered on the path
([`path_data.go` L88-104](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_data.go))
— which is [SOURCE], not documented.

### The CAS failure response

This is the single highest-value fact in the ticket, and the finding is that
**HashiCorp does not document it.** The KV v2 API page contains no error-response
example whatsoever: not for CAS, not for anything. Neither does the
[`vault kv put` CLI page](https://developer.hashicorp.com/vault/docs/commands/kv/put)
nor the
[versioned-KV tutorial](https://developer.hashicorp.com/vault/tutorials/secrets-management/versioned-kv).
The only documented anchor is the generic line in the
[API overview](https://developer.hashicorp.com/vault/api-docs): "`400` -
Invalid request, missing or invalid data", and the generic error envelope,
"A common JSON structure is always returned to return errors … This structure
will be returned for any HTTP status greater than or equal to 400":

```json
{
  "errors": [
    "message",
    "another message"
  ]
}
```

Traced through the source, a stale `cas` returns **HTTP 400 Bad Request**,
`Content-Type: application/json`, with this body (Go's `json.Encoder`, so
compact with a trailing newline) — **[SOURCE]**:

```json
{"errors":["check-and-set parameter did not match the current version"]}
```

and a write that omits `cas` where it is required returns the same **400** with:

```json
{"errors":["check-and-set parameter required for this call"]}
```

The chain, each link cited:

1. The strings, in `validateCheckAndSetOption`
   ([`path_data.go` L276-304](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_data.go)) —
   mismatch at L296-298, `if uint64(cas) != meta.CurrentVersion { return
   errors.New("check-and-set parameter did not match the current version") }`;
   required at L299-301, `} else if config.CasRequired || meta.CasRequired {
   return errors.New("check-and-set parameter required for this call") }`. A
   third string exists at L293-295, `"error parsing check-and-set parameter"`,
   for a `cas` that will not decode.
2. Error to logical response, same file L391-394 (write) and L607-609 (patch):
   `return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest`.
3. Logical response to HTTP status:
   [`http/logical.go` L388](https://raw.githubusercontent.com/hashicorp/vault/main/http/logical.go)
   hands off to
   [`sdk/logical/response_util.go`](https://raw.githubusercontent.com/hashicorp/vault/main/sdk/logical/response_util.go),
   L109-113 ("If we actually have a response, start out with bad request" —
   `statusCode = http.StatusBadRequest`) and L131-132
   (`case errwrap.Contains(err, ErrInvalidRequest.Error()): statusCode =
   http.StatusBadRequest`).
4. Body shape, same file L200-202: `type errorResponse struct { Errors []string
   \`json:"errors"\` }`.

**There is no `409 Conflict` and no `412 Precondition Failed` anywhere in this
path.** A lost race, a malformed `options` map, an undecodable `cas`, a missing
`cas` and a plain bad request are all `400`, and the only thing separating them
is an undocumented English sentence. A client that wants to say *"someone else
changed `db`; run `cred pull`"* has to substring-match
`"did not match the current version"`. One `curl -i` with a stale `cas` against
a dev Vault would confirm the bytes and is worth doing before the spec commits.

### `cas=0`

Reliable for create-only, but the condition is narrower than "the secret is not
there". The docs say: "If set to 0 a write will only be allowed if the key
doesn't exist as unset keys do not have any version information", and then, in
the same paragraph, the important caveat: "Also remember that soft deletes do
not remove any underlying version data from storage. In order to write to a
soft deleted key, the `cas` parameter must match the key's current version."

What `cas=0` really tests is *no metadata entry exists*: `cas` is compared to
`meta.CurrentVersion`, and a freshly constructed `KeyMetadata` has
`CurrentVersion == 0` ([`path_data.go` L384-389](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_data.go),
[SOURCE]). So `cas=0` **fails** against a soft-deleted path ([DOCS], quoted
above), and also against a path whose every version is destroyed, and against
one aged out by `max_versions` ([SOURCE]). Only
`DELETE <mount>/metadata/<path>` clears the metadata entry; after that `cas=0`
works again and numbering restarts at 1.

A related constraint: a patch cannot bootstrap. "A patch operation must be
attempted on an existing key, thus the provided `cas` value must be greater
than 0."

## `cas_required`: yes, CAS can be made mandatory

The field is `cas_required` at both levels, and it is **`false` by default at
both** — documented as `(bool: false)` in each place, and shown as
`"cas_required": false` in both `GET <mount>/config` and
`GET <mount>/metadata/<path>` sample responses
([KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)).

- **Mount-wide:** `POST <mount>/config`. "`cas_required` (bool: false) - If true
  all keys will require the `cas` parameter to be set on all write requests."
- **Per secret:** `POST <mount>/metadata/<path>` (and `PATCH` of the same).
  "`cas_required` (bool: false) - If true, the key will require the `cas`
  parameter to be set on all write requests. If false, the backend's
  configuration will be used."

That last sentence reads like an override. It is not: the two are combined with
a logical **OR**, `} else if config.CasRequired || meta.CasRequired {`
([`path_data.go` L299](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_data.go),
[SOURCE]). Mount `true` plus secret `false` still requires `cas`. The plugin
even says so out loud, in a warning it attaches to the metadata write
([`path_metadata.go` L455-458](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_metadata.go)):

```go
if cOk && config.CasRequired && !casRaw.(bool) {
    resp = &logical.Response{}
    resp.AddWarning("\"cas_required\" set to false, but is mandated by backend config. This value will be ignored.")
}
```

One wrinkle worth knowing: it *persists* `meta.CasRequired = false` anyway
(L481-483), so the ignored per-secret value becomes live again if someone later
turns the mount config back off.

**So yes — a mount can be configured so a non-CAS write is impossible.**
`POST <mount>/config {"cas_required": true}` closes it mount-wide with no
per-secret escape hatch, and it covers brand-new secrets too, because the check
reads `config.CasRequired` directly and a path with no metadata must therefore
send `cas=0`. The enforcement surface is exactly two handlers,
`pathDataWrite` (L391) and the patch handler (L607); nothing else in the plugin
mints a version except `pathDataRecover` (L482-549, new in v0.27.0), which calls
`pathDataWrite` with no `options` — so **snapshot recover onto a `cas_required`
mount fails** with `check-and-set parameter required for this call` rather than
bypassing CAS. An availability hole, not a security one. [SOURCE]

The useful half for this project: because `cas_required` also exists per secret,
`cred` can make its own credentials CAS-only **without mount admin** — one
`POST <mount>/metadata/<project>/<key> {"cas_required": true}` per secret it
creates. That matters given map decision 4, which deliberately keeps
`sys/mounts/*` out of onboarding. Turning it on mount-wide is the stronger
guarantee but it is a decision about *every* project sharing the mount.

## Version numbers behave exactly as the design needs

This is the part that holds, cleanly.

**Monotonic and never reused.** The only mutation of the counter anywhere in the
plugin is `k.CurrentVersion++` in `AddVersion`
([`path_data.go` L830](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_data.go)) —
no other assignment to it exists. So a number survives a soft delete, an
undelete, a destroy and a `max_versions` rollover, and is never handed out
twice. [SOURCE]

The one exception: `DELETE <mount>/metadata/<path>` deletes each version and
then the key entry
([`path_metadata.go` L612-651](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_metadata.go)),
after which **numbering restarts at 1**. [SOURCE] A `cred` that erases metadata
on `unset` would be resetting a counter that other machines have cached.

**The new number comes back on the write.** No second read. Verbatim sample
response for Create/Update secret [DOCS]:

```json
{
  "data": {
    "created_time": "2018-03-22T02:36:43.986212308Z",
    "custom_metadata": {
      "owner": "jdoe",
      "mission_critical": "false"
    },
    "deletion_time": "",
    "destroyed": false,
    "version": 1
  }
}
```

`data.version` is post-increment — the handler builds the response from
`meta.CurrentVersion` after `AddVersion` has run (L440, L447-455). It may also
attach a **warning** if cleanup of aged-out versions failed (L457-462); the
write still succeeded, so a client must not treat `warnings != null` as failure.
[SOURCE]

## `max_versions`: default 10, and a documentation defect

Default is **10**; `0` means "unset, use the default". Settable on
`<mount>/config` and per secret on `<mount>/metadata/<path>`
([KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2),
and [the kv-v2 overview](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2)
states it plainly: "a key can retain a configurable number of versions. The
default is 10 versions.").

At the limit the oldest version's data is **hard-deleted from storage and its
entry removed from the metadata `versions` map** (`delete(k.Versions, i)`,
[`path_data.go` L849-851](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_data.go)),
and `oldest_version` advances. The counter keeps climbing regardless. This is
observably different from `destroy`, which leaves the entry in place with
`"destroyed": true` — **an aged-out version vanishes, a destroyed one does not.**
That difference is [SOURCE] and undocumented.

**The defect.** The docs say a key's metadata `max_versions` "can overwrite"
the mount value. `AddVersion` actually uses `max(k.MaxVersions,
configMaxVersions)` (L837-843), so a per-secret value *lower* than the mount's
is silently ignored:

| mount `max_versions` | secret `max_versions` | versions actually kept |
| --- | --- | --- |
| 0 (unset) | 0 (unset) | 10 |
| 0 (unset) | 3 | 3 |
| 10 | 3 | **10** — per-secret value ignored |
| 3 | 10 | 10 |
| 5 | 0 (unset) | 5 |

Per-secret `max_versions` therefore only ever *raises* retention unless the
mount leaves its own value at `0`. Byte-identical at v0.11.0, v0.14.2, v0.20.0,
v0.26.2 and main — long-standing, not a regression. **[SOURCE], and it
contradicts the wording on the API page.** A live test (mount 10, secret 2,
five writes, read metadata) would settle it. Separately, lowering the limit is
applied lazily on the next write, not immediately, so reducing it prunes nothing
until something is written. [SOURCE]

Contrast `delete_version_after`, where the cap runs the *other* way and the docs
say so: "If the value is greater than the backend's `delete_version_after`, the
backend's `delete_version_after` will be used."

## Delete, destroy, and time

Five endpoints, all [DOCS] from the
[KV v2 API reference](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2),
all returning **204** on success:

1. **`DELETE <mount>/data/<path>`**, no body. Latest version only. "This
   endpoint issues a soft delete of the secret's latest version … This marks the
   version as deleted and will stop it from being returned from reads, but the
   underlying data will not be removed. A delete can be undone using the
   `undelete` path."
2. **`POST <mount>/delete/<path>`**, body `{"versions": [1, 2]}`. Same, for named
   versions. "The versioned data will not be deleted, but it will no longer be
   returned in normal get requests."
3. **`POST <mount>/undelete/<path>`**, same body. "This restores the data,
   allowing it to be returned on get requests."
4. **`PUT <mount>/destroy/<path>`**, same body. "Permanently removes the
   specified version data … Their data will be permanently deleted." (The API
   page's table says `PUT`; the
   [destroy cookbook](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/cookbook/destroy-data)
   says `POST`. Both work — it is the create/update capability either way.)
5. **`DELETE <mount>/metadata/<path>`**, no body. "This endpoint permanently
   deletes the key metadata and all version data for the specified key. All
   version history will be removed."

Two behaviours that are not in the docs and will surprise a client [SOURCE]:
every one of these handlers `return nil, nil` when the key does not exist, so
**deleting something that was never there is a `204`, not a `404`** (the CLI's
"Success! Data deleted (if it existed) at: …" is the tell). And
`pathUndeleteWrite` does `if lv == nil || lv.Destroyed { continue }`, so
**undeleting a destroyed version is a silent no-op** — 204, no error, nothing
restored.

Recoverability is documented in plain words on
[the kv-v2 overview](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2):
"The `kv` v2 plugin uses soft deletes to make data inaccessible while allowing
data recovery. When an entry is permanently deleted, Vault purges the underlying
version data and marks the key metadata as destroyed." And the
[undelete cookbook](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/cookbook/undelete-data):
"You can restore data from soft deletes … as long as the `destroyed` metadata
field for the targeted version is `false`."

### `delete_version_after`

Default **`"0s"` — off — at both sites** [DOCS]. On `<mount>/config`:
"`delete_version_after` (string:"0s") - If set, specifies the length of time
before a version is deleted." On `<mount>/metadata/<path>`: "Set the
`delete_version_after` value to a duration to specify the `deletion_time` for
all new versions written to this key. If not set, the backend's
`delete_version_after` will be used. If the value is greater than the backend's
`delete_version_after`, the backend's `delete_version_after` will be used."

`deletionTime(creation, mount, meta)` resolves to creation plus the **minimum
non-zero** of the two, with `-1s` as a sentinel for disabled
([`delete_version_after.go`](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/delete_version_after.go),
[SOURCE]). The effect is a **soft** delete only: `deletion_time` is stamped on
the version at write time and the read handler starts treating it as deleted
once that time passes; the data is not destroyed, so it stays recoverable. A
version whose `deletion_time` is still in the future reads normally, `200` with
data. [SOURCE]

This is the one mechanism by which **a secret can stop being readable with
nobody having touched it.** It is off by default, but it is a *mount-level*
setting, which map decision 4's shared mount puts in someone else's hands.

## Telling soft-deleted from destroyed from never-existed

The ticket's other headline question, and again the docs are silent: the KV v2
API page documents **only** the `200` for `GET <mount>/data/<path>`. It never
mentions `404`, never mentions `deletion_time` appearing on a read, never shows
a deleted or destroyed body. The plugin's own OpenAPI `Responses` map for the
read operation declares only `http.StatusOK`. Everything below is [SOURCE],
from `pathDataRead`
([`path_data.go`](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_data.go),
function at L186; `meta == nil` at L198-200; `vm == nil` at L209-212; the
`data: nil` plus metadata response at L214-225; the soft-delete 404 at L227-237
with `RespondWithStatusCode(resp, req, http.StatusNotFound)` at L235; the
destroyed 404 at L240-242) — byte-identical at
[tag v0.20.0](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/v0.20.0/path_data.go).
The plugin's comments say it outright: "If the version has been deleted return
metadata with a 404" and "If the version has been destroyed return metadata with
a 404".

Wire format for those two comes from `RespondWithStatusCode`
([`sdk/logical/response.go` L205](https://raw.githubusercontent.com/hashicorp/vault/main/sdk/logical/response.go))
marshalling into `HTTPRawBody`, the envelope struct `logical.HTTPResponse`
([`translate_response.go`](https://raw.githubusercontent.com/hashicorp/vault/main/sdk/logical/translate_response.go),
field order `request_id, lease_id, renewable, lease_duration, data, wrap_info,
warnings, auth, mount_type`), written by `respondRaw`
([`http/logical.go` L546](https://raw.githubusercontent.com/hashicorp/vault/main/http/logical.go),
`nonEmpty := status != http.StatusNoContent` at L586).

**(a) Soft-deleted — `404` with a full data envelope:**

```json
{
  "request_id": "9f2a8d3e-…",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "data": null,
    "metadata": {
      "created_time": "2024-11-13T21:51:50.898782695Z",
      "custom_metadata": null,
      "deletion_time": "2024-11-15T00:45:04.057772212Z",
      "destroyed": false,
      "version": 1
    }
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null,
  "mount_type": ""
}
```

The load-bearing parts: status `404`, `data.data` is `null`,
`data.metadata.deletion_time` is non-empty, `destroyed` is `false`. The
timestamp shape matches HashiCorp's own
[delete cookbook](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/cookbook/delete-data)
output (`deletion_time    2024-11-15T00:45:04.057772212Z`).

**(b) Destroyed — `404`, same shape, `destroyed: true`:**

```json
{
  "request_id": "9f2a8d3e-…",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "data": null,
    "metadata": {
      "created_time": "2024-11-13T21:52:10.326204209Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": true,
      "version": 2
    }
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null,
  "mount_type": ""
}
```

`deletion_time` is `""` when a version is destroyed without a prior soft delete,
matching the destroy cookbook's `deletion_time  n/a` / `destroyed  true`.
**Check `destroyed` before `deletion_time`.** A version soft-deleted *and then*
destroyed has both fields set, and the deleted branch fires first — so a client
that tests `deletion_time` first will call an unrecoverable secret recoverable
and tell the user to run an undelete that silently does nothing.

**(c) Never existed, or metadata deleted, or an unknown `?version=N` — `404`
and exactly:**

```json
{"errors":[]}
```

`meta == nil` returns `nil, nil` (L198-200), then `RespondErrorCommon`
([`response_util.go` L27-30](https://raw.githubusercontent.com/hashicorp/vault/main/sdk/logical/response_util.go)):
`case req.Operation == ReadOperation …: if resp == nil { return
http.StatusNotFound, nil }`, and `GenerateNonLogicalErrorResponse` (L208) builds
`&errorResponse{Errors: make([]string, 0, 1)}` and appends nothing. This exact
body *is* documented, indirectly: the
[API overview](https://developer.hashicorp.com/vault/api-docs) publishes it as
Vault's canonical empty result — "If the list result is an empty set, Vault
responds with status code 404 and the following JSON:" followed by
`{"errors":[]}`.

Two more cases land in bucket (c) and are easy to mistake for a missing secret:
an explicit `?version=N` for a version never created or since evicted by
`max_versions` (`vm == nil`, L209-212), and a path whose metadata was removed by
`DELETE <mount>/metadata/<path>`.

### The discriminator

One `GET` does separate all three. On `404`, parse the body:

- `data.metadata` present → **the path exists.** Branch on
  `data.metadata.destroyed`: `true` is destroyed and unrecoverable, `false` is
  soft-deleted and recoverable via `POST <mount>/undelete/<path>`.
- an `errors` key present (even as `[]`) → **absent, or an unknown version, or
  denied.** See the next section on that last one.
- `200` with `data.data` an object → live.

That asymmetry — a deleted-version 404 has **no** `errors` key and a full data
envelope, an absent-path 404 has **only** `errors` — is the entire basis of the
discriminator. It is undocumented, and it is the thing to verify first on a live
instance.

When certainty about history is needed, follow with
`GET <mount>/metadata/<path>`: `200` returns the whole `versions` map with every
version's `deletion_time` and `destroyed`, plus `current_version` and
`oldest_version`; `404 {"errors":[]}` means the metadata is genuinely gone
(`pathMetadataRead`, `meta == nil` at
[`path_metadata.go` L288-290](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-kv/main/path_metadata.go)).
Destroy does **not** remove the metadata entry, so a fully-destroyed secret
still answers `200` here — the destroy cookbook shows `vault kv metadata get`
succeeding after a destroy.

One field to ignore: `mount_type` is `""` in the raw 404 bodies above rather
than `"kv"`, because core sets `resp.MountType` on the outer wrapper
(`vault/request_handling.go` L1586) after the plugin has already marshalled the
inner body. That single field is an inference — **[UNCONFIRMED]** on the wire.
Do not key logic off it. A normal `200`, per the
[read cookbook](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/cookbook/read-data),
does carry `"mount_type": "kv"`.

**Nothing in (a) or (b) is documented.** One `curl -i` after a `vault kv delete`
and a `vault kv destroy` on a dev Vault settles it permanently, and the spec
should treat that as a prerequisite rather than trusting this note.

## Reads: one request gets the value and the version

Yes. `GET <mount>/data/<path>` returns both. Verbatim sample response for "Read
secret version" [DOCS]
([KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)):

```json
{
  "data": {
    "data": {
      "foo": "bar"
    },
    "metadata": {
      "created_time": "2018-03-22T02:24:06.945319214Z",
      "custom_metadata": {
        "owner": "jdoe",
        "mission_critical": "false"
      },
      "deletion_time": "",
      "destroyed": false,
      "version": 2
    }
  }
}
```

`data.metadata.version` is the number to feed back as `cas` on the next write.
So pull-before-read and push-after-write are **one round trip each, per
credential** — no metadata call needed in the normal path. The endpoint blurb
confirms which fields are version-specific: "The metadata fields
`created_time`, `deletion_time`, `destroyed`, and `version` are version
specific. The `custom_metadata` field is part of the secret's key metadata and
is included in the response whether or not the calling token has `read` access
to the associated metadata endpoint."

### What metadata costs

`GET <mount>/metadata/<path>` is the *cheap* call — it reads one metadata storage
entry with no version-decrypt loop — but it is an extra round trip and it needs a
**separate policy grant**. It contains **no secret data at all**: "This endpoint
retrieves the metadata and versions for the secret at the specified path.
Metadata is version-agnostic" [DOCS], and `pathMetadataRead` builds each version
entry as `{created_time, deletion_time, destroyed, deleted_by, created_by}` and
never touches a version blob [SOURCE]. Sample response (trimmed to one version;
note the docs' own sample has trailing commas after each `client_id`, which is a
docs bug, not the wire format):

```json
{
  "data": {
    "cas_required": false,
    "created_time": "2018-03-22T02:24:06.945319214Z",
    "current_version": 3,
    "delete_version_after": "3h25m19s",
    "max_versions": 0,
    "oldest_version": 0,
    "updated_time": "2018-03-22T02:36:43.986212308Z",
    "custom_metadata": {
      "foo": "abc"
    },
    "versions": {
      "1": {
        "created_time": "2018-03-22T02:24:06.945319214Z",
        "created_by": {
          "actor": "userpass-myuser",
          "operation": "create",
          "entity_id": "12345678-1234-1234-1234-123456789012",
          "client_id": "12345678-1234-1234-1234-123456789012"
        },
        "deletion_time": "",
        "destroyed": false
      }
    }
  }
}
```

Two response fields are missing from that sample and exist in reality [SOURCE]:
each version also carries `deleted_by`, and the top level also carries
`last_updated_by` (attribution landed in plugin v0.25.0 per its CHANGELOG).

Policy paths are separate, and the
[KV v2 setup page](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/setup)
spells it out with this example:

```hcl
# Grants permission to read and patch the latest version of API keys
path "shared/data/dev/square-api/*" {
  capabilities = ["read", "patch"]
}

# Grants permission to read metadata for any version of the API keys
path "shared/metadata/dev/square-api/" {
  capabilities = ["read"]
}
```

Its "Available path prefixes" table gives `data` = "Permissions apply to the
**latest** version of the data", and `undelete` / `destroy` / `metadata` = "…on
any version of the data". The table has **no `delete` row** — a docs gap. Use
`update` on `<mount>/delete/<path>` for the versioned soft delete, and `delete`
on `<mount>/data/<path>` for the latest-version one. Also on that page: "ACL
policies for `kv` plugins do not support the `allowed_parameters`,
`denied_parameters`, and `required_parameters` policy fields."

The one metadata leak without metadata permission is the documented one quoted
above: `custom_metadata` rides along on every data read regardless.

## LIST

`LIST <mount>/metadata/<prefix>` — and per the API overview, "The API
documentation uses `LIST` as the HTTP verb, but you can still use `GET` with the
`?list=true` query string." Sample response, with the docs' own caption ("The
example below shows output for a query path of `secret/` when there are secrets
at `secret/foo` and `secret/foo/bar`; note the difference in the two entries"):

```json
{
  "data": {
    "keys": ["foo", "foo/"]
  }
}
```

**Single level, not recursive.** "This endpoint returns a list of key names at
the specified location. Folders are suffixed with `/`. The input must be a
folder; list on a file will not return a value. Note that no policy-based
filtering is performed on keys; do not encode sensitive information in key
names. The values themselves are not accessible via this command." A secret at
`secret/foo/bar` shows up only as the folder marker `"foo/"`; walking the tree is
the client's job.

**Capability**, quoted: "To list secrets for KV v2, a user must have a policy
granting them the `list` capability on this `/metadata/` path - even if all the
rest of their interactions with the KV v2 are via the `/data/` APIs."

**Not ACL-filtered**, quoted from the setup page's permissions partial: "Data
returned for a `list` operation **is not** filtered against ACL policies. **Do
not** encode sensitive information in key names."

**Empty result is a `404`**, body `{"errors":[]}` — "If the list result is an
empty set, Vault responds with status code 404 and the following JSON", and the
status list repeats "LIST requests with no results will also return 404s."
[SOURCE] confirms `RespondErrorCommon` implements this for nil response, empty
`Data`, missing `keys` and `len(keys) == 0` alike.

**No pagination.** No `limit`, `after` or cursor parameter is documented, and the
handler returns `logical.ListResponse(keys)` over the full `es.List` result — one
response, everything in it [SOURCE]. Whether a very large folder hits any
practical response-size cap is **[UNCONFIRMED]**.

**Deleted secrets still appear.** There is one filter, `exclude_deleted`
"(bool: false) - Only return non-deleted entries", used as
`?exclude_deleted=false`. Two catches:

- It is documented in **v1.21.x / v2.x only**. Grepping
  `api-docs/secret/kv/kv-v2.mdx` finds zero hits in v1.19.x and v1.20.x. A spec
  targeting Vault ≤ 1.20 cannot rely on it.
- It is narrower than its name. `pathMetadataList` skips a key only when **the
  current version** has a `DeletionTime` set; directories are always kept; and on
  a metadata-read error the key is kept deliberately ("Include the key in case of
  error to avoid hiding potentially valid keys"). It **never** tests `Destroyed`.
  So a key whose every version has been destroyed is still listed, with or
  without `exclude_deleted`. Only `DELETE <mount>/metadata/<path>` removes a key
  from LIST output. [SOURCE], undocumented.

## `403` versus `404`: Vault blurs this on purpose

Both directions of the blur are real, and one of them is documented as a design
decision. From the
[API overview's HTTP status codes](https://developer.hashicorp.com/vault/api-docs),
verbatim:

> `403` - Forbidden, your authentication details are either incorrect, you don't
> have access to this feature, or - if CORS is enabled - you made a cross-origin
> request from an origin that is not allowed to make such requests.

> `404` - Invalid path. This can both mean that the path truly doesn't exist or
> that you don't have permission to view a specific path. We use 404 in some
> cases to avoid state leakage. LIST requests with no results will also return
> 404s.

That second paragraph is the blur, in HashiCorp's own words. **A client cannot in
general tell "policy denies" from "does not exist" by status code.** For an error
message that matters: a token missing `read` on `<mount>/data/<project>/<key>`
can be indistinguishable from a credential that was never pushed.

The other direction — `403` for something that does not exist — is also real, but
it is not on the KV data path. It lives on the mount-version preflight
`GET sys/internal/ui/mounts/<path>` that the `vault kv` CLI and many wrappers
issue first. `pathInternalUIMountRead`
([`vault/logical_system.go` L5727 onward](https://raw.githubusercontent.com/hashicorp/vault/main/vault/logical_system.go))
builds

```go
errResp := logical.ErrorResponse(fmt.Sprintf("preflight capability check returned 403, please ensure client's policies grant access to path %q", path))
```

and then, for a mount that is not there:

```go
me := b.Core.router.MatchingMountEntry(ctx, path)
if me == nil {
    // Return a permission denied error here so this path cannot be used to
    // brute force a list of mounts.
    return errResp, logical.ErrPermissionDenied
}
```

So a **nonexistent mount returns `403 permission denied` deliberately**, and the
comment says why. That is the origin of the familiar `1 error occurred: *
preflight capability check returned 403, please ensure client's policies grant
access to path "secret/foo/"`, which is ambiguous between a typo'd mount, a mount
elsewhere, and a policy gap — long-standing, per vault issues 11434, 10170, 6616
and 25710. `command/kv_helpers.go`'s `kvPreflightVersionRequest` also reads a
`404` from that preflight as "older Vault, assume KV v1".

**Spec implication:** do not use a CLI-style preflight. Address
`<mount>/data/<path>` directly and take the KV version from configuration. That
removes this failure mode entirely.

The `403` body itself has two forms in the wild:

```json
{"errors":["permission denied"]}
```

```json
{"errors":["1 error occurred:\n\t* permission denied\n\n"]}
```

`sdk/logical/error.go` defines `ErrPermissionDenied = errors.New("permission
denied")`; `response_util.go` L123-124 maps any error containing that string to
`StatusForbidden`, then overwrites the message with `resp.Error()` when the
backend also produced an error response — for an ACL denial that is
`logical.ErrorResponse(ctErr.Error())` = `"permission denied"`
(`vault/request_handling.go` ~L1429-1460). Where only the wrapped `retErr`
survives it is `multierror.Append(retErr, logical.ErrPermissionDenied)`, which
renders as the second form. **Which one the KV `data/` path emits is
[UNCONFIRMED]** and is path- and version-dependent. Branch on the status code,
never on the string — except for CAS, where the string is the only signal there
is.

And for completeness: a plain missing secret's `404` body is `{"errors":[]}` —
the `errors` key is always present, as an empty array, not a missing field and
not an empty body.

## KV v1 has no CAS, so the spec may require v2 by name

Confirmed. The
[KV v1 API page](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1)
documents exactly four operations — `GET /secret/:path`, `LIST /secret/:path`,
`POST /secret/:path`, `DELETE /secret/:path` — plus `RECOVER /secret/:path` for
snapshot recovery, which is unrelated to versioning. There is no `data/`,
`metadata/`, `delete/`, `undelete/`, `destroy/`, `subkeys/` or `config` path; no
`options` or `cas` parameter on the write; no `version` parameter on the read;
and no `version`, `created_time`, `deletion_time` or `destroyed` field in any
response.

The quotable lines, all [DOCS]:

- [KV v1](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v1): "Writing
  to a key in the `kv` backend will replace the old value; sub-fields are not
  merged together."
- [KV overview](https://developer.hashicorp.com/vault/docs/secrets/kv): "When
  running the `kv` secrets engine non-versioned, it stores the most recently
  written value for a key. Any update will overwrite the original value and not
  recoverable."
- Same page, CAS named as v2-only: "When running v2 of the `kv` secrets engine, a
  key can retain a configurable number of versions. The default is 10 versions.
  The older versions' metadata and data can be retrieved. Additionally, it
  provides check-and-set operations to prevent overwriting data unintentionally."
- Same page: "Regardless of its version, you use the `vault kv` command to
  interact with KV secrets engine. However, the API endpoint are different." —
  followed by the v1/v2 endpoint table, and then a second table of versioning
  sub-commands (`vault kv patch`, `rollback`, `undelete`, `destroy`, `metadata`)
  **with a KV v2 column only**. That second table is the cleanest single citation
  for requiring v2 by name.
- The version is fixed at mount time, so it is a precondition rather than
  something to negotiate: "To enable a version 1 kv store: `vault secrets enable
  -version=1 kv`".

Two v1 facts worth not over-claiming. It never auto-expires either — "Even with
a `ttl` set, the secrets engine _never_ removes data on its own. The `ttl` key is
merely advisory" — and it *does* honour create-versus-update ACLs: "This secrets
engine honors the distinction between the `create` and `update` capabilities
inside ACL policies." So that last property is **not** a reason to require v2.
CAS and versioning are.

## What the sync design assumes that does not hold

The interesting output. Each item names the map premise it dents and what the
spec has to say instead.

**1. A CAS conflict is not a distinct status code.** Decision 2 wants a conflict
to surface as *"someone else changed `db`; run `cred pull`"*. There is no `409`
and no `412`: a lost race is a `400`, the same `400` as a malformed body, an
undecodable `cas`, or a missing `cas` on a `cas_required` mount. The only thing
that separates them is the error string `"check-and-set parameter did not match
the current version"`. **The spec must commit to substring-matching an
undocumented English sentence**, and must say what it does when the match fails
(a `400` it cannot classify is not a conflict and must not tell the user to pull).

**2. That string is not documented anywhere.** The KV v2 API page has no
error-response example at all. Every fact about the CAS-failure response in this
note is read out of plugin source at v0.27.0. It has been stable since v0.11.0,
which is good evidence and not a promise. The architecture rests on an
implementation detail, and the spec should say so out loud rather than cite the
API docs for it.

**3. `404` does not mean "not in Vault".** HashiCorp documents `404` as meaning
*either* absent *or* denied — "We use 404 in some cases to avoid state leakage."
A pull that treats `404` as "this credential is not in Vault yet" will silently
misread a policy gap as an empty remote. Error messages cannot promise the user
which of the two happened.

**4. A soft-deleted secret also reads as `404`, and telling it apart needs
undocumented body parsing.** A recoverable credential, an unrecoverable one and
an absent one all return `404` from `GET <mount>/data/<path>`. They are
distinguishable — by whether the body carries `data.metadata` and what
`destroyed` says — but that shape is [SOURCE] only. A naive pull drops a
recoverable credential from the mirror and cannot tell the user it is recoverable.

**5. `cas=0` is not "create if absent".** It is "no metadata entry exists". After
a soft delete or a destroy the path is still occupied: `cas=0` fails, and the
write must use the current version instead. For a credential manager,
set-after-unset is a completely ordinary flow, so **the spec cannot use `cas=0`
as its create path without first deciding what `unset` does to Vault.** If `unset`
soft-deletes, a later `set` of the same key needs the version; only
`DELETE <mount>/metadata/<path>` frees `cas=0` again — and that resets the
version counter to 1, invalidating every other machine's cached number.

**6. A secret can change without anyone changing it.** `delete_version_after` on
the mount stamps a `deletion_time` on every new version at write time, after
which reads `404`. Default is `"0s"` (off), so this only bites on a mount someone
else configured — which is exactly what decision 4's *shared* mount allows.
Version numbers alone cannot detect this: the number does not move, the secret
just stops being readable. Decision 2's "no timestamps needed" is true for
conflict detection and false for staleness.

**7. `max_versions` defaults to 10, silently.** Ten `cred set` calls on one
credential and the oldest version's data is hard-deleted from storage and removed
from the `versions` map. Nothing in the design depends on history today, but any
future "roll back a credential" feature has a ten-deep default ceiling, and a
per-secret `max_versions` **lower** than the mount's is silently ignored
(`max(...)`, not override — see the table above, and note this contradicts the
docs). `cred` cannot cap its own retention below whatever the shared mount says.

**8. CAS is opt-in per request; nothing enforces it by default.** `cas_required`
is `false` at both levels. A write with no `cas` at all just succeeds and
overwrites. So the guarantee decision 2 leans on holds only for clients that ask
for it — a `vault kv put` from a shell, or a future `cred-ps` that forgets, blows
straight past it. The good news: `cas_required` also exists **per secret**, so
`cred` can close this per credential it creates without needing `sys/mounts`
admin, which fits decision 4. The bad news: mount-wide `cas_required` is a
decision about every project sharing that mount, and a mount-level `true` cannot
be relaxed per secret.

**9. Enumerating a project's credentials leaks their names.** `LIST` is
explicitly *not* ACL-filtered — "do not encode sensitive information in key
names" — and decision 3 puts the credential name in the path
(`<mount>/<project>/<key>`). Anyone with `list` on the shared mount's metadata
prefix learns every project's credential names. Also, `LIST` is single-level, so
walking a project means one call per folder level, and soft-deleted **and
destroyed** keys still appear in the results (`exclude_deleted` filters only on
the current version's `deletion_time`, never on `destroyed`, and exists in the
docs for v1.21.x and later only).

**10. There is no batch read and no batch write.** Pull-before-read at
`read_values` is the single funnel for the whole store, but KV v2 offers no
multi-get: refreshing a project of *N* credentials is a `LIST` plus *N* `GET`s.
And a push of several changed credentials is *N* independent CAS writes with **no
atomicity across them** — a conflict on the third leaves the first two already in
Vault and no rollback. Decision 3's "two machines editing different credentials
never conflict" is true and does not cover this. **The spec must say what a
partial push leaves behind.**

**11. Deletes are not confirmations.** Every delete-ish endpoint returns `204`
even when the path never existed, and `undelete` of a destroyed version is a
silent `204` no-op. A `204` therefore tells a client nothing about what was there.

**12. Do not probe for the KV version.** The CLI's preflight
`GET sys/internal/ui/mounts/<path>` returns `403 permission denied` for a
nonexistent mount *by design*, to prevent mount enumeration. Any auto-detection
of v1-versus-v2 inherits that ambiguity. Decision 5 already records the mount in
`config.json`; the spec should record the *version* as a precondition too and
address `<mount>/data/<path>` directly.

### What does hold

Worth stating, because most of it does:

- Version numbers are **monotonic and never reused**, surviving soft delete,
  undelete, destroy and `max_versions` rollover. Only
  `DELETE <mount>/metadata/<path>` resets them.
- The **new version comes back in the write response** at `data.version`. A push
  is one round trip.
- A **read returns the value and the version together** at
  `data.metadata.version`. A pull is one round trip per credential.
- **CAS can be made mandatory**, mount-wide or per secret, and mount-wide has no
  per-secret escape hatch.
- **KV v1 has no CAS and no versioning**, so requiring v2 by name is correct and
  citable.

## What a live Vault would settle

Every one of these is one `curl -i` against a dev Vault, and together they close
the whole [SOURCE] column. Worth doing before the spec is written, not after.

1. A stale `cas` — confirm `400` and the exact body bytes. (The load-bearing one.)
2. A `GET` after `vault kv delete` — confirm the `404`-with-`metadata` envelope.
3. A `GET` after `vault kv destroy` — confirm `destroyed: true` in the same shape.
4. A `GET` of a path that never existed — confirm `404 {"errors":[]}`.
5. A `GET` with a deliberately insufficient policy — find out which `403` body
   form the KV `data/` path emits, and whether it is `403` at all rather than
   `404`.
6. `cas=0` against a soft-deleted, a destroyed-only, and an aged-out path.
7. Mount `max_versions=10` plus secret `max_versions=2`, five writes, read
   metadata — confirm the `max(...)` precedence against the docs' wording.
8. Version numbering after `DELETE <mount>/metadata/<path>` — confirm it restarts
   at 1.
9. Whether `mount_type` really is `""` in the raw `404` bodies (and then still do
   not depend on it).

## Sources

Primary documentation, all fetched 2026-09-19:
[KV v2 API reference](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2) ·
[KV v2 overview](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2) ·
[KV v2 setup and policies](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/setup) ·
cookbook pages for
[read](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/cookbook/read-data),
[delete](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/cookbook/delete-data),
[undelete](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/cookbook/undelete-data),
[destroy](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/cookbook/destroy-data)
and [max-versions](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2/cookbook/max-versions) ·
[KV engine overview](https://developer.hashicorp.com/vault/docs/secrets/kv) ·
[KV v1 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1) and
[KV v1 docs](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v1) ·
[API overview and status codes](https://developer.hashicorp.com/vault/api-docs) ·
[`vault kv put`](https://developer.hashicorp.com/vault/docs/commands/kv/put).

Doc sources were also read unrendered from
[`hashicorp/web-unified-docs`](https://github.com/hashicorp/web-unified-docs)
under `content/vault/{v1.19.x,v1.20.x,v1.21.x,v2.x}/content/`, which is where
`developer.hashicorp.com` now renders from — `hashicorp/vault`'s own
`website/content/` paths 404.

Plugin source, [`hashicorp/vault-plugin-secrets-kv`](https://github.com/hashicorp/vault-plugin-secrets-kv)
at `main` = v0.27.0 (`3161a36`, 2026-09-16): `path_data.go`, `path_metadata.go`,
`path_delete.go`, `path_destroy.go`, `delete_version_after.go`, `backend.go`,
`CHANGELOG.md`; plus tags v0.11.0, v0.14.2, v0.20.0 and v0.26.2 of
`path_data.go` for the stability check.

Vault core, [`hashicorp/vault`](https://github.com/hashicorp/vault) at `main`:
`sdk/logical/response.go`, `sdk/logical/translate_response.go`,
`sdk/logical/response_util.go`, `sdk/logical/error.go`, `http/logical.go`,
`http/handler.go`, `vault/request_handling.go`, `vault/logical_system.go`,
`command/kv_helpers.go`.

The live instance was not used, for the reason in the opening paragraph. When
that changes, the nine checks above are the first thing to run.
