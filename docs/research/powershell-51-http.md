# HTTP from Windows PowerShell 5.1 without a dependency

Research for [#4](https://github.com/mfic/cred/issues/4), part of the
Vault-backed `cred` map ([#1](https://github.com/mfic/cred/issues/1)).

**The question.** Can PowerShell 5.1 do everything the sync layer needs over
HTTPS with no dependency, and what is the ugliest part?

**The short answer.** Yes — every requirement is reachable with nothing but
`System.Net`, so "refuse to sync" is a **choice, not a constraint**. But
`Invoke-RestMethod`, the cmdlet the map's decision 7 names, is the **wrong tool
for three of the six requirements**, and it fails at all three *silently*. The
ugliest part is not the network. It is a **fourth member of the
silent-corruption family documented at `ARCHITECTURE.md:256`**: on 5.1 the
default `Invoke-RestMethod` call destroys a non-ASCII secret in *both*
directions with no error, irreversibly on the way out, and
`ConvertTo-CredJson` does not save you — it is the thing that hands the cmdlet
the string that gets destroyed.

The recommendation is therefore not "PowerShell can't". It is: let `cred-ps`
**pull** (a `GET` has no request body, so the irreversible trap cannot fire) and
let it refuse to **push**, permanently. Section 7 has the reasoning.

Every claim below is marked **[observed]** or **[documented]**. Observed means
measured on this machine; documented means a primary source says so.

## How the observations were made

| | |
|---|---|
| Host | Windows 11 Pro 10.0.26200, `de-DE`, ANSI code page 1252 |
| Windows PowerShell | 5.1.26100.9444, CLR 4.0.30319.42000 |
| .NET Framework | `Release` 533509 (4.8.1) |
| PowerShell 7 | 7.6.5, for contrast |
| Remote endpoints | `httpbin.org`, `postman-echo.com`, `untrusted-root.badssl.com` |
| Local endpoint | a raw `TcpListener` HTTP server in a background runspace |

The raw listener matters. Public echo services decode and re-encode what you
send them, so they cannot answer "what bytes went on the wire". The listener
records the exact request bytes and replies with exact response bytes and an
exact `Content-Type`, which is the only way to separate *PowerShell mangled it*
from *the service normalised it*. Scripts are not committed; they were scratch.

`vault.questnet.eu` was never contacted.

## Verdict table

| Item | Verdict |
|---|---|
| TLS 1.2 on stock 5.1 | **works** — no longer needs the ritual, and the ritual now does harm |
| TLS 1.3 | **works** on Windows 11 — but only if you leave `SecurityProtocol` alone |
| Custom headers | **works** |
| Non-2xx response body | **works with a caveat** — via `ErrorDetails.Message`, undocumented, 64 KB cap |
| JSON parse/serialise | **works** — `ConvertFrom-CredJson` / `ConvertTo-CredJson` are already sufficient |
| Non-ASCII round trip | **works with a caveat** — and the caveat is severe: the default call corrupts silently, both directions |
| Private CA | **works with a caveat** — Windows cert store only; no per-call trust for `Invoke-RestMethod` |
| Proxy | **works with a caveat** — 5.1 ignores `HTTPS_PROXY`, which 7 honours |
| Token off argv | **works** — but nothing enforces it, and `SecureString` fails silently |
| Cloudflare Access 302 | **not without a dependency** for `Invoke-RestMethod`; **works** with `HttpWebRequest` |

## 1. TLS

**The ritual is no longer required on a current machine. [observed]**

    [Net.ServicePointManager]::SecurityProtocol   ->  SystemDefault
    negotiated against httpbin.org:443            ->  Tls12 (AES-128)
    Invoke-RestMethod https://httpbin.org/get     ->  OK, protocol untouched

`SystemDefault` (the enum's `0`) means .NET defers to SChannel. **[documented]**
"Starting with the .NET Framework 4.7, the default value of this property is
`SecurityProtocolType.SystemDefault`. This allows .NET Framework networking APIs
based on `SslStream` […] to inherit the default security protocols from the
operating system" — and of `SystemDefault` itself: "Allows the operating system
to choose the best protocol to use, and to block protocols that are not secure.
Unless your app has a specific reason not to, you should use this value."
([`SecurityProtocol`](https://learn.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager.securityprotocol?view=netframework-4.8),
[`SecurityProtocolType`](https://learn.microsoft.com/en-us/dotnet/api/system.net.securityprotocoltype?view=netframework-4.8))
So on 4.7+ the `= 'Tls12'` line is not merely dead code — see below. On 4.6.2 and
earlier no default is documented, and in practice it was `Ssl3, Tls`, which is
why the ritual exists at all. Microsoft's own TLS guidance is blunt about it:
"if possible, don't set a value for the `ServicePointManager.SecurityProtocol`
property"
([TLS best practices](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls)).

**But it leaks, and the leak is worse than the ticket suspects. [observed]**
`SecurityProtocol` is a static property on a class in the caller's AppDomain.
Assigning it anywhere sticks everywhere:

    before                                  SystemDefault
    after a function assigned it            Tls12
    after a module-scoped function          Tls11, Tls12

Neither function scope nor module scope contains it. `cred-ps` is imported
**into the user's session** (`Import-Module Cred` is a documented entry point),
so a `SecurityProtocol` assignment in the sync layer silently rewrites the TLS
policy of every other HTTP call that session makes for the rest of its life —
including *narrowing* it, since the assignment replaces rather than adds.

The honest handling is therefore: **do not touch it at all.** If a host is old
enough to need it, save the old value, set, and restore in a `finally` — which
is still not thread-safe, merely polite. Not setting it is the better default
because `SystemDefault` is strictly more capable than `Tls12` on any host where
the line would have helped.

**TLS 1.3 works, and this is the reason not to set the property. [observed]**
Windows PowerShell 5.1 on this Windows 11 host negotiates TLS 1.3 wherever the
server offers it, through `Invoke-RestMethod`, with no configuration:

    cloudflare.com     SystemDefault -> Tls13
    www.google.com     SystemDefault -> Tls13
    postman-echo.com   SystemDefault -> Tls13
    httpbin.org        SystemDefault -> Tls12     (the server's limit, not ours)

    Invoke-RestMethod https://cloudflare.com/cdn-cgi/trace  ->  tls=TLSv1.3

I had this backwards before measuring, and the correction matters: **writing
`= 'Tls12'` on a Windows 11 host actively downgrades a connection that would
otherwise have been TLS 1.3.** Since `vault.questnet.eu` sits behind Cloudflare,
and Cloudflare negotiates 1.3, the cargo-culted line would downgrade *precisely
the connection this map is about*. The documentation agrees: "explicitly setting
a lower TLS version prevents a TLS 1.3 connection."

**[documented]** The version matrix: .NET Framework 4.6.2–4.8.1 reaches TLS 1.2
on Windows 10 and TLS 1.3 on Windows 11, because "Since .NET Framework is
dependent on Schannel on Windows, the operating system dictates which versions
can be negotiated"; "For TLS 1.3, target .NET Framework 4.8 or later." SChannel
itself: "TLS 1.3 is supported starting in Windows 11 and Windows Server 2022.
Enabling TLS 1.3 on earlier versions of Windows is not a safe system
configuration"
([Schannel protocols](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-)).
So on Windows 10 TLS 1.3 is unreachable whatever you set — one more reason to set
nothing and let the OS decide.

A named-constant trap worth recording: the `Tls13` member is in the 4.8 enum
Fields table, but the same TLS page tells you to define it yourself as
`(SecurityProtocolType)12288` for 4.6.2+, so `[Net.SecurityProtocolType]::Tls13`
is not reliably present across hosts. **[observed]** It resolves on this 4.8.1
host, and `12288` passed to `SslStream.AuthenticateAsClient` negotiates 1.3.
Neither is needed if you never assign the property.

**[documented]** Two registry keys can move the default underneath you —
`SchUseStrongCrypto` and `SystemDefaultTlsVersions` under
`HKLM\SOFTWARE\[Wow6432Node\]Microsoft\.NETFramework\v4.0.30319`. "These registry
keys don't exist by default. You must add them manually" and "Setting registry
keys affects all applications on the system." A host where an administrator has
set `SystemDefaultTlsVersions = 0` gets .NET-picked protocols rather than
OS-picked ones. This is a reason for `cred doctor` to *report* the negotiated
protocol rather than for the sync layer to *set* it.

## 2. `Invoke-RestMethod` vs `HttpWebRequest`

### Headers: `Invoke-RestMethod` is fine

**[observed]** `-Headers @{...}` puts custom headers on the wire verbatim:

    POST /v1/x HTTP/1.1
    CF-Access-Client-Id: abc.access
    CF-Access-Client-Secret: sekret
    X-Vault-Token: s.tok
    User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; de-DE) WindowsPowerShell/5.1.26100.9444
    Content-Type: application/json
    Host: 127.0.0.1:64227
    Content-Length: 32
    Expect: 100-continue

Two incidental notes. 5.1 sends `Expect: 100-continue` by default (harmless to
Vault, occasionally fatal through old proxies; `[Net.ServicePointManager]::Expect100Continue`
turns it off and is process-wide, same leak as above). And the default
`User-Agent` announces the exact PowerShell build and the machine locale to
Vault's audit log — cosmetic, but `-UserAgent 'cred/1'` is free.

### The non-2xx body: the load-bearing finding

The ticket's fear was that a `WebException` discards the body. **It does not
discard it — PowerShell has already drained it for you, into a property the 5.1
documentation does not mention.** [observed]

Against a local `403` with body `{"errors":["permission denied: tok-äöü-🔑"]}`:

| Access path | Result |
|---|---|
| `$_.Exception.GetType()` | `System.Net.WebException` |
| `$_.Exception.Response.StatusCode` | `403` — usable |
| `$_.Exception.Response.GetResponseStream()` | **0 bytes** — already consumed |
| `$_.ErrorDetails.Message` | the **complete body, byte-exact**, emoji included |

So the useful error message is available, and the obvious place to look for it
is empty. Anyone who writes the textbook `GetResponseStream()` recovery gets an
empty string and concludes Vault sent no error text. Confirmed against public
endpoints too **[observed]**: `httpbin.org/status/418` yields the teapot body and
`postman-echo.com/status/404` yields `{"status":404}`, both via `ErrorDetails`,
both with a drained stream.

Three caveats on `ErrorDetails.Message`:

1. **64 KB cap. [observed]** A 200,015-byte error body arrives as exactly
   **65,536 characters**. Vault's errors are short, so this is a footnote — but
   it means `ErrorDetails.Message` is not a general-purpose body reader, and a
   truncated JSON body will fail to parse rather than fail to be present.
2. **It is not raw on PowerShell 7. [observed]** 7 *re-serialises* the body —
   pretty-printed, CRLF, non-ASCII as `\uXXXX` escapes — so the string differs
   between editions for the same response. Both parse to the same object. The
   rule that follows: **parse `ErrorDetails.Message`, never fingerprint it**, and
   never compare it across editions in a conformance test.
3. **Undocumented, and confirmed undocumented. [documented — by omission]**
   There is no first-party documentation of `$_.ErrorDetails.Message` carrying a
   response body, on the 5.1 pages or the 7.x ones. The 5.1 `Invoke-RestMethod`
   page says *nothing at all* about non-success status; the only error path it
   names is a `WebException` under `-TimeoutSec`. The 5.1 `Invoke-WebRequest`
   page documents the situation but not the body: "When `Invoke-WebRequest`
   encounters a non-success HTTP message (404, 500, etc.), it returns no output
   and throws a terminating error" — and its example recovers
   `$_.Exception.Response.StatusCode.value__`, **status only**
   ([5.1 `Invoke-WebRequest`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-5.1),
   [5.1 `Invoke-RestMethod`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-5.1)).
   The documented way to read an error body arrived in PowerShell 7:
   `-SkipHttpErrorCheck` and `-StatusCodeVariable`, both "introduced in
   PowerShell 7", both **absent from 5.1 [observed]** — confirmed by parameter
   enumeration, along with `-SkipCertificateCheck`, `-Authentication`, `-Token`,
   `-SslProtocol`, `-PreserveAuthorizationOnRedirect`, `-ResponseHeadersVariable`
   and `-NoProxy`.

   So the 5.1 code path stands on behaviour the vendor never promised. It has
   been stable since 3.0 and half of PowerShell relies on it, but the spec should
   say so out loud and pin it with a regression test against a local listener —
   the same way `Process.ps1`'s preamble swap is pinned.

   **[documented]** The exception type differs by edition, which a shared test
   must account for: on 5.1 it is `System.Net.WebException` with `.Response` an
   `HttpWebResponse`; from 6 onward the web cmdlets moved to `HttpClient`, so
   "The `Response` property on Web Cmdlet exceptions is now a
   `System.Net.Http.HttpResponseMessage` object" and the type is
   `Microsoft.PowerShell.Commands.HttpResponseException`
   ([differences from Windows PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/whats-new/differences-from-windows-powershell?view=powershell-7.5)).
   **[observed]** Confirmed in both directions: `WebException` on 5.1, and on 7
   `$_.Exception.Response.GetResponseStream()` fails with "does not contain a
   method named 'GetResponseStream'".

### Where `Invoke-RestMethod` genuinely cannot go: the 302

This is the one item where the cmdlet loses outright. **[observed]** Against a
`302` carrying `Location` and `Www-Authenticate: Cloudflare-Access`:

| Call | Outcome |
|---|---|
| `Invoke-RestMethod` (default) | **follows the redirect**, returns the login page's body as if it were data |
| `Invoke-RestMethod -MaximumRedirection 0 -ErrorAction Stop` | throws `InvalidOperationException`, and the exception **has no `Response` property at all** — status, `Location` and `Www-Authenticate` are unreachable |
| `HttpWebRequest` with `AllowAutoRedirect = $false` | returns the `302` as a **normal response**: `StatusCode 302`, `Location`, `Www-Authenticate: Cloudflare-Access`, all readable |

On PowerShell 7 the same `-MaximumRedirection 0` throws
`HttpResponseException` *with* the `302` visible **[observed]** — so this
asymmetry is 5.1's alone, and it is exactly the signal the map calls out as the
defining fact about `vault.questnet.eu`. Detecting "you are looking at
Cloudflare Access, not Vault" — the single most important error to report well —
is **not possible through `Invoke-RestMethod` on 5.1**. It is entirely possible
through `HttpWebRequest`, which is stdlib and therefore not a dependency.

**And the redirect leaks the token. [observed]** On *both* editions, following
that `302` **re-sends `X-Vault-Token` to the redirect target**:

    hop 0  GET /v1/secret              X-Vault-Token present
    hop 1  GET /cdn-cgi/access/login   X-Vault-Token present

A Vault token handed to whatever a misconfigured `Location` points at is a
credential-disclosure bug, not a usability one. 7's
`-PreserveAuthorizationOnRedirect` does not help: it governs `Authorization`,
not arbitrary headers. **The sync layer should not follow redirects at all.** A
Vault API call has no legitimate reason to redirect; a redirect *is* the Access
signal. `AllowAutoRedirect = $false` fixes the leak and surfaces the diagnosis
in one move.

### Conclusion for this section

`Invoke-RestMethod` is sufficient for the 2xx path and adequate for the error
path. It is **not** sufficient for Cloudflare Access detection or for refusing
to leak the token on redirect. `HttpWebRequest` is sufficient for all of it,
costs no dependency, and is the same `System.Net` stack the cmdlet is built on —
but it is ~30 lines where the cmdlet is one, and it makes the caller responsible
for disposal and for reading bytes.

The recommendation is a single private helper, `Invoke-CredVaultRequest`, built
on `HttpWebRequest`, byte-in/byte-out, `AllowAutoRedirect = $false` — the exact
shape `Invoke-CredProcess` already has for `age`. The module already has a
precedent for "one choke point, bytes only, no leaks"; this is the same pattern
pointed at a socket instead of a pipe.

## 3. Encoding: the fourth silent-corruption trap

This is the answer the ticket most needs, and it is worse than "does it mangle a
non-ASCII secret". **The default `Invoke-RestMethod` call on 5.1 corrupts
`tok-äöü-🔑` in both directions, silently, and outbound the loss is
irreversible.**

The canary is built from code points in the test script, so the script file's own
encoding cannot lie: `tok-` + U+00E4 U+00F6 U+00FC + `-` + U+1F511, which is
15 UTF-8 bytes:

    74 6f 6b 2d c3 a4 c3 b6 c3 bc 2d f0 9f 94 91

### Outbound: the request body

Measured on the wire against the raw listener. **[observed]**

| Call shape | Bytes on the wire | Byte-exact? |
|---|---|---|
| `-Body <string>`, `-ContentType 'application/json'` | `74 6f 6b 2d` **`e4 f6 fc`** `2d` **`3f 3f`** | **NO** |
| `-Body <string>`, `-ContentType 'application/json; charset=utf-8'` | `74 6f 6b 2d c3 a4 c3 b6 c3 bc 2d f0 9f 94 91` | yes |
| `-Body <byte[]>`, `-ContentType 'application/json'` | `74 6f 6b 2d c3 a4 c3 b6 c3 bc 2d f0 9f 94 91` | yes |

Read the failing row carefully. `c3 a4` (ä) became the single byte `e4`, and the
emoji became `3f 3f` — two literal question marks. The first is a transcode to
the host's ANSI code page; the second is **unrecoverable**. No decoding on
Vault's side reconstructs U+1F511 from `?`. A secret containing an emoji, or any
character outside the host's code page, is destroyed on the way out and the push
reports success.

**[documented]** The cmdlet's own words, identical on the 5.1 and 7.x pages: "If
the value for `ContentType` contains the encoding format (as charset), the cmdlet
uses that format to encode the body of the web request. If the `ContentType`
doesn't specify an encoding format, **the default encoding format is used
instead**." The 5.1 page never says what that default is. The 7.4 change note
names it retroactively: "Beginning in PowerShell 7.4, character encoding for
requests defaults to UTF-8 **instead of ASCII**. If you need a different
encoding, you must set the `charset` attribute in the `Content-Type` header"
([7.5 `Invoke-RestMethod`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-7.5)).

**The docs and the measurement disagree, and the measurement is worse.** The
documentation says the pre-7.4 default is ASCII; ASCII would have rendered ä as
`3f`. What actually happened is `e4` — the host's **ANSI code page**, 1252 on
this `de-DE` machine. The consequence is nasty: the corruption is
**locale-dependent**. `ä` survives as one wrong byte on a Western host, becomes
something else on a Cyrillic or Japanese one, and the emoji dies everywhere. A
conformance test written on an `en-US` machine and one written on a `de-DE`
machine would disagree about what the wrong answer even is. Treat the pre-7.4
default as "the host's ANSI code page", not as ASCII, and rely on neither.

### Inbound: the response body

Vault replies `Content-Type: application/json` with **no** `charset`. That is
exactly the case 5.1 gets wrong. **[observed]**

| Read path | Result |
|---|---|
| `Invoke-RestMethod`, `application/json` (no charset) | `74 6f 6b 2d` **`c3 83 c2 a4 c3 83 c2 b6 c3 83 c2 bc`** `2d c3 b0 c2 9f c2 94 c2 91` — **mojibake** |
| `Invoke-RestMethod`, `application/json; charset=utf-8` | byte-exact |
| `Invoke-WebRequest` → `.Content` (no charset) | same mojibake |
| `Invoke-WebRequest` → `.RawContentStream` → `UTF8.GetString` | **byte-exact** |
| PowerShell 7, any of the above, no charset | byte-exact |

A classic double decode: the UTF-8 bytes were read as Latin-1, so each byte
became its own character and re-encoding produced two bytes where there was one.
Unlike the outbound case this is reversible in principle — but only if you know
it happened, and nothing tells you. A secret read back on 5.1 and written into
`store.age` is silently a different secret, which then fails to authenticate
somewhere far away from here.

**[documented]** Neither 5.1 page documents response character encoding at all —
no charset handling, no fallback, no `-Encoding` parameter. The fix is dated
precisely in the 6.2 notes: "In PowerShell 6.2, a change was made to default to
UTF-8 encoding for JSON responses. **When a charset isn't supplied for a JSON
response, the default encoding should be UTF-8 per RFC 8259**"
([differences from Windows PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/whats-new/differences-from-windows-powershell?view=powershell-7.5)).
So this is a bug Microsoft fixed in 6.2 and never backported; 5.1 is on the wrong
side of it permanently. The observed Latin-1 fallback itself is documented
nowhere — it is inference from `HttpWebResponse.CharacterSet` ("This character set
information is taken from the header returned with the response", silent on the
absent case) plus the measurement above.

### What this means for the design

The rule already in `ARCHITECTURE.md` under "Encoding" — *everything internal is
bytes; strings become bytes with an explicit `UTF8Encoding($false)` and back
again; nothing relies on a default* — is the complete fix, applied to HTTP:

- **send** `byte[]`, never a string (byte-exact regardless of `charset`);
- **receive** bytes and decode them yourself with explicit UTF-8;
- set `charset=utf-8` on `Content-Type` anyway, because it is correct and costs
  nothing;
- never read `.Content`, and never let `Invoke-RestMethod` parse JSON for you.

That is a fourth entry for the `ARCHITECTURE.md:256` list, the same shape as the
other three: **5.1 silently corrupts rather than failing.** It also means the
sync layer cannot use `Invoke-RestMethod` on the inbound side at all — you need
`Invoke-WebRequest -UseBasicParsing` for `RawContentStream`, or `HttpWebRequest`
for the raw stream. Since the 302 handling already forces `HttpWebRequest`, that
is one decision rather than two.

**[documented]** One more reason not to reach for `Invoke-WebRequest`:
CVE-2025-54100 / KB5074596 (Dec 2025) makes `-UseBasicParsing` effectively
mandatory on patched 5.1 hosts — "There is no way to bypass this prompt without
using the `UseBasicParsing` parameter" — so a 5.1 path calling
`Invoke-WebRequest` without it now blocks on a confirmation prompt when run
unattended. `HttpWebRequest` has no such hazard.

## 4. JSON

**`ConvertFrom-CredJson` and `ConvertTo-CredJson` suffice for Vault payloads,
unchanged.** This is the one item that needs nothing. **[observed]**

Tested against a realistic KV v2 read reply — `request_id`, `lease_id`,
`renewable`, `data.data.{user,secret,encoding}`, `data.metadata.version`,
`custom_metadata` nested seven levels deep, and explicit `null` for `wrap_info`,
`warnings` and `auth`:

    parsed type                       OrderedDictionary
    data.data.secret byte-exact       True    (emoji intact)
    data.metadata.version             7       (a number, usable as the CAS value)
    depth-7 nested value              "value" (not truncated)
    warnings is $null                 True
    round trip preserves the secret   True
    round trip length delta           0
    300 KB value round trip exact     True

Both editions gave identical results. Three things worth spelling out:

- **`-Depth 20` covers Vault comfortably.** The deepest real path is
  `data.metadata.custom_metadata.<user keys>`, and `custom_metadata` is
  user-controlled, so nominally unbounded — but Vault types it as a flat
  `map[string]string`, so depth 4 is the real ceiling. 20 is slack.
- **The truncation trap is confirmed, and confirmed silent. [observed]** On 5.1,
  `@{a=@{b=@{c=@{d='leaf'}}}} | ConvertTo-Json -Compress` yields
  `{"a":{"b":{"c":"System.Collections.Hashtable"}}}` with **no warning**.
  PowerShell 7 prints `WARNING: Resulting JSON is truncated as serialization has
  exceeded the set depth of 2.` **[documented]** The 5.1 page *claims* it warns
  ("`ConvertTo-Json` emits a warning if the number of levels in an input object
  exceeds this number"); the 7.x page dates the warning to 7.1 ("As of PowerShell
  7.1, `ConvertTo-Json` emits a warning…"). **The 5.1 documentation is wrong and
  `ARCHITECTURE.md:261` is right.** Worth recording that the vendor doc
  contradicts observed behaviour here, so nobody "corrects" the comment later.
- **`-AsHashtable` is 6.0+ [documented]** — the 5.1 `ConvertFrom-Json` syntax
  block is one parameter wide, `[-InputObject] <String>`. `ConvertTo-CredHashtable`
  already fills the gap, and since 7.3 `-AsHashtable` returns an
  `OrderedHashtable`, which is what `ConvertTo-CredHashtable` produces on both
  editions — the repo's helper is already the forward-compatible shape.

Two Vault-specific notes, neither a blocker:

- **[documented]** Duplicate keys: "if the JSON string contains duplicate keys,
  only the last key is used by this cmdlet", and on 7.x keys differing only in
  case collapse the same way. Vault emits neither, but a `custom_metadata` map
  with both `Env` and `env` would silently lose one. If the spec ever lets `cred`
  read `custom_metadata`, say that PowerShell folds case there and Vault does not.
- **`-Compress` is whitespace-only on both editions [documented]**, and non-ASCII
  escaping is governed by `-EscapeHandling`, "introduced in PowerShell 6.2",
  whose default escapes only control characters. **[observed]** 5.1 therefore
  emits non-ASCII **literally**, not as `\uXXXX`: `ConvertTo-CredJson` produced
  `{"data":{"secret":"tok-äöü-🔑",…}}` as real UTF-8 bytes. That is correct JSON
  and byte-exact — and it is exactly why the outbound trap bites: the string
  leaving `ConvertTo-CredJson` is **not** pure ASCII, so handing it to
  `-Body <string>` destroys it. Had 5.1 escaped non-ASCII, the bug would have
  stayed hidden until someone switched editions. `ConvertTo-CredJson` is correct;
  the *caller* must run its output through `UTF8.GetBytes` before the wire.

## 5. Proxy and private CA

### Private CA

**Works, but only through the Windows certificate store. [observed + documented]**

Against `untrusted-root.badssl.com`, standing in for an internal Vault behind a
private CA, 5.1 fails cleanly — no silent corruption here, at least:

    WebException, Status = TrustFailure
    inner: AuthenticationException -- the remote certificate is invalid
           according to the validation procedure

The documented and correct fix is to install the private root into the Windows
certificate store, which needs no code and no dependency. **[observed]**
`CurrentUser\Root` is **writable without elevation** (75 certs present here);
`LocalMachine\Root` needs elevation. So a per-user trust decision is available to
an unprivileged `cred` user — which is the right granularity for a tool that
otherwise keeps everything under `CRED_HOME`.

The dangerous shortcut, and why to refuse it: **[observed]**
`[Net.ServicePointManager]::ServerCertificateValidationCallback` is a static
property with the same AppDomain-wide leak as `SecurityProtocol`. Setting it to
`{ $true }` disables certificate validation **for every HTTPS call in the
session**, including ones `cred` knows nothing about. That is the "disabling
validation globally" the ticket asks how to avoid, and the answer is: never write
it.

There is a per-request alternative, and it demonstrably works: **[observed]**
`HttpWebRequest.ServerCertificateValidationCallback` exists on .NET Framework
4.8.1 and is honoured — a per-request callback against
`untrusted-root.badssl.com` returned `200`, reported
`RemoteCertificateChainErrors` and `CN=*.badssl.com`, and left the global
callback `$null`. So a scoped trust decision *is* reachable from stdlib — enough
to implement "trust exactly this pinned CA for exactly this request" without
touching global state.

Two caveats. **[documented]** Precedence between the per-request callback and the
`ServicePointManager` one is undocumented, so do not assume the per-request one
wins if something else in the session has set the global. And **[observed]**
`Invoke-RestMethod` on 5.1 exposes neither — no `-SkipCertificateCheck`, and
`-Certificate`/`-CertificateThumbprint` are *client* certificates for
authentication, not server validation. Per-request trust is another thing only
`HttpWebRequest` can do.

Recommendation for the spec: **document the certificate store as the supported
path** ("import your internal CA into `CurrentUser\Root`"), have `cred doctor`
diagnose `TrustFailure` by name and say that, and do **not** ship a
`--insecure`-style switch. If pinning is ever wanted, the per-request callback is
the mechanism, not the global one.

### Proxy

**Works with a caveat, and the caveat is an asymmetry between editions.**
**[observed]** With `HTTPS_PROXY=http://127.0.0.1:9` (a dead port) set in the
environment and a request to `https://httpbin.org/get`:

    Windows PowerShell 5.1   request SUCCEEDED -- the env var was ignored
    PowerShell 7.6.5         request FAILED    -- connection refused to 127.0.0.1:9

**[documented]** Exactly as specified. 5.1 goes through
`WebRequest.DefaultWebProxy`, which "reads proxy settings from the app.config
file. If there is no config file, **the current user's Internet options proxy
settings are used**" — i.e. WinINET / Internet Options, never the environment.
PowerShell 7.0+ switched to `HttpClient.DefaultProxy`, which on Windows "Reads
proxy configuration from environment variables or, if those aren't defined, from
the user's proxy settings" — env vars first
([`DefaultWebProxy`](https://learn.microsoft.com/en-us/dotnet/api/system.net.webrequest.defaultwebproxy?view=netframework-4.8),
[7.5 `Invoke-RestMethod`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-7.5)).

Consequences for the spec, in order of how much they will annoy someone:

1. A CI job or container that sets `HTTPS_PROXY` — the near-universal convention,
   and what the Python implementation gets for free via `urllib`'s
   `getproxies()` — is **silently ignored by 5.1**. Not an error: it goes direct,
   and either succeeds (no proxy needed) or times out at a firewall.
2. `-ProxyCredential` and `-ProxyUseDefaultCredentials` are inert unless `-Proxy`
   is also given **[documented]**, a trap for anyone who sets only the credential.
3. `-NoProxy` does not exist on 5.1 **[observed]** (7.0+). To force a direct
   connection you set `HttpWebRequest.Proxy` to
   `GlobalProxySelection.GetEmptyWebProxy()` **[documented]** — again only
   reachable through `HttpWebRequest`.
4. **[documented]** `HttpWebRequest` bypasses the proxy for "local" destinations,
   including loopback and any address whose domain suffix matches the machine's.
   An internal Vault at a bare hostname (no dots) is treated as local and bypasses
   the proxy automatically — usually what you want, occasionally a surprise.

If PowerShell sync ever ships, it should read `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`
itself and pass the result as an explicit proxy, so both editions and both
implementations agree. That is a dozen lines, not a dependency — but it is a
dozen lines that only exist because 5.1 is 5.1.

## 6. Keeping the token off argv

**Works — but nothing in the cmdlet helps, and one obvious attempt fails
silently.**

**[documented]** `-Headers` takes an `IDictionary`; no parameter anywhere in the
5.1 web cmdlets accepts a `SecureString`. `-Token` (the only one that does) is
7-only. So a Vault token necessarily exists as a plaintext `[string]` inside a
hashtable for the duration of the call — which is the same honest limit the
README already documents for the store: .NET strings are immutable and
garbage-collected.

**[observed]** The tempting workaround does not work and does not complain.
Passing a `SecureString` as a header value sends the literal string
`System.Security.SecureString` on the wire:

    X-Vault-Token: System.Security.SecureString

The plaintext did **not** reach the wire — so this is not a leak — but it is a
silent auth failure whose error message will point at Vault's ACLs rather than at
the bug. Worth a named guard if the sync layer ever accepts a `SecureString`
from `Get-Cred -AsSecureString`: convert explicitly, or refuse.

Where the real exposure is, and it is not argv for our own process:

- **[observed]** header values never appear on any command line; `Invoke-CredProcess`
  and `Start-CredChildProcess` are the only argv builders in the module and
  neither is involved.
- **[documented]** `Win32_Process.CommandLine` carries no privilege qualifier, so
  a token passed as a *parameter to `cred-ps` itself* — `cred-ps push --token …` —
  would be readable by other processes for the lifetime of the call. The standing
  repo rule already forbids this shape; the spec should restate it for the token
  specifically.
- **[documented]** PSReadLine 2.0 (the version in the box on 5.1) scrubs history
  only by substring match on `password`, `asplaintext`, `token`, `apikey`,
  `secret`, and its history file at
  `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt` "is not
  deleted when the session ends". An interactive
  `Invoke-RestMethod -Headers @{'X-Vault-Token'='s.abc…'}` *does* match (`token`),
  but `@{Authorization="Bearer …"}` matches **none** of the five and is written to
  disk permanently. The AST-based filtering that would catch it is PSReadLine
  2.2+, i.e. not on 5.1.

So the rule that follows is the one the repo already lives by, extended one step:
the token arrives from the environment (`VAULT_TOKEN`) or from a file
(`~/.vault-token`), never from a parameter and never from an interactive command
line. Decision 5 of the map already says no token is written to `.creds/` or to
either JSON file; this adds *and never to a command line or a shell history*.

## 7. Is PowerShell sync a reasonable ask?

### First, the honest answer to the question behind the question

The ticket asks how much of "refuse to sync" is a deliberate choice and how much
is a constraint. **Almost all of it is choice.** Every capability the sync layer
needs is reachable from Windows PowerShell 5.1 with no dependency:

| Need | Reachable on 5.1? | With what |
|---|---|---|
| TLS 1.2/1.3 to Vault behind Cloudflare | yes | nothing; leave `SecurityProtocol` alone |
| `X-Vault-Token`, `CF-Access-Client-*` | yes | `-Headers`, or `HttpWebRequest.Headers` |
| Read Vault's error text on 4xx/5xx | yes | `ErrorDetails.Message`, or `WebException.Response` |
| Distinguish Cloudflare Access from Vault | yes | `HttpWebRequest`, `AllowAutoRedirect = $false` |
| Byte-exact non-ASCII both directions | yes | `byte[]` in, raw stream out, explicit UTF-8 |
| KV v2 payloads, CAS version numbers | yes | `ConvertFrom-CredJson` / `ConvertTo-CredJson`, unchanged |
| Private CA | yes | Windows cert store (`CurrentUser\Root`, no elevation) |
| Proxy | yes | read the env vars yourself, pass `-Proxy` explicitly |
| Token off argv | yes | environment or file, never a parameter |

Only two genuine constraints turned up, and neither blocks anything:

1. **TLS 1.3 is unreachable on Windows 10** regardless of configuration, because
   SChannel does not offer it there. Vault serves 1.2, so this costs nothing.
2. **Reading a non-2xx body depends on undocumented behaviour**
   (`ErrorDetails.Message`). Stable since 3.0, but unpromised — and the
   documented `HttpWebRequest` route is available as the fallback, so even this is
   not a wall.

**So the spec must not word the asymmetry as an incapacity.** "PowerShell cannot
do the network" would be false, and a later session would discover that in an
afternoon and undo the decision for the wrong reason. The asymmetry is a
*deliberate* limit on where a second implementation of a correctness-critical
path is worth maintaining.

### Second, what sync would actually cost in PowerShell

The cost is not the HTTP. It is that **every one of the four traps sits on the
path where a wrong answer is silent**, and this repo has already been bitten by
that family four times (`ARCHITECTURE.md:256`, plus the four divergences that
`tests/fixtures/` exists to catch). Specifically:

- `Invoke-RestMethod`, the obvious tool and the one the map's decision 7 names,
  is **the wrong tool** for three of the six requirements. A faithful
  implementation is a `HttpWebRequest` helper — byte-in, byte-out,
  `AllowAutoRedirect = $false`, explicit UTF-8, disposal in `finally` — which is
  structurally the same object as `Invoke-CredProcess`. That is a real,
  reviewable ~60 lines, not a wrapper.
- Python gets all of this right by default. `urllib.request` hands you bytes,
  raises `HTTPError` which *is* a readable response object, and honours
  `HTTPS_PROXY` via `getproxies()`. There is no encoding decision to make and no
  redirect footgun that leaks the token. **The two implementations would not be
  symmetric in effort — they would be off by roughly the whole of this document.**
- Every one of those decisions then becomes a thing the conformance corpus has to
  pin forever, on a matrix of two editions, two locales (because the outbound
  corruption is code-page dependent) and two Windows versions (because TLS 1.3
  is not).

### Recommendation

**Keep `cred-ps` read-only, and make it permanent rather than provisional — but
draw the line at the write, not at the network.**

Concretely, the shape I would put in the spec:

1. **`cred-ps` may `pull`.** A KV v2 read is `GET` with **no request body**, which
   means the *irreversible* trap — outbound transcoding to the ANSI code page —
   **cannot fire on a read path at all**. What remains inbound is reversible and
   fully fixed by reading `RawContentStream`/the raw stream and decoding with
   explicit UTF-8, which is a rule the module already follows everywhere else.
   Pull also sits exactly on the seam the map already located
   (`Read-CredStoreValues`, `Store.ps1:78`), and decision 8 already obliges
   `cred-ps` to read a Vault-backed mirror. Letting it refresh that mirror is a
   small, safe extension of an obligation it already has.
2. **`cred-ps` must refuse to `push`, by name, permanently.** Push is where the
   outbound encoding trap is live *and* irreversible, where CAS correctness
   (`options.cas`, 412 handling, the conflict message) has to be reimplemented
   identically, and where a silent corruption writes a broken secret into the
   shared source of truth that every other machine then pulls. That is the one
   direction where a 5.1-specific bug stops being one machine's problem. The
   refusal is a one-line named message at a single choke point, with the
   `ARCHITECTURE.md:447` precedent.
3. **Word it as a choice, with the reason stated.** Not "PowerShell cannot", but
   *"the authoritative write path has one implementation on purpose; see
   `docs/research/powershell-51-http.md` for what a second one would cost."*
   That keeps the door open without inviting anyone through it casually.
4. **Whatever ships, a fourth trap goes in `ARCHITECTURE.md`'s Encoding section
   now**, because it is true of any future HTTP in this repo, PowerShell sync or
   not: *`Invoke-RestMethod` on 5.1 transcodes a string request body to the host's
   ANSI code page and decodes a charset-less JSON response as Latin-1. Send bytes;
   read bytes.* If `cred-ps` is ever allowed to pull, that line is what stops the
   pull being wrong.

### The condition under which to revisit

One clean trigger, so this is a decision and not a mood: **if Windows PowerShell
5.1 stops being a supported host for `cred-ps`** — i.e. the module requires
PowerShell 7+ — then most of this document evaporates. On 7, `Invoke-RestMethod`
gets the encoding right by default, `-SkipHttpErrorCheck` and
`-StatusCodeVariable` make the error path documented, `-MaximumRedirection 0`
surfaces the 302, and `HTTPS_PROXY` is honoured. Symmetric sync in PowerShell 7
is a genuinely reasonable ask; it is 5.1 that makes it expensive. `src/Cred`
currently carries `#requires -Version 5.1` and the launcher table advertises
"PowerShell 5.1 / 7", so that trigger is nowhere near — but it is the thing to
watch, not "has anyone asked for PowerShell sync".

## Appendix: the two behaviours worth a regression test

If any of this ships, these two are the ones that will regress silently.

**1. Byte-exact non-ASCII across HTTP.** Against a local listener, assert that a
push body arrives as the exact 15 UTF-8 bytes of `tok-äöü-🔑` and that a pull of
a charset-less `application/json` response yields the same 15 bytes. The corpus
already contains the value; this reuses it. A test that asserts *only* the
round trip through one implementation will pass while both ends are wrong in the
same way — the exact failure mode `ARCHITECTURE.md` describes for
`tests/Interop.Tests.ps1` — so assert the **wire bytes**, not the round trip.

**2. The non-2xx body survives.** Assert that a `403` with a JSON body yields
Vault's error text, on both editions, parsed not compared — 5.1 returns the raw
body and 7 returns a re-serialised one. This is the test that protects the one
undocumented dependency in the design.

Both need nothing but a `TcpListener` in a runspace, which is how every
measurement in this document was made: no network, no fixtures, no dependency.
