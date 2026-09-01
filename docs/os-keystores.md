# OS keystores off Windows

On Windows, `cred key protect` wraps the age identity with DPAPI and the whole
thing takes four lines of `ctypes`. Everywhere else `keystore_name()` returns
`"none"` and the CLI tells you to protect the key file yourself. This note is
the research behind that gap: what the OS-native equivalent of DPAPI is on
Linux and macOS, whether anything can be plugged into the same seam, and what
to do if nothing can.

Every factual claim here is cited to the specification, the official
documentation, or the source that owns the behaviour. Where a claim comes from
running the thing on a real machine instead, it says so — that machine is Arch
Linux, systemd 261, age 1.3.1, GNOME Keyring on a Wayland session, and it is
evidence about one configuration rather than a guarantee.

## The contract being matched

DPAPI was not chosen because it is the strongest thing available. It was chosen
because of the shape of its interface, which is the part that has to be matched:

- **Zero install.** `Crypt32.dll` ships with the OS. Microsoft's own
  description is that DPAPI is "a service that is provided by the operating
  system itself and does not require any additional libraries", and that
  "application developers can assume that all Windows systems have this DLL
  available" ([Windows Data
  Protection](https://learn.microsoft.com/en-us/previous-versions/ms995355%28v%3Dmsdn.10%29)).
- **Non-interactive.** No prompt, no unlock step, nothing to set up first.
- **Arbitrary bytes in, opaque blob out.** `CryptProtectData` takes a
  `DATA_BLOB` of plaintext and returns a `DATA_BLOB`; there is no encoding
  question and no length rule to trip over. That is what lets `wrap_identity`
  base64 the result into one JSON field.
- **Bound to the user account.** "Typically, only a user with the same logon
  credential as the user who encrypted the data can decrypt the data"
  ([CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)).
- **Headless-safe.** It is an LSA RPC call on the local machine. There is no
  session, no display, no daemon of your own to keep alive.

Two things about DPAPI are worth stating precisely, because the whole
comparison turns on them and it is easy to credit DPAPI with more than it does.

**It does not protect you from code running as you.** Microsoft says so
outright: "A small drawback to using the logon password is that all
applications running under the same user can access any protected data that
they know about." The optional entropy parameter exists to blunt this, and it
"does not strengthen the key used to encrypt the data" — it only makes one
application's blob harder for another application under the same account to
open. `cred` passes `NULL` for it on both sides
(`python/cred_store.py:540`, `src/Cred/Private/Platform.ps1:126`), so a
DPAPI-wrapped `identity.wrapped.json` is readable by anything running as you.
Against a local-process attacker, DPAPI and a mode 600 file are the same
protection.

**What it does protect is the key at rest.** The MasterKey is 512 bits of
random data stored in the user's profile, encrypted under a key derived from
the user's logon credential — SHA-1 of the password, then PBKDF2 with a
16-byte salt and a default of 4000 iterations. The per-blob session key is
derived from the MasterKey and never stored. So an attacker holding the disk,
a backup image, or the profile directory does not have the key; they have a
password-cracking problem, and by 2026 standards PBKDF2-SHA1 at 4000
iterations is not much of one. (All from [Windows Data
Protection](https://learn.microsoft.com/en-us/previous-versions/ms995355%28v%3Dmsdn.10%29),
"Keys and Passwords in DPAPI" and "MasterKey".) On a domain-joined machine
there is a second copy of the MasterKey encrypted to a Domain Controller
public key, recoverable over RPC, which is worth knowing before calling DPAPI
an offline-only protection.

That is the honest DPAPI: *at-rest* protection tied to a login secret, not
process isolation. Any candidate below should be judged against that, not
against a stronger DPAPI that does not exist.

One correction to the record while we are here. The DPAPI calls in this
repository do **not** pass `CRYPTPROTECT_UI_FORBIDDEN`; Python passes
`dwFlags = 0` (`python/cred_store.py:540` and `:239`) and PowerShell goes
through `ProtectedData.Protect`/`Unprotect` with
`DataProtectionScope.CurrentUser`, which has no flags parameter
(`src/Cred/Private/Platform.ps1:126`, `:144`). The behaviour is still
non-interactive, because the prompt flow is opt-in through
`pPromptStruct` and `cred` passes `NULL` for that too — and Microsoft now
documents the prompt flow as deprecated, to be removed in February 2027, with
`NULL` selecting "the non-interactive path for new operations". Nothing needs
fixing, but the flag is not there and the comments should not imply it is.

## systemd-creds — the closest thing Linux has

`systemd-creds` is the credential encryption tool that ships as part of
systemd. It encrypts a named blob with a key derived from a secret in
`/var/lib/systemd/credential.secret`, from the local TPM2, or from both:
"Credentials may optionally be encrypted and authenticated, either with a key
derived from a local TPM2 chip, or one stored in `/var/`, or both"
([systemd.io System and Service
Credentials](https://systemd.io/CREDENTIALS/)). The default, `--with-key=auto`,
uses both where both are available, "thus ensuring that credentials protected
this way can only be decrypted and validated on the local hardware and OS
installation".

On its own that is machine binding, not user binding, and it would not qualify.
The thing that makes it qualify arrived in systemd 256:

> Encrypted service credentials can now be made accessible to unprivileged
> users. systemd-creds gained new options --user/--uid= for
> encrypting/decrypting a credential for a specific user.
>
> — [systemd NEWS, v256](https://github.com/systemd/systemd/blob/v256/NEWS)

`man systemd-creds(1)`, under `--user`, says what that binding is: "Such
credentials may only be decrypted from the specified user's context, except if
privileges can be acquired… Internally, this ensures that the selected user's
numeric UID and username, as well as the system's machine-id(5) are
incorporated into the encryption key." With `--uid=self`, implied by `--user`
alone, the credential is encrypted for the calling user. That is the DPAPI
property, arrived at by a different route: machine plus account, unwrappable by
any process running as you, useless to another local account.

An unprivileged process gets at this through a Varlink service, added in
systemd 255, that runs as root and does the key handling on your behalf. On the
research machine the socket is world-connectable and socket-activated by
default — `srw-rw-rw- root root /run/systemd/io.systemd.Credentials`, unit
`systemd-creds.socket`, `WantedBy=sockets.target`, and shipped in
`/usr/lib/systemd/system/sockets.target.wants/`, so it is on without anybody
enabling anything. The service reads the caller's UID from the connection,
which is what makes the user binding an enforced property rather than an
argument the caller supplies: the interface documents `uid` as "If not
specified and 'user' scope is selected defaults to the UID of the calling user,
if that can be determined" (`varlinkctl introspect
/run/systemd/io.systemd.Credentials`, observed).

Both halves of that are in the source, which is worth pointing at because the
distinction between "checked" and "keyed" is the whole value of the mechanism.
`src/creds/creds.c` takes the caller's identity from the kernel with
`sd_varlink_get_peer_uid()` — `SO_PEERCRED`, not something the caller can
claim. `src/shared/creds-util.c` then folds it into the key rather than merely
comparing it: `struct ScopeHashData` carries the uid and the machine ID,
`SCOPE_HASH_DATA_BASE_FLAGS` is `HAS_UID | HAS_USERNAME | HAS_MACHINE`, and
`mangle_uid_into_key()` calls `getpwuid_malloc()` to bring the username in. A
blob for another account is not refused; it is undecryptable.

### Observed behaviour

All of the following was run on the research machine as an ordinary user, uid
1000, with no `sudo`, and `/var/lib/systemd/credential.secret` mode `0400
root:root` and unreadable:

- `systemd-creds encrypt --user --name=cred-identity - -` round-trips through
  `decrypt` and returns the input byte for byte, including an embedded NUL and
  invalid UTF-8 (`a\x00b\xff\xfe` came back as `a\x00b\xff\xfe`). Arbitrary
  bytes, confirmed.
- It works with `env -i`: no session bus, no `DISPLAY`, no `XDG_RUNTIME_DIR`,
  no terminal. Nothing prompts. This is the property Secret Service does not
  have.
- Decrypting with the wrong `--name` fails ("Name in credential doesn't match
  expectations"), and decrypting a `--user` credential without `--user` fails
  ("Scope mismatch"). The name is authenticated, which the man page describes
  as being "done in order to ensure that encrypted credentials are not
  re-purposed without this being detected".
- A 189-byte age identity encrypts to a 796-character base64 blob — small
  enough to sit in the existing `data` field of `identity.wrapped.json` without
  anyone noticing.
- Steady-state cost is about 30 ms per decrypt, with `host` and `host+tpm2`
  indistinguishable. The very first call on a machine took 1.3 s, because that
  is when `/var/lib/systemd/credential.secret` gets created and the TPM is
  first touched.

### What it would cost cred

Less than anything else here, which was the surprise. It does not even need a
subprocess. Varlink is NUL-terminated JSON over an `AF_UNIX` socket at a fixed
path, so the whole client is about twenty lines of `socket` and `json` — both
stdlib, both there in 3.8. This actually ran, and round-tripped an age
identity exactly:

```python
def call(method, params):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/run/systemd/io.systemd.Credentials")
    s.sendall(json.dumps({"method": method, "parameters": params}).encode() + b"\0")
    buf = b""
    while not buf.endswith(b"\0"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    return json.loads(buf.rstrip(b"\0"))
```

`Encrypt` takes `data` as base64 and returns `blob` as base64; `Decrypt` takes
the blob and gives the base64 back. Errors come back as clean identifiers —
`io.systemd.Credentials.NameMismatch`,
`io.systemd.InteractiveAuthenticationRequired` — which map onto `CredError`
without string matching. Subprocessing `systemd-creds` is the alternative and
costs nothing extra, since `cred` already shells out to `age`; the socket is
simply cheaper and has no argv to keep secrets off. A new `protection` value —
`systemd-creds-user` — slots in beside `dpapi-currentuser` with no format
change, because the wrapped-identity file was already self-describing.

The PowerShell edition can reach the same socket: .NET has
`System.Net.Sockets.UnixDomainSocketEndPoint` from .NET Core 2.1 and
PowerShell 7 on Linux. Windows PowerShell 5.1 cannot, but Windows PowerShell
5.1 does not run on Linux either, so that is not a real gap.

### Where it does not reach

- **systemd 256 is recent.** `--user` landed in June 2024, and LTS
  distributions lag. Debian 13 trixie ships systemd 257 and Debian 12 bookworm
  ships 252
  ([packages.debian.org](https://packages.debian.org/search?keywords=systemd&searchon=names&suite=all&section=all));
  Ubuntu 24.04 LTS ships 255 — one short — while 25.10 ships 257 and 26.04 LTS
  ships 259
  ([packages.ubuntu.com](https://packages.ubuntu.com/search?keywords=systemd&searchon=names&exact=1&suite=all&section=all));
  RHEL 10 ships 257 and RHEL 9 ships 252. So it is available on current
  releases and absent on the LTS releases people are still running. That is a
  gap that closes on its own, but not this year, and `keystore_available()`
  has to probe rather than assume.
- **Not portable off systemd.** Alpine, the musl containers, the BSDs, WSL1,
  and anything running without systemd as PID 1 have neither the binary nor
  the socket. In a container the socket only exists if systemd is running
  inside it; and `--with-key=auto` is documented to skip TPM2 when "running in
  a container", falling back to the host key, which then needs
  `/var/lib/systemd` on persistent media. A container is exactly where you
  would most want this and exactly where it is least likely to work.
- **Same non-portability trade as DPAPI, for the same reason.** A wrapped key
  does not survive a reinstall (new `credential.secret`), a TPM clear, a
  `machine-id` change, a UID change, or a rename. `cred key protect --backup`
  and its warning apply unchanged.
- **Root can decrypt anything.** The man page says so — "except if privileges
  can be acquired". This is the same as DPAPI, where LSA holds the MasterKeys,
  so it is not a point of difference.

## Secret Service / libsecret — the obvious answer, and why it is not one

This is what everybody reaches for, and it is what `Platform.ps1` names in a
comment as one of the two obvious next steps. It does not survive contact with
the requirements.

**It is a specification, not an implementation** — the
[Secret Service API](https://specifications.freedesktop.org/secret-service/latest/),
still published as "Version: Secret Service 0.2 DRAFT" as of April 2026, with
the D-Bus name `org.freedesktop.secrets`. It is stable in practice because
three implementations froze around it, not because the document is finished.
The implementations are gnome-keyring-daemon, KWallet's Secret Service front
end, and KeePassXC's opt-in one. On the research machine
`org.freedesktop.secrets` is owned by `gnome-keyring-daemon --components=pkcs11,secrets`,
with `org.kde.secretservicecompat` also activatable — two providers, one name,
first to claim it wins.

Four things sink it, and a fifth would make it expensive even if you accepted
the other four.

**It needs a login session, by definition.** The specification's own
introduction says the service runs "in the user's login session", and
`gnome-keyring-daemon(1)` says it is "normally started automatically when a
user logs into a desktop session". Unlocking happens through
`pam_gnome_keyring.so`, which pipes the login password in at PAM time. Over
SSH that PAM module is typically not in the sshd stack, so the login keyring
stays locked; and `DBUS_SESSION_BUS_ADDRESS` is not exported either, at which
point libdbus autolaunches a fresh, empty, isolated bus rather than failing.
That is the worst possible failure mode: it looks like it worked and the
secret is not there. Observed here — with `XDG_RUNTIME_DIR` still set,
`secret-tool` finds `/run/user/1000/bus` and works; with a genuinely clean
environment it dies with `Cannot autolaunch D-Bus without X11 $DISPLAY`.

**Unlocking is interactive by design.** The `Prompt` interface takes a window
id. There is no non-interactive unlock, which is the single property the DPAPI
seam most depends on.

**It is not installed where it would be needed.** A Secret Service provider is
a desktop assumption, not a Linux assumption: present on Ubuntu, Debian and
Fedora *desktops*, absent from server installs and from every container base
image. `secret-tool` itself is `libsecret-tools` — Debian main, but Ubuntu
*universe* with no `Task:` field at all, so it is in no Ubuntu flavour's
default install; on Fedora it is inside the base `libsecret` package, which
makes Fedora Workstation the one mainstream target where it is there by
default. Fedora Server is the nastiest case: `secret-tool` exists and fails at
runtime.

**And it does not take bytes, whatever the wire format says.** The `value`
field of a `Secret` is `ay` on the bus, but no client API you would actually
call is byte-shaped. `secret_password_store_sync`'s `password` parameter is
documented as "The **null-terminated** password to store… The value is a NUL
terminated UTF-8 string"
([libsecret](https://gnome.pages.gitlab.gnome.org/libsecret/func.password_store_sync.html)).
There *is* a bytes API — `SecretValue`, whose data "is not necessarily
null-terminated, unless the content type is `text/plain`", with
`secret_password_store_binary_sync` since 0.19.0 — but `Secret.Value.new` has
no array annotation on its `secret` parameter, so through PyGObject you can
read arbitrary bytes back and cannot cleanly write them.

`secret-tool` is worse, and worth spelling out because a first test can
mislead you. Its man page says "A password to store can also be piped in via
stdin. The password will be the contents of stdin until EOF", but
`read_password_stdin()` in `tool/secret-tool.c` validates with
`g_utf8_validate(password, -1, NULL)` and exits 1 on failure, and caps the
read at 8192 bytes with the comment `/* TODO: This restriction is due purely
to laziness. */`. Because that `-1` means "validate up to the first NUL", a
payload whose *prefix* is valid UTF-8 sails through and round-trips exactly,
while the same bytes without a leading ASCII run are rejected. Both observed
here: `OK\x00\xff\xfe` stored and came back byte-exact; `\xff\xfe\xfd-not-utf8`
gave `secret-tool: password not valid UTF-8`, exit 1. Anyone testing with an
`AGE-SECRET-KEY-…` prefix would conclude binary works. It does not; that is an
accident of the validation call. Base64 is the only defensible way through.

**Reaching it from stdlib-only Python 3.8+ is a project, not a call.** There is
no D-Bus in the standard library — 316 entries in the module index, none of
them D-Bus, `gi`, GLib or GObject. Raw D-Bus over the socket means the NUL
byte before the ASCII handshake, `AUTH EXTERNAL` with the uid as the hex of the
*decimal string* (`1000` → `31303030`, not `0x3e8`), the mandatory
`org.freedesktop.DBus.Hello` without which you are disconnected, and a
marshaller whose alignment "boundaries are calculated globally, with respect to
the first byte in the message" — so sub-buffers cannot be built independently
and concatenated. That is roughly 250–350 lines for one hardcoded call and
450–700 for anything you would want to own, all of it arithmetic that fails
silently. The alternatives each break a constraint: `secret-tool` is not
installed by default anywhere but Fedora Workstation, and PyGObject is not
stdlib, is absent from every `python:3.x` container, is ABI-pinned to a
specific interpreter, is invisible in a venv without
`--system-site-packages` — and upstream now requires Python 3.9+, below this
repository's floor.

### The finding that settles it

On this machine, `~/.local/share/keyrings/Default_keyring.keyring` is
gnome-keyring's *textual, non-encrypted* format — `gkm-secret-textual.c`
describes it in exactly those words — protected by nothing but mode 0600.
Stored a canary through `secret-tool`, then grepped the file for it: one match,
in cleartext.

That is a configuration-dependent result, not a universal one: it happens when
the keyring has no password of its own, which on this box is a consequence of
how the session logs in. The keyring here carries `lock-on-idle=false` and
`lock-after=false` and no salt or iteration count. But it is a *default*
configuration on a mainstream desktop, and the consequence is exact: for a
real user on a real install, moving the age identity from a mode 600 file into
Secret Service would add a daemon, a session dependency, a base64 encoding, a
draft specification and several hundred lines of protocol code — in exchange
for storing the key in a mode 600 file. Writing gnome-keyring's own format
directly is not a way out either: the only documentation is a ~50-line struct
sketch in `pkcs11/secret-store/file-format.txt` with no stability statement,
and the encrypted variant keys AES-128-CBC from the user's login password,
which is not available non-interactively.

## The kernel keyring

`add_key(2)`, `request_key(2)`, `keyctl(2)` and the `keyctl(1)` tool give you
an in-kernel place to put small blobs, organised into thread, process, session,
user, user-session and persistent keyrings ([`man 7
keyrings`](https://man7.org/linux/man-pages/man7/keyrings.7.html)). It looks
like the answer and it is not, for one reason that settles it before any of the
details matter.

**It is a cache, not storage.** Keys live in kernel memory and nothing is ever
written to disk. A reboot loses everything. Even short of a reboot the
lifetimes are hostile: `user-keyring(7)` says the user keyring is destroyed
when the last process holding a reference to it exits, and the persistent
keyring — the only one designed to outlive a logout — expires. The default is
three days, which is not in the man page but is `3 * 24 * 3600` in keyutils'
`persistent.c`, and matches `/proc/sys/kernel/keys/persistent_keyring_expiry`
= `259200` observed here.

So `cred` would still need somewhere to keep the identity across a reboot, and
that somewhere is the problem the keystore was supposed to solve. The keyring
can only ever be a layer on top: unlock once, cache, re-prompt in three days.
That is a genuinely useful pattern — it is roughly what `ssh-agent` is — but it
is not a replacement for `identity.wrapped.json`.

The rest, for the record:

- **Binding is by possession, not by user.** This is the part that is easy to
  get wrong. Permissions are granted separately to possessor, user, group and
  other, and possession is a property of the calling process's keyring chain
  rather than of its uid. Observed here: after `keyctl padd user cred-probe
  @u`, a separate `bash -c 'keyctl print …'` got `Permission denied` even
  though it ran as the same user, because it did not possess the key. Root
  without possession is denied too. Reasoning about this correctly is harder
  than the whole DPAPI path.
- **`pam_keyinit` actively destroys the session keyring.** `man 8 pam_keyinit`:
  "Be aware that after the session keyring has been replaced, the old session
  keyring and the keys it contains will no longer be accessible." It is in the
  base `pam` package and enabled with `force revoke` in every login path on
  this machine.
- **Quotas are small and the byte quota binds first.**
  `/proc/sys/kernel/keys/maxkeys` = 200 and `maxbytes` = 20000 for non-root
  here; a 30000-byte `keyctl padd` failed with `add_key: Disk quota exceeded`.
  Fine for an age identity, not fine as a general store.
- **Secrets need not go on argv.** `keyctl add` puts the payload on the command
  line; `keyctl padd` reads it from stdin. Only the latter is usable here.
- **Reachable from stdlib Python**, via `ctypes` and `syscall()` — no
  `keyutils` package, no PyPI. That part is genuinely fine.

## TPM2 directly, and the rest of the field

**tpm2-tools** is a package to install, not something that ships. It needs
`/dev/tpmrm0`, which is `crw-rw---- root tss` under the upstream `tpm2-tss`
udev rule, so an unprivileged user needs adding to a group before they can use
it at all. And TPM2 sealing binds to the machine and to PCR state — not to a
user account. It fails zero-install, fails user-binding, and fails on any
machine without a TPM. Everything worth having from it is already available,
for free and without the group membership, through `systemd-creds`, which is
what that tool is for.

Four others were checked and ruled out, all for the same underlying reason —
they consume a secret rather than keep one, or they need a login session:

- **fscrypt** is filesystem encryption. It protects directories, not a
  hundred-byte blob, and the kernel documentation notes the API "can be used by
  unprivileged users, with no need to mount anything" only because v2 uses
  `FS_IOC_ADD_ENCRYPTION_KEY` — the keyring path is v1-only and deprecated.
  You would still need somewhere to put the identity *inside* the encrypted
  directory, which is where we came in.
- **pam_mount** advertises "No stored passwords" as a feature. It reuses the
  login password at PAM time precisely so it never keeps one. There is no API
  to deposit bytes.
- **ecryptfs** is `S: Odd Fixes` in the kernel `MAINTAINERS` file, is in
  Ubuntu's `universe` rather than main, and `ecryptfs-add-passphrase` *puts* a
  secret into the keyring so a mount can proceed. Same category error.
- **systemd-homed** does not persist the `secret` section of a user record at
  all, and both `privileged` and `secret` are closed field sets
  (`hashedPassword`, `sshAuthorizedKeys`, `pkcs11EncryptedKey`,
  `fido2HmacSalt`, `recoveryKey`) with no slot for arbitrary bytes. It also
  requires migrating the account.

## Wrapping the identity with your SSH key

This one is not an OS keystore at all, and it is the only candidate here that
introduces no new mechanism whatsoever — no daemon, no library, no second
binary. It encrypts the age identity to an SSH public key you already have,
using the `age` that `cred` already requires. That makes it worth taking
seriously even though it does not belong to the operating system.

age supports this natively on both sides. From its README: "age also supports
encrypting to `ssh-rsa` and `ssh-ed25519` SSH public keys, and decrypting with
the respective private key file"
([README](https://github.com/FiloSottile/age/blob/main/README.md)). The man
page is more precise about the identity side: "An `IDENTITY` is an SSH private
key *file* passed individually to `-i`/`--identity`"
([age.1](https://github.com/FiloSottile/age/blob/main/doc/age.1.ronn)).

Wrapping is `age -a -R ~/.ssh/id_ed25519.pub -o identity.wrapped identity.txt`
and unwrapping is `age -d -i ~/.ssh/id_ed25519`. Confirmed end to end on the
research machine: wrapped an age identity to an ed25519 public key, unwrapped
it under `env -i` with no terminal, no agent, no session bus and no
`XDG_RUNTIME_DIR`, and drove `cred get` through the result. About 16 ms. It is
a subprocess to a binary that is already a hard dependency, so it is reachable
from stdlib-only Python 3.8+ by construction, and from PowerShell 5.1 through
the `Invoke-CredProcess` path that already exists.

### The catch, and it is the whole story

**age cannot use ssh-agent.** The man page: "Note that keys held on hardware
tokens such as YubiKeys or accessed via ssh-agent(1) are not supported." The
maintainer, asked directly, calls it "technically impossible to support them
through the standard ssh-agent protocol" ([discussion
#218](https://github.com/FiloSottile/age/discussions/218)) — the agent protocol
exposes signing, and age's SSH stanzas need key agreement. `agessh/agessh.go`
contains no reference to an agent.

Nor is there a way to feed a passphrase in. `internal/term` opens `/dev/tty`,
falls back to stdin only when stdin is already a terminal, and otherwise
errors; there is no `SSH_ASKPASS` support anywhere in it. Observed exactly
that: with the key loaded into a running `ssh-agent` and `SSH_ASKPASS` set and
`SSH_ASKPASS_REQUIRE=force`, `age -d -i ed_pass` still ignored both and failed
with `standard input is not a terminal, and /dev/tty is not available`.

So the option forks into two, and they are not close:

**A passphrase-less SSH key.** Fully non-interactive, headless, zero-install,
arbitrary bytes, works today on every platform including macOS and Windows.
It also protects nothing at rest that a mode 600 identity file did not already
protect, because an OpenSSH private key with no passphrase is stored with
"the cipher `none` and the KDF `none`"
([PROTOCOL.key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key)).
An attacker with the disk has `~/.ssh/id_ed25519`, and therefore has the
identity. You have moved the secret, not protected it. The one genuine gain is
that it is no longer *two* files to look after — but that is filing, not
security.

**A passphrase-protected SSH key.** Now there is real at-rest protection —
bcrypt_pbkdf, not PBKDF2-SHA1-4000 — and it is stronger than DPAPI's. But
because there is no agent support, the passphrase is demanded on the terminal
on *every single `cred` operation*, and the operation fails outright with no
tty. That is not the DPAPI contract; it is `age -p` with extra steps. And it is
a bad trade even on its own terms: it takes the passphrase off a
narrowly-scoped, easily-rotated age identity and puts the load on the user's
SSH key — the credential with the widest blast radius they own — typed far more
often, into a prompt that is now routine. Making a high-value passphrase
routine is how it ends up in a wrapper script.

Two smaller notes. Only `ssh-rsa` and `ssh-ed25519` are supported;
`ecdsa-sha2-nistp256` is rejected outright with `unknown recipient type`
(observed), and `agessh` handles only `ed25519.PrivateKey` and
`rsa.PrivateKey`. And age's README warns that "SSH key support employs more
complex cryptography, and embeds a public key tag in the encrypted file, making
it possible to track files that are encrypted to a specific public key", plus
"people might not protect SSH keys long-term, since they are revokable when
used only for authentication" — a caution that lands squarely on using an SSH
key as your only copy of a decryption key.

### The other variant: SSH keys as store recipients

Encrypting `.creds/store.age` directly to SSH public keys, dropping the wrapped
identity entirely, is a real thing age supports — the man page's own example is
`curl https://github.com/benjojo.keys`. Onboarding a colleague would become
"paste their GitHub username".

It should not be done here, for a reason that has nothing to do with
cryptography. `recipients` in `config.json` is plaintext and committed, and
that is deliberate. Making them SSH public keys pins the store's readership to
keys that their owners rotate for unrelated reasons, cannot enumerate the
copies of, and — per age's own warning — do not treat as long-lived decryption
keys. Rotating an SSH key would silently lock someone out of the
store, and rotating the *store* would mean chasing everyone's current key. The
age recipient model exists precisely so that the encryption key is separate
from the authentication key. This would collapse them. It is also a change to
the data model, which the ARCHITECTURE file treats as the contract, for a
convenience gain — the wrong side of that trade.

Where the idea does belong is `--backup`: an escrow copy of the identity
encrypted to a team lead's SSH key is strictly better than the current advice
of writing a plaintext key to a path and hoping.

## Is `age -p` the right fallback?

It is a reasonable fallback and the message that recommends it is wrong in
three specific ways, one of which means the command as printed cannot work.

What `-p` does: encrypt under a passphrase using scrypt. The work factor is
`logN = 18`, commented in `scrypt.go` as "1s on a modern machine", and
decryption refuses anything above 22. That is a serious work factor —
materially stronger at rest than DPAPI's PBKDF2-SHA1 at 4000 iterations. The
Go documentation is blunt about the shape, though: "Its use is not recommended
for automated systems, which should prefer [HybridRecipient] or
[X25519Recipient]."

Applied to the *identity file* rather than the store, which is what
ARCHITECTURE.md already recommends and what the fallback message repeats, the
prompt lands in one place instead of on every operation's ciphertext, and age
accepts the result directly: "Passphrase encrypted age files can be used as
identity files" (`age --help`). Verified end to end — encrypted a real
`identity.txt` in place, then `cred get demo` prompted once on the tty and
returned the right secret.

The three problems:

**The command as printed fails.** `age -p identity.txt` writes to stdout,
because "INPUT defaults to standard input, and OUTPUT defaults to standard
output", and age then refuses: `age: error: refusing to output binary to the
terminal` / `hint: did you mean to use -a/--armor?` (observed verbatim). The
command that works is `age -p -a -o identity.age identity.txt`, and the user
then has to know to put the result at `$CRED_HOME/identity.txt` — which the
message does not say, and which is the step that actually connects it to
`cred`.

**It silently costs you non-interactive operation, and the message does not
say so.** age reads passphrases from `/dev/tty` only. Every `cred get`, `cred
exec`, `cred list --verify` now needs a terminal. The DPAPI path this is
offered as the equivalent of needs none. Anyone wiring `cred exec` into a
script or a CI job is being pointed at something that will break there, with no
warning at the point of advice.

**Failure in that case is misdiagnosed.** With no tty, `cred get` reports:

```
cred: age could not decrypt the store: age: error: failed to decrypt identity
file: could not read passphrase: … /dev/tty is not available …
cred: Next:
cred:   The store may be damaged. Restore it from git:
cred:     git checkout HEAD -- .creds/
```

The store is fine. The advice is to `git checkout` over it. The underlying age
error does say "failed to decrypt **identity** file", so the two cases are
distinguishable in `age_decrypt`'s error mapping (`python/cred_store.py`, the
`rc != 0` branch) — this is a real papercut with a small fix, not an inherent
limit.

## macOS: Keychain Services

The Mac has the thing Linux does not: a real, first-party, zero-install
keystore. `/usr/bin/security` is part of the base OS, not of Xcode — Apple's
end-user documentation tells ordinary users to run it by absolute path with no
developer-tools prerequisite ([Configure domain access in Directory
Utility](https://support.apple.com/guide/directory-utility/configure-domain-access-diru11f4f748/mac)),
the Command Line Tools install to `/Library/Developer/CommandLineTools` and do
not contain it, and it is built from the base-OS
[Security](https://github.com/apple-oss-distributions/security) project. Apple
never says "`security` ships in the base OS" in one sentence, but those three
converge.

It is also more awkward than it first looks, in ways that matter here.

**Which keychain you get is decided for you.** There are two: the modern data
protection keychain and the legacy file-based one. The data protection keychain
is reached through keychain access groups, which come from code-signing
entitlements that "must be authorized by a provisioning profile" embedded in
"an app-like bundle structure", which is "not [standard] for command-line
tools" ([TN3137: On Mac keychain APIs and
implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)).
An unsigned CLI has no entitlements, so it gets `errSecMissingEntitlement` and
falls back to the file-based keychain. Every modern guarantee —
`kSecAttrAccessible`, access groups, the access control object — is therefore
unavailable to `cred` unless someone codesigns and provisions it, which is a
paid developer account and a notarisation pipeline for a script.

**On the file-based keychain, access is an ACL of trusted applications**, and
the default is exactly what you want: "By default, the application which
creates an item is trusted to access its data without warning"
([security(1)](https://keith.github.io/xcode-man-pages/security.1.html), under
`add-generic-password`). `SecACL.h` documents the list as "an array of
`SecTrustedApplication` instances that will be allowed access without
prompting". So an item written by `/usr/bin/security` and read back by
`/usr/bin/security` does not prompt.

The subtlety is what "the same application" means, and the answer is different
for signed and unsigned code. `TrustedApplication.cpp` is explicit that "the
path argument is only stored for documentation; it is NOT used to denote
anything on disk". A code-signed binary is matched by its designated
requirement, checked at access time with `SecStaticCodeCheckValidity`, so it
survives updates from the same signing identity. An unsigned one is matched by
a SHA-1 "legacy hash" of its bytes — byte-exact, so any rebuild, patch or
package upgrade silently invalidates the grant and the user gets a prompt they
were not expecting.

That settles the design question: **the ACL principal must be
`/usr/bin/security`**, not the interpreter and not `cred` itself. It is
Apple-signed, stable across updates, and already on every Mac. Trying to trust
`/usr/bin/python3` would be worse in both directions — Apple's built-in Python
is deprecated and Apple tells you to ship your own ([Apple
DTS](https://developer.apple.com/forums/thread/704099)), and trusting an
interpreter grants access to every script it runs anyway.

**Secrets can be kept off argv**, which the invariants require.
`security -i` takes subcommands on stdin, and `readline.c` uses `getchar()`
with no `isatty()` gate, so a pipe works. Do not use bare `-w` with a pipe
instead: `-w` without a value goes through `getpass(3)`, which reads `/dev/tty`
whenever it is available and truncates at 128 characters.

**It is not a byte store.** `-w` takes the password through `strlen()`, so a
NUL is impossible. `-X` accepts "password data to be added as a hexadecimal
string", which is the way to store arbitrary bytes; the output encoding of
`find-generic-password -w` for non-UTF-8 data is undocumented, so hex or base64
on both sides is the only defensible choice. Since `cred` wraps an age identity
— printable ASCII — this is a small tax, but it is a tax, and it is the
difference between this and `CryptProtectData`'s `DATA_BLOB`.

**It fails over SSH.** The login keychain is auto-unlocked at GUI login and not
by an SSH session; Apple DTS states it plainly — "Logging in via SSH does not
unlock the keychain" — and the call then returns `errSecInternalComponent`
([Apple DTS](https://developer.apple.com/forums/thread/712005)). The remedy is
`security unlock-keychain`, whose password is itself a secret you would have to
supply from somewhere. So macOS Keychain is non-interactive in a GUI session
and not available at all in the headless case — the opposite of DPAPI on that
one axis.

**And there is a second, undocumented gate.** The partition list "is an extra
parameter in the ACL which limits access to the item based on an application's
code signature. You must present the keychain's password to change a partition
list" (security(1)). Apple DTS on it: "Keychain partitions are a bit of a dark
art because they were added to the file-based keychain long after it was
initially introduced. Thus, they have no APIs and the docs are kinda minimal"
([Apple DTS](https://developer.apple.com/forums/thread/756171)). What partition
list a fresh `add-generic-password` item gets is not documented anywhere
primary. That is a real risk for a tool that has to work the same way on
someone else's Mac.

The escape hatch, `-A` — "Allow any application to access this item without
warning (insecure, not recommended!)" — buys unconditional non-interactivity by
letting every process running as that user read the item. Which, note, is
exactly the DPAPI property established above. It is not the disaster the man
page's tone suggests *for this specific use*, since a mode 600 identity file
already has that exposure; but it does give up the one thing the ACL was buying.

Reachable from stdlib Python 3.8+: yes, through `subprocess` to
`/usr/bin/security -i`. The `ctypes` route against Security.framework is
technically possible but buys nothing — without entitlements `SecItemAdd`
lands on the same file-based keychain — in exchange for a few hundred lines of
CoreFoundation bridging. It also has a trap worth writing down if anyone tries:
since Big Sur, "copies of dynamic libraries are no longer present on the
filesystem… check for library presence by attempting to `dlopen()` the path"
([macOS Big Sur 11.0.1 release
notes](https://developer.apple.com/documentation/macos-release-notes/macos-big-sur-11_0_1-release-notes)),
so an `os.path.exists` availability probe returns `False` on a working system.

## The comparison

"Zero install" means present without the user installing anything, on a
mainstream default configuration. "User-bound" means another local account
cannot unwrap it. "Headless" means it works over SSH with no display and no
session bus. Windows DPAPI is the row everything else is being measured
against.

| | Zero install | Non-interactive | Arbitrary bytes | User-bound | Headless | Survives reboot | Stdlib Python 3.8 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **DPAPI** (Windows) | yes | yes | yes | yes | yes | yes | yes (`ctypes`) |
| **systemd-creds `--user`** | yes, systemd ≥ 256 | yes | yes | yes | yes | yes | yes (`socket`+`json`) |
| **Secret Service** | desktop only | no, `Prompt` | no, UTF-8 in practice | yes | no | yes, often in cleartext | no, ~500 lines of D-Bus |
| **Kernel keyring** | yes | yes | yes | by possession, not uid | yes | **no** | yes (`ctypes`+`syscall`) |
| **TPM2 direct** | no, and needs group `tss` | yes | yes | **no**, machine-bound | yes | yes | via subprocess |
| **macOS Keychain** (`security`) | yes | in a GUI session | hex/base64 only | yes | **no** | yes | yes (subprocess) |
| **SSH key, no passphrase** | yes | yes | yes | file permissions only | yes | yes | yes (`age` subprocess) |
| **SSH key, passphrase** | yes | **no**, tty every call | yes | yes, by passphrase | **no** | yes | yes (`age` subprocess) |
| **`age -p` on the identity** | yes | **no**, tty every call | yes | yes, by passphrase | **no** | yes | yes (`age` subprocess) |

## What to do

### Linux: `systemd-creds --user`, feature-detected

It is the only candidate that matches the DPAPI contract on every axis, and it
matches it for the same reasons DPAPI does: the OS owns a secret you cannot
read, a privileged component does the key handling on your behalf, and the
result is bound to your account on this machine. It needs no package, no
daemon of yours, no session, no display and no terminal; it takes arbitrary
bytes and returns base64 that drops into the existing `data` field unchanged.
It costs about twenty lines of `socket` and `json`, or one subprocess if you
prefer symmetry with `age`.

`keystore_name()` returns `"systemd-creds-user"`; `wrap_identity` writes it as
the `protection` value; `identity_text` dispatches on it exactly as it already
dispatches on `dpapi-currentuser`. The format was designed to be
self-describing and this is the case it was designed for. Nothing else in the
data model moves.

Four things to get right:

- **Feature-detect, never version-sniff.** A throwaway round trip —
  encrypt a probe, decrypt it, compare — is the only honest availability test,
  because the answer depends on the systemd version, on the socket being
  reachable, and on `/var/lib/systemd` being persistent. Parsing
  `/etc/os-release` gets Ubuntu 24.04 and Debian 12 wrong, and they are two of
  the most widely deployed bases there are. This is the same shape as
  `keystore_available()`'s existing `dpapi_protect(b"probe")` call, so the seam
  already has the right idea in it.
- **Always pass user scope.** System scope is polkit-gated and will produce
  `io.systemd.InteractiveAuthenticationRequired` — an interactive prompt, in
  the one place that must never have one.
- **Use a fixed, purpose-specific `name`.** It is authenticated, and the man
  page says the check exists "to ensure that encrypted credentials are not
  re-purposed without this being detected". `cred-identity` is the obvious
  choice.
- **If you subprocess rather than use the socket, pass `--newline=no` on
  decrypt.** The default is `auto`, which appends a newline when stdout is a
  terminal. That is silent corruption of key bytes in exactly the case a human
  is most likely to be debugging.

The version gate is real and should be stated in `cred doctor` rather than
hidden: on a machine below systemd 256 the answer is still "no OS keystore",
and that is a true statement about that machine rather than about Linux.

### macOS: nothing, and say so

The Keychain is a real keystore and `security` is genuinely zero-install, but
the shape is wrong in two places that matter more than the strengths. It fails
over SSH — Apple documents that an SSH session does not unlock the login
keychain — and the only documented way to guarantee no prompt is `-A`, "Allow
any application to access this item without warning (insecure, not
recommended!)". Behind that sits the file-based keychain, whose trusted-app ACL
API has been deprecated since 10.10 and whose partition list is undocumented,
because the modern data protection keychain needs entitlements from a
provisioning profile that a shell script cannot have.

A `security`-backed keystore would therefore work on a Mac at a desk and break
on a Mac in CI, with an opaque `errSecInternalComponent`. That is a worse
outcome than not having one, because it fails in the case people trust it in.
If it is ever added it should be `-A`-based, `/usr/bin/security -i` with the
subcommand on stdin, base64 or `-X` for the payload, and honest documentation
that it is a convenience and not a second factor.

### The general answer

There is no clean DPAPI equivalent on Linux in the sense the question meant —
something that has always been there, on every distribution, for a decade. What
there is instead is a mechanism that arrived in June 2024, is already in Debian
13, Ubuntu 25.10, RHEL 10 and Arch, and is genuinely as good as DPAPI on every
axis. So the honest answer is "not yet, but soon, and here is the probe that
tells you", rather than "no".

The reason the gap existed at all is worth recording, because it explains why
the obvious candidates all fail the same way. Linux's secret-handling
mechanisms were built for two jobs — unlock a session, or hold a key for the
kernel — and both of those *consume* a secret at login. DPAPI's job is
different: it is a sealed box tied to an account, with no session in it. That
is why Secret Service needs a login, why the keyring dies with the session,
why pam_mount advertises storing nothing, and why `ecryptfs-add-passphrase`
runs the wrong way round. systemd-creds is the first thing on Linux built for
the sealed-box job, and it only became a *user* sealed box in v256.

### What not to do

**Do not add SSH-key wrapping as the Linux answer.** With no passphrase it
protects nothing that a mode 600 file did not — an unencrypted OpenSSH key is
stored with "the cipher `none` and the KDF `none`", so an attacker with the
disk has both files. With a passphrase it is not the DPAPI contract at all,
because age cannot use ssh-agent and reads passphrases from `/dev/tty` only,
so every `cred get` prompts and every scripted use fails. And it puts the
recurring passphrase burden on the user's SSH key rather than on a
narrowly-scoped, easily-rotated age identity, which is the wrong credential to
be typing more often.

It is still worth having in one place: `cred key protect --backup` could take
an SSH public key instead of a path, so the escrow copy is encrypted to a
colleague rather than written out in plaintext. That is a strict improvement on
the current advice and it does not pretend to be a keystore.

**Do not make SSH public keys the store's recipients.** `recipients` is a
committed, plaintext, long-lived field. SSH keys are rotated on someone else's
schedule, for reasons unrelated to this store, and age's own README warns that
"people might not protect SSH keys long-term, since they are revokable when
used only for authentication". Collapsing the decryption key into the
authentication key is the thing age's recipient model exists to avoid.

## The fallback message

The current text, printed from `python/cred.py:684` and again from
`python/cred_store.py:521`, with near-copies in
`src/Cred/Public/Keystore.ps1:43` and `src/Cred/Private/Platform.ps1:120`:

```
cred: No OS keystore is available on this platform.
cred:
cred: Next:
cred:   On Windows this uses DPAPI and needs nothing installed.
cred:   Elsewhere, protect the key file itself: age -p identity.txt
```

It is well-aimed, wrong in three places, and out of date in a fourth.

Well-aimed, because passphrase-protecting the *identity* rather than the store
really is the right shape, it really does put the prompt in one place, and age
really does accept the result as an identity file. That was verified end to
end.

Wrong, because the command as written fails outright — `age -p identity.txt`
writes binary to stdout and age refuses; because it does not say where the
result has to go, which is the one step that connects it to `cred`; and because
it does not mention that taking the advice gives up non-interactive operation
altogether. That last omission is the serious one: non-interactive operation is
precisely what the reader came to this message wanting, since it is what DPAPI
would have given them.

Out of date, because "on this platform" is no longer true on Linux. There is an
OS keystore there now, and that phrasing tells the reader their platform will
never have one.

Something closer to:

```
cred: No OS keystore is available here.
cred:
cred: Next:
cred:   Windows uses DPAPI, and needs nothing installed.
cred:   Linux uses systemd-creds, and needs systemd 256 or newer.
cred:     This machine has systemd 252.
cred:   Otherwise, put a passphrase on the key file itself:
cred:     age -p -a -o identity.age identity.txt
cred:     mv identity.age <CRED_HOME>/identity.txt
cred:   age will then ask for that passphrase on every cred command,
cred:   and cred will not work without a terminal.
```

Four copies of this text is three too many, and they have already drifted —
PowerShell says "protect the key file itself with a passphrase" and offers
"Leave the key as a permission-restricted file" as an option that Python does
not mention. One string, named once per implementation, would keep them
honest.

Two related notes, both small and both real:

- **`cred doctor` should report the keystore it *could* use, not just the one
  it has.** `keystore_available()` currently answers a yes/no question whose
  "no" carries no information. A probe that says "systemd-creds, needs systemd
  ≥ 256, this machine has 252" is the difference between a dead end and a
  next step.
- **The no-tty failure is misdiagnosed today.** With a passphrase-protected
  identity and no terminal, `cred get` reports that the store may be damaged
  and suggests `git checkout HEAD -- .creds/`, which is both wrong and
  destructive-sounding. age's own error says "failed to decrypt **identity**
  file", so the two cases are distinguishable in `age_decrypt`'s error mapping.
  Worth fixing whether or not any of the above happens.

## Appendix: what was checked on real hardware

Arch Linux, systemd 261.2, age 1.3.1, gnome-keyring 50.0, libsecret 0.21.7, on
a Wayland session with a TPM2 present, as uid 1000 with no `sudo` and no
membership of `tss`. Findings labelled
"observed" above come from here. In summary: `systemd-creds --user` round-trips
arbitrary bytes non-interactively under `env -i`; a twenty-line stdlib Varlink
client does the same; `age` ignores `ssh-agent` and `SSH_ASKPASS` and reads
passphrases from `/dev/tty` only; `age -p identity.txt` fails as printed;
`cred` works with a passphrase-protected identity when a tty exists and
misreports the failure when one does not; `secret-tool` accepts non-UTF-8 only
when the bytes happen to start with a valid UTF-8 run; and gnome-keyring stored
a canary in cleartext in `~/.local/share/keyrings/Default_keyring.keyring`.

None of that is a guarantee about anyone else's machine. It is one data point
each, and where it disagrees with a specification the specification wins —
except where the specification is silent, which on Linux is most of the time.
