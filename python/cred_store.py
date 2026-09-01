"""
cred_store.py -- the store, as a Python library.

This is a peer implementation, not a wrapper. It reads and writes exactly the
same files as the PowerShell module because the formats are the contract:

    .creds/config.json   plain JSON, committed
    .creds/store.age     an age file whose plaintext is
                         {"version":1,"values":{"<key>":{"user":..,"secret":..}}}

Same invariants as the PowerShell side, for the same reasons:
  - plaintext never reaches disk; age is driven over pipes
  - secrets are never command-line arguments
  - writes take an exclusive lock, stage, verify by decrypting, then replace

Requires: Python 3.8+ and the `age` binary. Nothing from PyPI.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CONFIG_VERSION = 1
STORE_VERSION = 1
CREDS_DIR = ".creds"
CONFIG_NAME = "config.json"
LOCK_NAME = ".lock"
WRAPPED_IDENTITY_NAME = "identity.wrapped.json"
IDENTITY_FORMAT = "cred-identity"

EXIT_OK = 0
EXIT_GENERAL = 1
EXIT_USAGE = 2
EXIT_NOT_FOUND = 3
EXIT_KEY = 4
EXIT_BACKEND = 5
EXIT_CORRUPT = 6
EXIT_LOCKED = 7
EXIT_COMMAND = 8


class CredError(Exception):
    """A failure that knows what the user should do about it.

    Never carries a secret value. It may name a project or a key -- both are
    already plaintext in the repo -- but never anything from the store.
    """

    def __init__(self, message: str, next_steps: Optional[List[str]] = None,
                 code: int = EXIT_GENERAL):
        super().__init__(message)
        self.message = message
        self.next_steps = [s for s in (next_steps or []) if s]
        self.code = code

    def render(self) -> str:
        out = [self.message]
        if self.next_steps:
            out.append("")
            out.append("Next:")
            out.extend("  " + s for s in self.next_steps)
        return "\n".join(out)


# --------------------------------------------------------------- platform ---

def is_windows() -> bool:
    return os.name == "nt"


def cred_home() -> Path:
    """Per-user config root. Must agree with the PowerShell module exactly."""
    override = os.environ.get("CRED_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if is_windows():
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "cred"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "cred"


def restrict_path(path: Path) -> None:
    """Best effort: make a file or directory readable only by this user."""
    try:
        if is_windows():
            # icacls is the only thing that works without pywin32. Failure here
            # must never block credential work, so it stays advisory.
            user = os.environ.get("USERNAME") or ""
            if user:
                subprocess.run(
                    ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(F)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
    except Exception:
        pass


def find_executable(name: str, override_env: Optional[str] = None) -> Optional[str]:
    if override_env:
        p = os.environ.get(override_env)
        if p and Path(p).is_file():
            return p
    from shutil import which
    found = which(name)
    if found:
        return found
    if is_windows():
        local = os.environ.get("LOCALAPPDATA")
        if local:
            shim = Path(local) / "Microsoft" / "WinGet" / "Links" / f"{name}.exe"
            if shim.is_file():
                return str(shim)
    return None


def require_age() -> str:
    age = find_executable("age", "CRED_AGE_PATH")
    if not age:
        raise CredError(
            "The 'age' encryption backend was not found.",
            ["Install age:  winget install FiloSottile.age   "
             "(or: brew install age / apt install age)",
             "Then re-run: cred doctor"],
            EXIT_BACKEND)
    return age


# ------------------------------------------------------------------- json ---

def read_text(path: Path) -> str:
    # utf-8-sig so a file written by a BOM-happy Windows tool still parses.
    return path.read_text(encoding="utf-8-sig")


def write_bytes_atomic(path: Path, data: bytes) -> None:
    tmp = stage_bytes(path, data)
    commit_staged(tmp, path)


def stage_bytes(path: Path, data: bytes) -> Path:
    """Write to a temp file beside `path` and return it, uncommitted."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".tmp")
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def commit_staged(tmp: Path, dest: Path) -> None:
    """Atomic replace. os.replace is atomic on both POSIX and Windows."""
    os.replace(str(tmp), str(dest))


def write_text_atomic(path: Path, text: str) -> None:
    """Not for secrets: the staged file is world-readable until it is committed.

    Anything that is itself a secret goes through write_private_text.
    """
    write_bytes_atomic(path, text.encode("utf-8"))


def dump_json(obj: Any) -> str:
    # ensure_ascii=False keeps the file readable; the PowerShell side reads
    # UTF-8 either way. indent=2 to match what ConvertTo-Json produces.
    return json.dumps(obj, indent=2, ensure_ascii=False)


# --------------------------------------------------------------- identity ---

def identity_path(config: Optional[Dict[str, Any]] = None) -> Path:
    override = os.environ.get("CRED_IDENTITY_FILE")
    if override:
        return Path(override)
    if config and config.get("identityFile"):
        p = Path(str(config["identityFile"]))
        return p if p.is_absolute() else cred_home() / p
    wrapped = cred_home() / WRAPPED_IDENTITY_NAME
    if wrapped.is_file():
        return wrapped
    return cred_home() / "identity.txt"


def identity_protection(path: Path) -> str:
    """The mechanism a wrapped key names, or 'file-permissions' if it is plain.

    Read from the file rather than derived from the platform: a key wrapped on
    another machine is precisely the case worth being able to see.
    """
    if not identity_is_wrapped(path):
        return "file-permissions"
    try:
        return str(json.loads(read_text(path)).get("protection") or "unknown")
    except Exception:
        return "unknown"


def identity_is_wrapped(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        head = read_text(path).lstrip()
        if not head.startswith("{"):
            return False
        return json.loads(head).get("format") == IDENTITY_FORMAT
    except Exception:
        return False


def _dpapi_unprotect(blob: bytes) -> bytes:
    """Unwrap a DPAPI CurrentUser blob via ctypes.

    Lets a Python `cred` open a key that `cred key protect` wrapped, so the two
    implementations stay interchangeable on Windows.
    """
    if not is_windows():
        raise CredError(
            "This key is wrapped with Windows DPAPI and cannot be opened here.",
            ["Unwrap it on the Windows account that wrapped it: cred key unprotect",
             "Then copy the resulting identity.txt to this machine."],
            EXIT_KEY)

    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    buf = ctypes.create_string_buffer(blob, len(blob))
    src = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise CredError(
            "Windows refused to unwrap your key.",
            ["A DPAPI-wrapped key only opens for the account that wrapped it, "
             "on that machine.",
             "If you have moved machine or account, restore your backup and re-wrap:",
             "  cred keygen --protect"],
            EXIT_KEY)
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def identity_text(path: Path) -> str:
    """The age key as text. Exists only in memory; never written anywhere."""
    if not path.is_file():
        raise CredError(
            f"No age identity at '{path}', so the store cannot be opened.",
            ["If this is a new machine, restore your key file to that path.",
             "If this is a new setup, run: cred keygen",
             "To use a key from elsewhere: CRED_IDENTITY_FILE=<path>"],
            EXIT_KEY)

    if not identity_is_wrapped(path):
        return read_text(path)

    meta = json.loads(read_text(path))
    return keystore_unprotect(base64.b64decode(meta["data"]),
                              str(meta.get("protection") or "")).decode("utf-8")


# ------------------------------------------------------------------- crypto ---

def _run(argv: List[str], stdin_bytes: Optional[bytes] = None,
         timeout: int = 120) -> Tuple[int, bytes, str]:
    """Run a binary with bytes on stdin and bytes on stdout.

    The single choke point through which plaintext leaves or enters this
    module -- mirroring Invoke-CredProcess on the PowerShell side.
    """
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(input=stdin_bytes or b"", timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise CredError(f"'{argv[0]}' did not finish within {timeout} seconds.",
                        ["Run 'cred doctor' to check the encryption backend."])
    # age appends a "report unexpected errors at ..." line to every failure;
    # it is noise inside a message that already ends with concrete next steps.
    text = " ".join(
        line for line in err.decode("utf-8", "replace").splitlines()
        if "report unexpected or unhelpful errors" not in line).strip()
    return proc.returncode, out, text


def age_encrypt(plain: bytes, recipients: List[str],
                config: Optional[Dict[str, Any]] = None) -> bytes:
    """Encrypt to `recipients`. Takes the seam's signature directly.

    There used to be a one-line _age_encrypt_adapter here purely because this
    function's shape did not match the contract's, which is the tell: the
    mismatch belonged at the seam, not beside it.
    """
    if not recipients:
        raise CredError(
            "This project has no recipients, so nothing could decrypt the store.",
            ["Add your key with: cred recipients add $(cred keygen --show)"])
    age = require_age()
    argv = [age, "--encrypt", "--armor"]
    for r in recipients:
        argv += ["-r", str(r)]          # public keys, safe on a command line
    rc, out, err = _run(argv, plain)
    if rc != 0:
        raise CredError(
            f"age could not encrypt the store: {err}",
            ["Check every recipient in .creds/config.json is a valid age public key.",
             "List them with: cred recipients"])
    return out


def age_decrypt(cipher: bytes, cipher_path: Optional[Path],
                config: Optional[Dict[str, Any]] = None) -> bytes:
    """Decrypt, choosing how to hand age the key.

    A plaintext key goes by path with the ciphertext on stdin. A wrapped key is
    unwrapped in memory and piped to stdin instead, which forces the ciphertext
    to be a file argument -- fine, since ciphertext on disk is what the store
    already is. Either way the unwrapped key never becomes a file.
    """
    age = require_age()
    ident = identity_path(config)

    if not identity_is_wrapped(ident):
        if not ident.is_file():
            raise CredError(
                f"No age identity at '{ident}', so the store cannot be opened.",
                ["If this is a new machine, restore your key file to that path.",
                 "If this is a new setup, run: cred keygen",
                 "To use a key from elsewhere: CRED_IDENTITY_FILE=<path>"],
                EXIT_KEY)
        rc, out, err = _run([age, "--decrypt", "-i", str(ident)], cipher)
    else:
        text = identity_text(ident)
        staged: Optional[Path] = None
        try:
            path = cipher_path
            if path is None or not Path(path).is_file():
                fd, name = tempfile.mkstemp(suffix=".age")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(cipher)          # ciphertext only
                staged = Path(name)
                path = staged
            rc, out, err = _run([age, "--decrypt", "-i", "-", str(path)],
                                text.encode("utf-8"))
        finally:
            if staged:
                staged.unlink(missing_ok=True)

    if rc != 0:
        # age distinguishes "could not open your key" from "could not open the
        # store", and so must we: telling someone whose key needs a passphrase
        # to git checkout their store is both wrong and alarming.
        if "identity file" in err or "passphrase" in err or "/dev/tty" in err:
            raise CredError(
                f"age could not open your key at '{ident}': {err}",
                ["A passphrase-protected key can only be opened from a terminal.",
                 "cred cannot supply it, and age will not read it from a pipe.",
                 "For unattended use, wrap the key with the OS keystore instead:",
                 "  cred key protect"],
                EXIT_KEY)
        if "no identity matched" in err or "no identities" in err:
            steps = ["Your key is not a recipient of this store.",
                     "Ask someone who can already read it to run: "
                     "cred recipients add <your-public-key>",
                     "Print your public key with: cred keygen --show"]
        else:
            steps = ["The store may be damaged. Restore it from git:",
                     "  git checkout HEAD -- .creds/"]
        raise CredError(f"age could not decrypt the store: {err}", steps, EXIT_KEY)
    return out


def age_recipient(config: Optional[Dict[str, Any]] = None) -> str:
    keygen = find_executable("age-keygen", "CRED_AGE_KEYGEN_PATH")
    if not keygen:
        raise CredError("'age-keygen' was not found.",
                        ["Install age: winget install FiloSottile.age"], EXIT_BACKEND)
    ident = identity_path(config)
    if identity_is_wrapped(ident):
        # age-keygen -y reads the identity from stdin when given no INPUT.
        rc, out, err = _run([keygen, "-y"], identity_text(ident).encode("utf-8"))
    else:
        if not ident.is_file():
            raise CredError(f"No age identity found at '{ident}'.",
                            ["Create one with: cred keygen"], EXIT_KEY)
        rc, out, err = _run([keygen, "-y", str(ident)])
    if rc != 0:
        raise CredError(f"Could not read the age identity at '{ident}': {err}",
                        ["Check the file starts with 'AGE-SECRET-KEY-'.",
                         "Regenerate with: cred keygen --force"], EXIT_KEY)
    return out.decode("utf-8").strip().splitlines()[0]


def age_new_identity(path: Path) -> Tuple[Path, str]:
    keygen = find_executable("age-keygen", "CRED_AGE_KEYGEN_PATH")
    if not keygen:
        raise CredError("'age-keygen' was not found.",
                        ["Install age: winget install FiloSottile.age"], EXIT_BACKEND)
    rc, out, err = _run([keygen])
    if rc != 0:
        raise CredError(f"age-keygen failed: {err}", ["Run 'cred doctor'."])
    text = out.decode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    restrict_path(path.parent)
    write_private_text(path, text)
    pub = next((l.strip() for l in text.splitlines() if l.startswith("age1")), "")
    if not pub:
        for line in text.splitlines():
            if "public key:" in line:
                pub = line.split("public key:")[1].strip()
                break
    return path, pub


# --------------------------------------------------------------- providers ---
# The same seam as src/Cred/Private/Providers.ps1, in the same shape. Nothing
# above this layer knows what encryption is, so adding a backend is one entry.
#
#   test         () -> (available: bool, detail: str)
#   new_identity (path) -> (path, recipient)
#   recipient    (config) -> str
#   encrypt      (plain: bytes, recipients: list, config) -> bytes
#   decrypt      (cipher: bytes, cipher_path, config) -> bytes
#
# A provider must not write plaintext to disk and must not put secret material
# on a command line.

def _age_test():
    if not find_executable("age", "CRED_AGE_PATH"):
        return False, "'age' was not found on PATH."
    if not find_executable("age-keygen", "CRED_AGE_KEYGEN_PATH"):
        return False, "'age' found but 'age-keygen' was not."
    return True, "age and age-keygen found."


PROVIDERS: Dict[str, Dict[str, Any]] = {
    "age": {
        "name": "age",
        "summary": "age (X25519, authenticated ChaCha20-Poly1305)",
        "store_file": "store.age",
        "install_hint": "Install age:  winget install FiloSottile.age   "
                        "(or: brew install age / apt install age)",
        "test": _age_test,
        "new_identity": age_new_identity,
        "recipient": age_recipient,
        # cred owns this key file, so it is cred's to locate and to wrap.
        "identity_path": identity_path,
        "supports_keystore": True,
        "encrypt": age_encrypt,
        "decrypt": age_decrypt,
    },
}


def provider_for(config: Optional[Dict[str, Any]] = None,
                 name: Optional[str] = None) -> Dict[str, Any]:
    """The provider a project uses, defaulting to age outside a project."""
    return get_provider(name or (config or {}).get("provider") or "age")


def provider_identity_path(config: Optional[Dict[str, Any]] = None,
                           name: Optional[str] = None) -> Path:
    """Where this project's key lives, according to its provider.

    The peer of Get-CredIdentityPath. Commands used to call identity_path()
    directly, which is age's answer regardless of what the project actually
    uses.
    """
    prov = provider_for(config, name)
    path = prov["identity_path"](config)
    if path is None:
        raise CredError(
            f"The '{prov['name']}' provider does not keep its key in a file "
            "cred manages.",
            ["Its keys live somewhere cred does not own; manage them where "
             "they live.",
             "Only providers with a cred-managed key file support 'cred key'."],
            EXIT_KEY)
    return path


def assert_keystore_supported(config: Optional[Dict[str, Any]] = None,
                              name: Optional[str] = None) -> Dict[str, Any]:
    """Refuse a keystore operation the provider cannot honour."""
    prov = provider_for(config, name)
    if not prov.get("supports_keystore"):
        raise CredError(
            f"The '{prov['name']}' provider has no key for cred to wrap.",
            ["It holds your private key somewhere with its own protection.",
             "'cred key protect' applies to providers whose key is a file "
             "cred manages, such as age."],
            EXIT_USAGE)
    return prov


def get_provider(name: str) -> Dict[str, Any]:
    prov = PROVIDERS.get(name)
    if prov is None:
        known = ", ".join(sorted(PROVIDERS))
        raise CredError(f"Unknown encryption provider '{name}'.",
                        [f"Known providers: {known}",
                         "Fix the 'provider' field in .creds/config.json."],
                        EXIT_BACKEND)
    return prov


# --------------------------------------------------------------- keystore ---
# One wrapped-identity format, more than one mechanism that can wrap it. The
# `protection` field in identity.wrapped.json names the mechanism, so a key
# says what can open it instead of the reader inferring it from the platform.
# `data` is always base64 of the opaque blob that mechanism returned, whatever
# shape the mechanism hands it back in.
#
# What counts as a keystore here: it takes arbitrary bytes, it binds the result
# to this account on this machine, and it never prompts. The last one is the
# point. A keystore that asks a question cannot be used from a script, and a
# script is where credentials are actually needed.

KEYSTORE_DPAPI = "dpapi-currentuser"
KEYSTORE_SYSTEMD = "systemd-creds-user"


def dpapi_protect(data: bytes) -> bytes:
    """Wrap bytes with DPAPI, bound to the current Windows account."""
    if not is_windows():
        raise CredError(
            "DPAPI is a Windows facility and is not available here.",
            ["This machine's keystore, if it has one, is: " + keystore_name()],
            EXIT_BACKEND)

    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    buf = ctypes.create_string_buffer(data, len(data))
    src = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()

    ok = crypt32.CryptProtectData(ctypes.byref(src), None, None, None, None,
                                  0, ctypes.byref(out))
    if not ok:
        raise CredError("Windows refused to wrap the key.",
                        ["Run 'cred doctor' and try again."], EXIT_KEY)
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


# ------------------------------------------------------- systemd-creds -----
# The Linux answer, and the only mechanism off Windows that meets the bar
# above. `systemd-creds` encrypts a named blob with a key held in
# /var/lib/systemd/credential.secret and/or the TPM; since systemd 256 it can
# additionally bind that key to one user. It is not a permission check: the
# uid, the username and the machine-id are folded into the encryption key, and
# the uid comes from SO_PEERCRED on the socket rather than from anything the
# caller says. A blob belonging to another account is not refused, it is
# undecryptable.
#
# We speak Varlink to it directly rather than shelling out. Varlink is
# NUL-terminated JSON over an AF_UNIX socket, which is a dozen lines of stdlib
# and keeps the blob off a command line -- the same rule age is held to here.

SYSTEMD_CREDENTIALS_SOCKET = "/run/systemd/io.systemd.Credentials"

# Authenticated by systemd, and checked on the way back out: it exists so that
# a credential cannot be quietly re-purposed as a different one.
SYSTEMD_CREDENTIAL_NAME = "cred-identity"

# The service reports failures as dotted identifiers rather than prose, so the
# cases we can say something useful about are matched exactly, not by substring.
_SYSTEMD_ERRORS = {
    "io.systemd.Credentials.NameMismatch":
        "This blob was not written by cred, or was written under another name.",
    "io.systemd.Credentials.BadScope":
        "This blob is bound to a different user, or to the system rather than "
        "to an account.",
    "io.systemd.Credentials.BadFormat":
        "This blob is not a systemd credential, or it is damaged.",
    # systemd cannot tell these two apart, and neither can we: a damaged blob
    # and a foreign TPM both surface as one failed integrity check.
    "io.systemd.Credentials.KeyBelongsToOtherTPM":
        "The integrity check failed: either this key was sealed by another "
        "machine's TPM, or the blob is damaged.",
    "io.systemd.Credentials.TPMInDictionaryLockout":
        "The TPM is in lockout and will not answer.",
    "io.systemd.InteractiveAuthenticationRequired":
        "The system refused to act without an interactive prompt.",
}

_systemd_probe: Optional[bool] = None


def _varlink_call(method: str, params: Dict[str, Any],
                  timeout: float = 15.0) -> Dict[str, Any]:
    """One Varlink round trip: NUL-terminated JSON in, NUL-terminated JSON out."""
    import socket

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect(SYSTEMD_CREDENTIALS_SOCKET)
        except OSError as exc:
            raise CredError(
                f"Could not reach systemd's credential service: {exc}",
                ["This needs systemd 256 or newer, running as PID 1.",
                 "Check it is there: systemd-creds --version"],
                EXIT_BACKEND) from exc

        request = json.dumps({"method": method, "parameters": params})
        sock.sendall(request.encode("utf-8") + b"\0")

        chunks: List[bytes] = []
        while not (chunks and chunks[-1].endswith(b"\0")):
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()

    raw = b"".join(chunks).rstrip(b"\0")
    if not raw:
        raise CredError("systemd's credential service closed the connection "
                        "without answering.",
                        ["Check the service: systemctl status systemd-creds.socket"],
                        EXIT_BACKEND)
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise CredError("systemd's credential service sent a reply that is "
                        "not valid JSON.", [], EXIT_BACKEND) from exc


def _systemd_creds_call(method: str, params: Dict[str, Any]) -> Dict[str, Any]:
    reply = _varlink_call("io.systemd.Credentials." + method, params)
    error = reply.get("error")
    if error:
        detail = _SYSTEMD_ERRORS.get(str(error), f"systemd reported {error}.")
        raise CredError(
            f"systemd-creds could not {method.lower()} the key. {detail}",
            ["A wrapped key only opens for the account and the machine that "
             "wrapped it.",
             "If you have moved either, restore your backup and re-wrap:",
             "  cred keygen --protect"],
            EXIT_KEY)
    return reply.get("parameters") or {}


def systemd_creds_protect(data: bytes) -> bytes:
    """Wrap bytes for this uid on this machine. Returns the raw blob.

    `withKey` is deliberately left unset, so systemd picks the same default its
    own CLI does: host key and TPM where there is one, host key alone where
    there is not. It does not bind to PCRs, so a kernel update does not cost
    you the key.
    """
    params = {"name": SYSTEMD_CREDENTIAL_NAME,
              "scope": "user",
              "data": base64.b64encode(data).decode("ascii")}
    blob = _systemd_creds_call("Encrypt", params)["blob"]
    return base64.b64decode(blob)


def systemd_creds_unprotect(blob: bytes) -> bytes:
    params = {"name": SYSTEMD_CREDENTIAL_NAME,
              "scope": "user",
              "blob": base64.b64encode(blob).decode("ascii")}
    data = _systemd_creds_call("Decrypt", params)["data"]
    return base64.b64decode(data)


def systemd_creds_available() -> bool:
    """Can this machine wrap a key with systemd-creds, for this user?

    Answered by doing it: encrypt a probe and open it again. Nothing else is
    honest, because the answer turns on the systemd version, on the socket
    being reachable, and on /var/lib/systemd being writable and persistent --
    and version-sniffing /etc/os-release gets Ubuntu 24.04 and Debian 12 wrong,
    which are two of the most widely deployed bases there are.
    """
    global _systemd_probe
    if _systemd_probe is not None:
        return _systemd_probe
    _systemd_probe = False
    if is_windows():
        return False
    try:
        import stat
        mode = os.stat(SYSTEMD_CREDENTIALS_SOCKET).st_mode
        if not stat.S_ISSOCK(mode):
            return False
        probe = b"cred keystore probe"
        _systemd_probe = systemd_creds_unprotect(systemd_creds_protect(probe)) == probe
    except Exception:
        _systemd_probe = False
    return _systemd_probe


def systemd_version() -> Optional[int]:
    """The running systemd's major version, for a message that has to explain
    why the keystore is missing. None if systemd is not here at all."""
    if is_windows():
        return None
    try:
        rc, out, _ = _run(["systemctl", "--version"], timeout=10)
    except Exception:
        return None
    if rc != 0:
        return None
    # "systemd 261 (261.2-1-arch)"
    for word in out.decode("utf-8", "replace").split():
        if word.isdigit():
            return int(word)
    return None


# ------------------------------------------------------- keystore, chosen ---

def keystore_name() -> str:
    """The mechanism this machine would wrap a key with, or 'none'."""
    if is_windows():
        return KEYSTORE_DPAPI
    if systemd_creds_available():
        return KEYSTORE_SYSTEMD
    return "none"


def keystore_available() -> bool:
    if is_windows():
        try:
            return dpapi_protect(b"probe") is not None
        except Exception:
            return False
    return systemd_creds_available()


def keystore_unavailable() -> CredError:
    """Why there is no keystore here, and what to do instead.

    One function rather than a copy of this text at every call site. There were
    four copies before, and they had already drifted apart.
    """
    steps = ["Windows uses DPAPI, and needs nothing installed."]
    if is_windows():
        steps.append("DPAPI is here but refused to answer. Run: cred doctor")
    else:
        version = systemd_version()
        line = "Linux uses systemd-creds, and needs systemd 256 or newer."
        if version is None:
            line += " This machine is not running systemd."
        elif version < 256:
            line += f" This machine has systemd {version}."
        else:
            # New enough, so the version is not the problem. Say what is,
            # rather than repeating a requirement this machine already meets.
            line += (f" This machine has systemd {version}, but "
                     f"{SYSTEMD_CREDENTIALS_SOCKET} did not answer.")
        steps.append(line)
    steps += [
        "Otherwise, put a passphrase on the key file itself:",
        "  age -p -a -o identity.age identity.txt",
        f"  mv identity.age '{cred_home() / 'identity.txt'}'",
        "age will then ask for that passphrase on every cred command, and "
        "cred will not work without a terminal.",
    ]
    return CredError("No OS keystore is available here.", steps, EXIT_BACKEND)


def keystore_protect(data: bytes) -> bytes:
    """Wrap bytes with whatever keystore this machine has."""
    name = keystore_name()
    if name == KEYSTORE_DPAPI:
        return dpapi_protect(data)
    if name == KEYSTORE_SYSTEMD:
        return systemd_creds_protect(data)
    raise keystore_unavailable()


def keystore_unprotect(blob: bytes, protection: str) -> bytes:
    """Unwrap a blob that says which mechanism sealed it.

    A key wrapped elsewhere is a clear refusal rather than a decryption
    failure, because the two have completely different remedies.
    """
    if protection == KEYSTORE_DPAPI:
        return _dpapi_unprotect(blob)
    if protection == KEYSTORE_SYSTEMD:
        if not systemd_creds_available():
            raise CredError(
                "This key is wrapped with systemd-creds and cannot be opened here.",
                ["It opens on the Linux account and machine that wrapped it.",
                 "Unwrap it there with 'cred key unprotect', then copy the "
                 "resulting identity.txt to this machine."],
                EXIT_KEY)
        return systemd_creds_unprotect(blob)
    raise CredError(
        f"This key is wrapped with '{protection or 'an unnamed mechanism'}', "
        "which this machine cannot open.",
        ["Open it where it was wrapped, then: cred key unprotect"],
        EXIT_KEY)


def wrap_identity(text: str) -> str:
    """The wrapped-identity file, byte-identical in shape to the PowerShell one."""
    return dump_json({
        "format": IDENTITY_FORMAT,
        "version": 1,
        "protection": keystore_name(),
        "note": "Wrapped by the OS keystore. Only the account that wrapped it "
                "can open it. Keep a separate backup of the unwrapped key.",
        "data": base64.b64encode(keystore_protect(text.encode("utf-8"))).decode("ascii"),
    })


# ------------------------------------------------------- PSCredential XML ---
# Export-Clixml is plain XML in which a SecureString is a DPAPI blob in hex --
# exactly what ConvertFrom-SecureString emits. That makes the PowerShell
# migration formats readable and writable from here, so the CLI does not have to
# hand part of its job to another runtime.

_CLIXML_NS = "http://schemas.microsoft.com/powershell/2004/04"


def dpapi_hex_to_text(hex_text: str) -> str:
    blob = bytes.fromhex(hex_text.strip())
    return _dpapi_unprotect(blob).decode("utf-16-le")


def text_to_dpapi_hex(text: str) -> str:
    return dpapi_protect(text.encode("utf-16-le")).hex()


def read_clixml_credential(path: Path):
    """Return (username, secret) from an Export-Clixml file, or None.

    Handles the two shapes people actually have: a PSCredential, and a bare
    SecureString (which has no username).
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.parse(str(path)).getroot()
    except ET.ParseError:
        return None

    def tag(el):
        return el.tag.split("}")[-1]

    # A bare SecureString: <Objs><SS>hex</SS></Objs>
    for child in root:
        if tag(child) == "SS" and child.text:
            return None, dpapi_hex_to_text(child.text)

    # A PSCredential: <Obj><Props><S N="UserName"/><SS N="Password"/></Props></Obj>
    for obj in root.iter():
        if tag(obj) != "Props":
            continue
        user = None
        secret = None
        for prop in obj:
            name = prop.attrib.get("N")
            if tag(prop) == "S" and name == "UserName":
                user = prop.text or ""
            elif tag(prop) == "SS" and name == "Password" and prop.text:
                secret = dpapi_hex_to_text(prop.text)
        if secret is not None:
            return user, secret
    return None


def write_clixml_credential(path: Path, user: str, secret: str) -> None:
    """Write a PSCredential that Import-Clixml reads back natively."""
    from xml.sax.saxutils import escape

    xml = (
        '<Objs Version="1.1.0.1" xmlns="{ns}">\r\n'
        '  <Obj RefId="0">\r\n'
        '    <TN RefId="0">\r\n'
        '      <T>System.Management.Automation.PSCredential</T>\r\n'
        '      <T>System.Object</T>\r\n'
        '    </TN>\r\n'
        '    <ToString>System.Management.Automation.PSCredential</ToString>\r\n'
        '    <Props>\r\n'
        '      <S N="UserName">{user}</S>\r\n'
        '      <SS N="Password">{pw}</SS>\r\n'
        '    </Props>\r\n'
        '  </Obj>\r\n'
        '</Objs>'
    ).format(ns=_CLIXML_NS, user=escape(user), pw=text_to_dpapi_hex(secret))
    write_private_text(path, xml)

# ------------------------------------------------------------------ config ---

def find_project_root(start: Optional[Path] = None) -> Optional[Path]:
    d = (start or Path.cwd()).resolve()
    if d.is_file():
        d = d.parent
    while True:
        if (d / CREDS_DIR / CONFIG_NAME).is_file():
            return d
        if d.parent == d:
            return None
        d = d.parent


def registry_path() -> Path:
    return cred_home() / "projects.json"


def read_registry() -> Dict[str, Any]:
    p = registry_path()
    if not p.is_file():
        return {"version": CONFIG_VERSION, "projects": {}}
    try:
        reg = json.loads(read_text(p))
    except Exception as exc:
        raise CredError(f"The project registry at '{p}' is not valid JSON.",
                        ["Inspect it, or delete it and re-run 'cred init' "
                         "in each project."], EXIT_CORRUPT) from exc
    reg.setdefault("projects", {})
    return reg


def write_registry(reg: Dict[str, Any]) -> None:
    p = registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    restrict_path(p.parent)
    write_text_atomic(p, dump_json(reg))


def register_project(name: str, path: Path) -> None:
    reg = read_registry()
    reg["projects"][name] = {"path": str(path.resolve())}
    write_registry(reg)


def split_reference(ref: str) -> Tuple[Optional[str], Optional[str]]:
    """'proj/key' -> ('proj','key'); 'key' -> (None,'key'). Keys cannot hold '/'."""
    if "/" in ref:
        proj, _, key = ref.partition("/")
        return (proj or None), (key or None)
    return None, (ref or None)


def valid_key_name(name: Optional[str]) -> bool:
    import re
    return bool(name) and bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name))


class Project:
    def __init__(self, root: Path):
        self.root = root
        self.creds_dir = root / CREDS_DIR
        self.config_path = self.creds_dir / CONFIG_NAME
        self.config = read_config(self.config_path)
        self.name = self.config["project"]
        self.store_path = self.creds_dir / self.config["store"]


def read_config(path: Path) -> Dict[str, Any]:
    try:
        cfg = json.loads(read_text(path))
    except FileNotFoundError:
        raise CredError(f"'{path.parent.parent}' has no .creds/config.json.",
                        [f"Create one with: cd '{path.parent.parent}'; cred init"],
                        EXIT_NOT_FOUND)
    except Exception as exc:
        raise CredError(f"'{path}' is not valid JSON.",
                        ["Fix the syntax, or restore it: "
                         "git checkout HEAD -- .creds/config.json"],
                        EXIT_CORRUPT) from exc

    if cfg.get("version", CONFIG_VERSION) > CONFIG_VERSION:
        raise CredError(
            f"'{path}' was written by a newer version of cred "
            f"(config version {cfg['version']}).",
            ["Update cred, then try again."], EXIT_CORRUPT)

    prov = get_provider(cfg.setdefault("provider", "age"))   # fail fast on a typo

    cfg.setdefault("version", CONFIG_VERSION)
    cfg.setdefault("project", path.parent.parent.name)
    # From the provider, not hardcoded: a project with no 'store' key used to
    # resolve to one filename here and another in PowerShell, so the two
    # implementations opened different files for the same repository.
    cfg.setdefault("store", prov["store_file"])
    cfg.setdefault("recipients", [])
    cfg.setdefault("credentials", {})
    return cfg


def resolve_project(name: Optional[str] = None,
                    path: Optional[str] = None) -> Project:
    """Name from the registry, an explicit path, $CRED_PROJECT, or the cwd."""
    if path:
        root = find_project_root(Path(path)) or Path(path)
        if not (root / CREDS_DIR / CONFIG_NAME).is_file():
            raise CredError(f"'{root}' has no .creds/config.json.",
                            [f"Create one with: cd '{root}'; cred init"],
                            EXIT_NOT_FOUND)
        return Project(root)

    if name:
        reg = read_registry()
        entry = reg["projects"].get(name)
        if entry:
            candidate = Path(entry["path"])
            if not candidate.is_dir():
                raise CredError(
                    f"Project '{name}' is registered at '{candidate}', "
                    "but that directory no longer exists.",
                    ["Re-register it: cd <new-location>; cred init",
                     f"Or forget it: cred project rm {name}"], EXIT_NOT_FOUND)
            return Project(find_project_root(candidate) or candidate)
        if Path(name).is_dir():
            root = find_project_root(Path(name))
            if root:
                return Project(root)
        known = sorted(reg["projects"])
        raise CredError(
            f"No project named '{name}'.",
            [f"Known projects: {', '.join(known)}" if known
             else "You have no projects yet.",
             "List them with: cred project list",
             f"Create this one: cd <repo>; cred init --project {name}"],
            EXIT_NOT_FOUND)

    if os.environ.get("CRED_PROJECT"):
        return resolve_project(name=os.environ["CRED_PROJECT"])

    root = find_project_root()
    if not root:
        raise CredError(
            "No credential store found for the current directory.",
            ["Create one here:  cred init",
             "Or name a project: cred <command> <project>/<key>",
             "Or point at one:   CRED_PROJECT=<project-name-or-path>"],
            EXIT_NOT_FOUND)
    return Project(root)


# ------------------------------------------------------------------- store ---

class StoreLock:
    """Exclusive write lock on .creds/.lock.

    Same protocol as the PowerShell side, including the important part: the
    lock file is created once and never deleted. Deleting it on release is racy
    -- a waiter can hold a handle to a file already pending deletion while a
    third process creates a fresh one under the same name, so two processes both
    believe they hold the lock and one loses its update.
    """

    def __init__(self, creds_dir: Path, timeout: float = 60.0):
        self.path = creds_dir / LOCK_NAME
        self.timeout = timeout
        self._fh = None

    def __enter__(self) -> "StoreLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        delay = 0.015
        while True:
            try:
                self._fh = open(self.path, "a+b")
                self._acquire(self._fh)
                return self
            except OSError:
                if self._fh:
                    self._fh.close()
                    self._fh = None
                if time.monotonic() >= deadline:
                    raise CredError(
                        "Another cred process is holding the write lock "
                        "for this project.",
                        ["Wait a moment and retry.",
                         f"If nothing else is running, delete the stale lock: "
                         f"rm '{self.path}'"],
                        EXIT_LOCKED)
                time.sleep(delay)
                delay = min(delay * 2, 0.25)

    @staticmethod
    def _acquire(fh) -> None:
        if is_windows():
            import msvcrt
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def __exit__(self, *exc) -> None:
        if not self._fh:
            return
        try:
            if is_windows():
                import msvcrt
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            self._fh.close()
            self._fh = None


def read_values(project: Project) -> Dict[str, Dict[str, str]]:
    """Decrypt the store. Lock-free: every write is an atomic replace."""
    if not project.store_path.is_file():
        return {}
    cipher = project.store_path.read_bytes()
    if not cipher:
        return {}
    prov  = get_provider(project.config["provider"])
    plain = prov["decrypt"](cipher, project.store_path, project.config)
    try:
        data = json.loads(plain.decode("utf-8"))
    except Exception as exc:
        raise CredError(
            "The store decrypted, but its contents are not valid JSON.",
            [f"Restore it from git: git checkout HEAD -- '{project.store_path}'",
             "Or start over: cred init --force"], EXIT_CORRUPT) from exc
    return data.get("values") or {}


def write_values(project: Project, values: Dict[str, Any]) -> None:
    """Encrypt, stage, prove it decrypts, then replace. Caller holds the lock."""
    payload = json.dumps({"version": STORE_VERSION, "values": values},
                         separators=(",", ":"), ensure_ascii=False)
    plain = payload.encode("utf-8")
    prov = get_provider(project.config["provider"])
    cipher = prov["encrypt"](plain, list(project.config.get("recipients") or []),
                             project.config)

    staged = stage_bytes(project.store_path, cipher)
    try:
        try:
            verify = prov["decrypt"](cipher, staged, project.config)
        except CredError:
            verify = b""
        if verify != plain:
            raise CredError(
                "The new store encrypted, but you could not decrypt it again, "
                "so it was not saved.",
                ["You are probably not one of this project's recipients.",
                 "Check with: cred recipients",
                 "Add yourself: cred recipients add $(cred keygen --show)"],
                EXIT_KEY)
        commit_staged(staged, project.store_path)
    finally:
        if staged.exists():
            staged.unlink(missing_ok=True)


def write_config(project: Project) -> None:
    write_text_atomic(project.config_path, dump_json(project.config))


def update_store(project: Project, mutate) -> None:
    """Read-modify-write under the project's exclusive lock."""
    with StoreLock(project.creds_dir):
        # Re-read inside the lock: another process may have added a recipient
        # or a definition since we resolved the project.
        project.config = read_config(project.config_path)
        project.store_path = project.creds_dir / project.config["store"]
        values = read_values(project)
        mutate(values, project)
        write_values(project, values)
        write_config(project)


def env_names(key: str, kind: str = "secret",
              env: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """The environment variable names a credential maps to.

    The single home of the naming convention. It used to be written out five
    times here and three times in the PowerShell peer, and the copies
    disagreed: a userpass entry whose definition carried no `env` map became
    KEY_PASSWORD here and a bare KEY there, so `cred exec` injected a
    different variable name depending on which implementation you ran.

    A file credential maps to nothing, by design.
    """
    if kind == "file":
        return {}
    import re
    slug = re.sub(r"[^A-Za-z0-9]", "_", key).upper()
    if kind == "userpass":
        names = {"user": f"{slug}_USER", "secret": f"{slug}_PASSWORD"}
    else:
        names = {"secret": slug}
    # An explicit mapping in config.json wins over the convention.
    for field, value in (env or {}).items():
        if field in ("user", "secret") and value:
            names[field] = str(value)
    return names



def entry_kind(entry: Dict[str, Any], definition: Optional[Dict[str, Any]]) -> str:
    """The type of a credential, trusting the store over the config.

    `encoding` is only ever set by the file importer, so a store that has
    outlived its config.json still reports the right kind.

    The store only wins where it has something to say. `cred list` runs
    without decrypting and therefore without an entry at all, so a declared
    credential must still report its own type rather than defaulting to
    'secret'.
    """
    if "encoding" in entry:
        return "file"
    if "user" in entry:
        return "userpass"
    declared = (definition or {}).get("type")
    if declared in ("secret", "userpass", "file"):
        return str(declared)
    return "secret"


def resolve_entry(key: str, entry: Dict[str, Any],
                  definition: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Everything a caller needs to know about one credential, decided once.

    The peer of Resolve-CredEntry in src/Cred/Private/Entry.ps1. Callers must
    not re-derive any of this; a new credential type should be one edit here
    rather than one at every command that touches a store.
    """
    kind = entry_kind(entry, definition)
    # Only the value-bearing fields. Bookkeeping like `encoding` must never
    # become a field, and must never become an environment variable.
    fields = {f: str(entry[f]) for f in ("user", "secret") if f in entry}

    is_binary = entry.get("encoding") == "base64"
    filename = ""
    if kind == "file":
        filename = str((definition or {}).get("filename") or "")

    names = env_names(key, kind, (definition or {}).get("env"))
    env_vars = {names[f]: v for f, v in fields.items() if f in names}

    # A file credential has no env mapping, so that column would be empty
    # where the interesting fact -- which file it was -- fits neatly.
    display = (f"file: {filename}" if kind == "file" and filename
               else ", ".join(names.values()))

    return {"key": key, "kind": kind, "entry": entry, "fields": fields,
            "is_binary": is_binary, "filename": filename,
            "env_names": names, "env_vars": env_vars, "display": display}


def entry_bytes(view: Dict[str, Any], field: str = "secret",
                project_name: Optional[str] = None) -> bytes:
    """The exact bytes of a credential, whatever kind it is.

    A file credential comes back as the bytes that were imported. Anything
    else is the requested field as UTF-8, with no trailing newline.
    """
    if view["kind"] == "file":
        return decode_file_content(view["entry"])
    if field not in view["fields"]:
        label = f"{project_name}/{view['key']}" if project_name else view["key"]
        raise CredError(f"'{label}' has no '{field}' field.",
                        [f"It has: {', '.join(view['fields'])}"], EXIT_NOT_FOUND)
    return str(view["fields"][field]).encode("utf-8")


# Every write re-encrypts the whole store, so a large file is not just its own
# cost -- it is paid again on every unrelated `cred add`. Certificates and keys
# are kilobytes; anything past this is a sign the store is the wrong home.
MAX_FILE_BYTES = 1024 * 1024


def encode_file_content(data: bytes) -> Tuple[str, Optional[str]]:
    """(text-for-the-store, encoding) for a file's exact bytes.

    Text stays text so the value is still greppable once decrypted and diffs
    sensibly; anything that is not clean UTF-8 goes to base64. NUL forces
    base64 too -- it decodes fine but is not text by any useful definition.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None or "\x00" in text:
        import base64
        return base64.b64encode(data).decode("ascii"), "base64"
    return text, None


def decode_file_content(entry: Dict[str, Any]) -> bytes:
    """The exact bytes that were imported. Inverse of encode_file_content."""
    value = str(entry.get("secret", ""))
    if entry.get("encoding") == "base64":
        import base64
        import binascii
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CredError(
                "This credential's stored content is not valid base64.",
                ["The store decrypted, so this is corruption inside it.",
                 "Restore it from git: git checkout HEAD -- .creds/"],
                EXIT_CORRUPT) from exc
    return value.encode("utf-8")


def write_private_file(path: Path, data: bytes) -> None:
    """Write bytes to a new file only this user can read.

    Permissions are applied to the staged file before it is put in place, so
    there is no window in which the content exists world-readable.
    """
    tmp = stage_bytes(path, data)
    try:
        restrict_path(tmp)
        commit_staged(tmp, path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    # restrict_path is best effort by design. If it quietly failed on the staged
    # file, this is the published file's second chance.
    restrict_path(path)


def write_private_text(path: Path, text: str) -> None:
    """write_private_file for text. Peer of Write-CredPrivateFileText."""
    write_private_file(path, text.encode("utf-8"))


def entry_view(name: str, project_name: Optional[str] = None,
               path: Optional[str] = None) -> Dict[str, Any]:
    """A reference such as 'acme-api/db' resolved all the way to one entry.

    Split the name, open the store, prove the credential exists, say what it
    is. Every single-credential path wants exactly this, and the order matters:
    entry_or_raise before resolve_entry, so a missing key gets the message with
    the near-miss hint. Peer of Get-CredEntryView in Private/Store.ps1.

    The decrypted values come back too, for a caller with more to ask.
    """
    proj_ref, key = split_reference(name)
    project = resolve_project(project_name or proj_ref, path)
    values = read_values(project)
    entry = entry_or_raise(project, key, values)
    defs = project.config.get("credentials") or {}
    return {"key": key, "project": project, "values": values,
            "view": resolve_entry(key, entry, defs.get(key))}


def read_value(name: str, project_name: Optional[str] = None,
               path: Optional[str] = None,
               field: str = "secret") -> Dict[str, Any]:
    """One credential's bytes, together with what it is.

    For a caller that has to decide how to write a value out: a `file`
    credential is written raw, everything else as text, and binary content must
    not go to a terminal at all. One call, one decryption, so the CLI does not
    have to resolve stores itself. Peer of Read-CredValue.
    """
    resolved = entry_view(name, project_name, path)
    view = resolved["view"]
    return {"project": resolved["project"].name,
            "key": resolved["key"],
            "kind": view["kind"],
            "is_binary": bool(view["is_binary"]),
            "bytes": entry_bytes(view, field, resolved["project"].name)}


def read_import_file(spec: str, force: bool = False) -> bytes:
    """The exact bytes of a file being imported as a credential.

    Peer of Read-CredImportFile in Private/Entry.ps1. It lives here rather than
    in the CLI because the size limit is a rule about the store, not about how
    the CLI was invoked.
    """
    path = Path(spec).expanduser()
    if not path.is_file():
        raise CredError(
            f"There is no file at '{path}'.",
            ["Check the path. --file takes the file to import, not its content."],
            EXIT_NOT_FOUND)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise CredError(f"Could not read '{path}': {exc}",
                        ["Check that you have permission to read it."],
                        EXIT_GENERAL)
    if len(data) > MAX_FILE_BYTES and not force:
        raise CredError(
            f"'{path.name}' is {len(data) // 1024} KiB; the limit is "
            f"{MAX_FILE_BYTES // 1024} KiB.",
            ["The whole store is re-encrypted on every write, so a large file "
             "is paid for again on every unrelated 'cred add'.",
             "Keys and certificates are kilobytes. If this really belongs "
             "here: cred add ... --file <path> --force"],
            EXIT_USAGE)
    return data


def export_credential_file(project, view: Dict[str, Any], spec: str,
                           force: bool = False,
                           field: str = "secret") -> Dict[str, Any]:
    """`cred get --out` -- the only path that deliberately writes plaintext.

    It exists because a private key is useless to openssl or nginx as a string
    on stdout. Everything else in cred keeps plaintext off disk; the caller
    says so out loud rather than doing it quietly, which is why this returns
    what happened instead of printing it. Peer of Export-CredFile.
    """
    key = view["key"]
    target = Path(spec).expanduser()
    if target.is_dir():
        target = target / (view["filename"] or key)
    if target.exists() and not force:
        raise CredError(
            f"'{target}' already exists.",
            ["Overwriting a key file is not something to do by accident.",
             "Pass --force if that is what you mean."],
            EXIT_USAGE)

    data = entry_bytes(view, field, project.name)
    write_private_file(target, data)
    return {"file": target, "byte_count": len(data)}


def environment_and_skipped(project: Project, only=None, exclude=None,
                            prefix: str = "") -> Tuple[Dict[str, str], List[str]]:
    """Variables to inject, and the file credentials deliberately left out.

    Both come from one decryption; callers that want to tell the user what was
    skipped should not pay for a second pass over the store.
    """
    values = read_values(project)
    defs = project.config.get("credentials") or {}
    out: Dict[str, str] = {}
    skipped: List[str] = []
    for key, entry in values.items():
        if only and key not in only:
            continue
        if exclude and key in exclude:
            continue
        view = resolve_entry(key, entry, defs.get(key))
        # File credentials are deliberately not injected: the content is a PEM
        # or a certificate, and `export KEY=-----BEGIN...` breaks the shell it
        # is pasted into. `cred get --out` is the way to get one of these.
        if view["kind"] == "file":
            skipped.append(key)
            continue
        for name, value in view["env_vars"].items():
            out[prefix + name] = str(value)
    return out, sorted(skipped)


def entry_or_raise(project: Project, key: Optional[str],
                   values: Dict[str, Any]) -> Dict[str, str]:
    if not key:
        raise CredError("No credential name was given.",
                        ["Use: cred get <project>/<key>"], EXIT_USAGE)
    if key not in values:
        known = sorted(values)
        hint = _nearest(key, known)
        raise CredError(
            f"Project '{project.name}' has no credential named '{key}'.",
            [f"Did you mean '{project.name}/{hint}'?" if hint else "",
             f"It has: {', '.join(known)}" if known
             else "It has no credentials yet.",
             f"Add it with: cred add {project.name}/{key}"],
            EXIT_NOT_FOUND)
    return values[key]


def _nearest(key: str, candidates: List[str]) -> Optional[str]:
    import difflib
    match = difflib.get_close_matches(key.lower(),
                                      [c.lower() for c in candidates], n=1, cutoff=0.7)
    if not match:
        return None
    return next(c for c in candidates if c.lower() == match[0])
