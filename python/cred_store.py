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
    if meta.get("protection") != "dpapi-currentuser":
        raise CredError(
            f"'{path}' is wrapped with '{meta.get('protection')}', "
            "which this machine cannot open.",
            ["Open it where it was wrapped, then: cred key unprotect"],
            EXIT_KEY)
    return _dpapi_unprotect(base64.b64decode(meta["data"])).decode("utf-8")


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


def age_encrypt(plain: bytes, recipients: List[str]) -> bytes:
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
    write_text_atomic(path, text)
    restrict_path(path)
    pub = next((l.strip() for l in text.splitlines() if l.startswith("age1")), "")
    if not pub:
        for line in text.splitlines():
            if "public key:" in line:
                pub = line.split("public key:")[1].strip()
                break
    return path, pub


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

    provider = cfg.setdefault("provider", "age")
    if provider != "age":
        raise CredError(
            f"The Python cred only implements the 'age' provider, "
            f"but this project uses '{provider}'.",
            ["Use the PowerShell cred for this project, which also ships gpg.",
             "Or re-encrypt it with age."], EXIT_BACKEND)

    cfg.setdefault("version", CONFIG_VERSION)
    cfg.setdefault("project", path.parent.parent.name)
    cfg.setdefault("store", "store.age")
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
    plain = age_decrypt(cipher, project.store_path, project.config)
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
    cipher = age_encrypt(plain, list(project.config.get("recipients") or []))

    staged = stage_bytes(project.store_path, cipher)
    try:
        try:
            verify = age_decrypt(cipher, staged, project.config)
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


def default_env_names(key: str, kind: str) -> Dict[str, str]:
    import re
    slug = re.sub(r"[^A-Za-z0-9]", "_", key).upper()
    if kind == "userpass":
        return {"user": f"{slug}_USER", "secret": f"{slug}_PASSWORD"}
    return {"secret": slug}


def build_environment(project: Project, only=None, exclude=None,
                      prefix: str = "") -> Dict[str, str]:
    values = read_values(project)
    defs = project.config.get("credentials") or {}
    out: Dict[str, str] = {}
    for key, entry in values.items():
        if only and key not in only:
            continue
        if exclude and key in exclude:
            continue
        d = defs.get(key) or {}
        env = d.get("env") or default_env_names(
            key, "userpass" if "user" in entry else "secret")
        for field, value in entry.items():
            name = prefix + str(env.get(field) or
                                default_env_names(key, "userpass")[field])
            out[name] = str(value)
    return out


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
