"""Unit checks for the pure-Python half of cred.

The Python CLI is the default implementation on every platform, so its argv
parser and its entry rules deserve direct tests rather than only being
exercised through `cred` as a process. cred.py is importable, so unlike its
PowerShell peer nothing had to move to make this possible -- it simply was
never done.

No pytest: the repo depends on nothing from PyPI, and tests/Invoke-Tests.ps1
is the one runner. This prints one line per case and exits non-zero on any
failure, so a single Pester assertion can wrap the lot.

    python tests/pyunit.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))
import cred        # noqa: E402
import cred_store as cs  # noqa: E402

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append(f"{label}\n    got:  {got!r}\n    want: {want!r}")
        print(f"FAIL  {label}")
    else:
        print(f"ok    {label}")


# ------------------------------------------------------------------ argv ---
# These mirror the PowerShell cases in tests/Unit.Tests.ps1 one for one. The
# two CLIs must parse the same argv the same way; `--opt=` used to be an empty
# string in PowerShell and a bare flag here.

head, tail = cred.split_argv(["exec", "acme", "--", "npm", "run", "--", "x"])
check("split_argv: splits at the first bare --", (head, tail),
      (["exec", "acme"], ["npm", "run", "--", "x"]))

check("split_argv: empty tail without a separator",
      cred.split_argv(["list", "acme"]), (["list", "acme"], []))

opts, pos = cred.read_options(
    ["acme/db", "--user", "svc", "--desc=a b", "--stdin"], switches=("stdin",))
check("read_options: --opt value, --opt=value and switches",
      (opts, pos), ({"user": "svc", "desc": "a b", "stdin": True}, ["acme/db"]))

opts, _ = cred.read_options(["x", "--env", "--stdin"], switches=("stdin",))
check("read_options: a value-taking option does not swallow the next flag",
      opts, {"env": True, "stdin": True})

opts, pos = cred.read_options(["x", "--field"])
check("read_options: a trailing value-taking option is a flag",
      (opts, pos), ({"field": True}, ["x"]))

opts, pos = cred.read_options(["-n", "x"], switches=("no-newline",),
                              short={"n": "no-newline"})
check("read_options: short forms", (opts, pos), ({"no-newline": True}, ["x"]))

opts, _ = cred.read_options(["--Field", "user"])
check("read_options: option names are lower-cased", opts, {"field": "user"})

opts, _ = cred.read_options(["--prefix="])
check("read_options: --opt= is an empty string, not a flag", opts, {"prefix": ""})

opts, pos = cred.read_options(["-", "x"])
check("read_options: a lone dash stays positional", (opts, pos), ({}, ["-", "x"]))


# ----------------------------------------------------------------- entry ---
# The rules in cred_store.resolve_entry, checked directly rather than only
# through a decrypted store.

check("entry_kind: the encoding marker means file",
      cs.entry_kind({"secret": "x", "encoding": "base64"}, None), "file")
check("entry_kind: a user field means userpass",
      cs.entry_kind({"user": "u", "secret": "x"}, None), "userpass")
check("entry_kind: a declaration speaks when the store is silent",
      cs.entry_kind({}, {"type": "userpass"}), "userpass")
check("entry_kind: the store wins over a stale declaration",
      cs.entry_kind({"secret": "x", "encoding": "base64"}, {"type": "secret"}),
      "file")
check("entry_kind: an unknown declared type falls back to secret",
      cs.entry_kind({}, {"type": "nonsense"}), "secret")

check("env_names: a secret is the bare slug",
      cs.env_names("my.key", "secret"), {"secret": "MY_KEY"})
check("env_names: a userpass gets USER and PASSWORD",
      cs.env_names("db", "userpass"),
      {"user": "DB_USER", "secret": "DB_PASSWORD"})
check("env_names: a file maps to nothing",
      cs.env_names("pem", "file"), {})
check("env_names: a declaration overrides the convention",
      cs.env_names("db", "userpass", {"secret": "PGPASSWORD"}),
      {"user": "DB_USER", "secret": "PGPASSWORD"})
check("env_names: a half-filled declaration keeps the convention for the rest",
      cs.env_names("db", "userpass", {"user": "DB_LOGIN"}),
      {"user": "DB_LOGIN", "secret": "DB_PASSWORD"})

view = cs.resolve_entry("notes", {"secret": "line one\nzweite Zeile\n"},
                        {"type": "file", "filename": "notes.txt"})
check("resolve_entry: a text file credential injects nothing",
      (view["kind"], view["env_vars"], view["display"], view["is_binary"]),
      ("file", {}, "file: notes.txt", False))

view = cs.resolve_entry("db", {"user": "svc", "secret": "p"}, None)
check("resolve_entry: an undeclared userpass still follows the convention",
      view["env_vars"], {"DB_USER": "svc", "DB_PASSWORD": "p"})

# 'encoding' is the file marker and must never leak into the environment as
# $env:BLOB_ENCODING. Both implementations test for the key's *presence*, not
# its truthiness, so they agree on the odd case of an explicit null -- neither
# ever writes one.
view = cs.resolve_entry("blob", {"secret": "AAEC", "encoding": "base64"}, None)
check("resolve_entry: the encoding marker never becomes a variable",
      (view["kind"], view["env_vars"]), ("file", {}))
check("resolve_entry: a present-but-null encoding is still the file marker",
      cs.entry_kind({"secret": "x", "encoding": None}, None), "file")

print()
if FAILURES:
    print(f"{len(FAILURES)} failure(s):")
    for f in FAILURES:
        print("  " + f)
    sys.exit(1)
print("all python unit checks passed")
