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
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))
import cred        # noqa: E402
import cred_store as cs  # noqa: E402

_CRED_SRC = (Path(__file__).resolve().parent.parent
             / "python" / "cred.py").read_text(encoding="utf-8")

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append(f"{label}\n    got:  {got!r}\n    want: {want!r}")
        print(f"FAIL  {label}")
    else:
        print(f"ok    {label}")


def _error_code(call):
    """The exit code a CredError carries, or what came back instead of one."""
    try:
        return call()
    except cs.CredError as exc:
        return exc.code


def _error_text(call):
    try:
        call()
        return ""
    except cs.CredError as exc:
        return exc.render()


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

check("read_options: an unknown option is rejected, not silently ignored",
      _error_code(lambda: cred.read_options(["x", "--partial"], known=("field",))),
      cs.EXIT_USAGE)
opts, pos = cred.read_options(["x", "--field", "user"], known=("field",))
check("read_options: a known option still parses normally with `known` set",
      (opts, pos), ({"field": "user"}, ["x"]))


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


# ---------------------------------------------------------------- reveal ---
# mask_value and value_stat: two ways to answer "what does this look like"
# without handing back a value that would work as the credential. Mirrored in
# tests/Unit.Tests.ps1 against ConvertTo-CredMaskedValue / ConvertTo-CredValueStat.

check("mask_value: reveals only the trailing boundary, plus the length",
      cs.mask_value("demo-key-abcdefghijklmno"), "********mno (24 characters)")
check("mask_value: at or under twice the boundary reveals nothing",
      cs.mask_value("abcdef"), "******** (6 characters)")
check("mask_value: one character over the boundary still reveals it",
      cs.mask_value("abcdefg"), "********efg (7 characters)")
check("mask_value: the empty string is 0 characters, not an error",
      cs.mask_value(""), "******** (0 characters)")
check("mask_value: singular character count",
      cs.mask_value("a"), "******** (1 character)")

check("value_stat: reports every class present, no characters",
      cs.value_stat("Tr0ub4dor&3"), "11 characters — upper, lower, digit, symbol")
check("value_stat: an all-lowercase value names only lower",
      cs.value_stat("abcdef"), "6 characters — lower")
check("value_stat: whitespace counts as its own class",
      cs.value_stat("a b"), "3 characters — lower, whitespace")
check("value_stat: the empty string is its own case, not '0 characters -- '",
      cs.value_stat(""), "0 characters")
check("value_stat: never echoes the input",
      "Tr0ub4dor&3" in cs.value_stat("Tr0ub4dor&3"), False)


# -------------------------------------------------------------- commands ---
# The table of what each verb accepts. `known` used to be passed at one of
# fifteen read_options call sites, so a mistyped flag was silently ignored on
# the other fourteen. Mirrored in tests/Unit.Tests.ps1 against
# Get-CredCommandSpec / Read-CredCommandOptions.

check("command_spec: known covers the switches",
      [v for v in cred.COMMANDS
       if not set(cred.command_spec(v)["switches"]) <= set(cred.command_spec(v)["known"])],
      [])
check("command_spec: every project-bearing verb takes --project and --path",
      [v for v in ("init", "add", "get", "list", "exec", "rm", "env",
                   "recipients", "doctor", "claude", "import", "export")
       if not {"project", "path"} <= set(cred.command_spec(v)["known"])],
      [])
check("command_spec: a verb with no project takes neither",
      [v for v in ("keygen", "key", "project", "providers")
       if "project" in cred.command_spec(v)["known"]],
      [])
check("command_spec: aliases resolve to the canonical verb",
      [cred.command_spec(a)["known"] == cred.command_spec(c)["known"]
       for a, c in cred.ALIASES.items()],
      [True] * len(cred.ALIASES))
check("command_spec: an unknown verb is an empty spec, not an error",
      cred.command_spec("nonsense")["known"], ())

check("parse_command: refuses an option the verb does not take",
      _error_code(lambda: cred.parse_command("list", ["--verfiy"])), cs.EXIT_USAGE)
check("parse_command: accepts the options it does take",
      cred.parse_command("list", ["acme", "--verify", "--json"]),
      ({"verify": True, "json": True}, ["acme"]))
check("parse_command: short forms still work",
      cred.parse_command("rm", ["acme/k", "-y"])[0], {"yes": True})
check("parse_command: --reveal partial survives the spec",
      cred.parse_command("get", ["acme/k", "--reveal", "partial"])[0],
      {"reveal": "partial"})

# Every verb the dispatcher accepts must have a spec, or its options go
# unchecked -- which is the hole this table was added to close.
_dispatch = set(re.findall(r'"([a-z-]+)":', re.search(
    r"handlers = \{(.*?)\n    \}", _CRED_SRC, re.S).group(1)))
check("command_spec: every dispatched verb has a spec",
      sorted(v for v in _dispatch
             if v not in cred.COMMANDS and v not in cred.ALIASES), [])

# The usage text is the other copy of this table, and it was never checked.
for _verb in sorted(cred.COMMANDS):
    for _opt in sorted(cred.command_spec(_verb)["known"]):
        if _opt in ("project", "path"):
            continue   # universal, documented once under ENVIRONMENT
        check(f"usage documents --{_opt} (accepted by {_verb})",
              bool(re.search(r"--%s\b" % re.escape(_opt), cred.USAGE)), True)


# ------------------------------------------------------------ read modes ---
# resolve_read_mode / assert_read_mode_applies / apply_read_mode: the rules
# `cred get` used to carry inline in both CLIs, where the only way to reach
# them was to run a process. Mirrored in tests/Unit.Tests.ps1 against
# Resolve-CredReadMode / Assert-CredReadModeApplies / Invoke-CredReadMode.

check("resolve_read_mode: no flags is the ordinary whole-value path",
      cs.resolve_read_mode(), "full")
check("resolve_read_mode: --reveal partial",
      cs.resolve_read_mode(reveal="partial"), "partial")
check("resolve_read_mode: --reveal full is that same path, named explicitly",
      cs.resolve_read_mode(reveal="full"), "full")
check("resolve_read_mode: a reveal mode is case-insensitive",
      cs.resolve_read_mode(reveal="PARTIAL"), "partial")
check("resolve_read_mode: --check", cs.resolve_read_mode(check=True), "check")
check("resolve_read_mode: --stat", cs.resolve_read_mode(stat=True), "stat")
check("resolve_read_mode: --out alone is not a read mode",
      cs.resolve_read_mode(out=True), "full")
check("resolve_read_mode: always answers with one of READ_MODES",
      cs.resolve_read_mode() in cs.READ_MODES, True)
check("resolve_read_mode: a bare --reveal names no mode and is refused",
      _error_code(lambda: cs.resolve_read_mode(reveal=True)), cs.EXIT_USAGE)
check("resolve_read_mode: an unknown reveal mode is refused",
      _error_code(lambda: cs.resolve_read_mode(reveal="bogus")), cs.EXIT_USAGE)
check("resolve_read_mode: two modes at once are refused",
      _error_code(lambda: cs.resolve_read_mode(reveal="partial", stat=True)),
      cs.EXIT_USAGE)
check("resolve_read_mode: a mode beside --out is refused",
      _error_code(lambda: cs.resolve_read_mode(stat=True, out=True)), cs.EXIT_USAGE)
check("resolve_read_mode: --reveal full beside --out is refused too",
      _error_code(lambda: cs.resolve_read_mode(reveal="full", out=True)),
      cs.EXIT_USAGE)

_SECRET = {"project": "p", "key": "k", "kind": "secret", "is_binary": False,
           "bytes": b"Tr0ub4dor&3"}
_FILE = {"project": "p", "key": "pem", "kind": "file", "is_binary": False,
         "bytes": b"-----BEGIN CERTIFICATE-----\n"}
_BINARY = {"project": "p", "key": "blob", "kind": "file", "is_binary": True,
           "bytes": b"\x00\x01\x02"}

check("assert_read_mode_applies: full passes even a file credential",
      cs.assert_read_mode_applies("full", _FILE), None)
check("assert_read_mode_applies: a mode passes an ordinary secret",
      cs.assert_read_mode_applies("stat", _SECRET), None)
check("assert_read_mode_applies: stat is refused on file content",
      _error_code(lambda: cs.assert_read_mode_applies("stat", _FILE)),
      cs.EXIT_USAGE)
check("assert_read_mode_applies: partial is refused under its flag name",
      "--reveal does not apply to file content"
      in _error_text(lambda: cs.assert_read_mode_applies("partial", _FILE)), True)

check("apply_read_mode: partial masks, and never returns the value",
      cs.apply_read_mode("partial", _SECRET),
      {"bytes": b"********r&3 (11 characters)", "newline": True,
       "exit_code": cs.EXIT_OK})
check("apply_read_mode: stat describes the composition",
      cs.apply_read_mode("stat", _SECRET)["bytes"].decode("utf-8"),
      "11 characters — upper, lower, digit, symbol")
check("apply_read_mode: a matching candidate exits 0",
      cs.apply_read_mode("check", _SECRET, candidate="Tr0ub4dor&3"),
      {"bytes": b"match", "newline": True, "exit_code": cs.EXIT_OK})
check("apply_read_mode: a mismatching candidate exits 1",
      cs.apply_read_mode("check", _SECRET, candidate="wrong"),
      {"bytes": b"no match", "newline": True, "exit_code": cs.EXIT_GENERAL})
check("apply_read_mode: no candidate at all is a mismatch, never a match",
      cs.apply_read_mode("check", _SECRET)["exit_code"], cs.EXIT_GENERAL)
check("apply_read_mode: check compares exactly, not case-insensitively",
      cs.apply_read_mode("check", _SECRET, candidate="tr0ub4dor&3")["bytes"],
      b"no match")

# The fourth arm. It sat in both CLIs until now, where the only way to reach it
# was to run a process -- and the binary-to-terminal refusal went with it.

check("apply_read_mode: full hands back a secret's exact bytes, newline allowed",
      cs.apply_read_mode("full", _SECRET),
      {"bytes": b"Tr0ub4dor&3", "newline": True, "exit_code": cs.EXIT_OK})
check("apply_read_mode: full never permits a newline after file content",
      cs.apply_read_mode("full", _FILE),
      {"bytes": b"-----BEGIN CERTIFICATE-----\n", "newline": False,
       "exit_code": cs.EXIT_OK})
check("apply_read_mode: binary content is refused at a terminal",
      _error_code(lambda: cs.apply_read_mode("full", _BINARY, to_terminal=True)),
      cs.EXIT_USAGE)
check("apply_read_mode: that refusal says how to get the bytes out",
      "--out <path>"
      in _error_text(lambda: cs.apply_read_mode("full", _BINARY, to_terminal=True)),
      True)
check("apply_read_mode: binary content is fine when stdout is redirected",
      cs.apply_read_mode("full", _BINARY, to_terminal=False)["bytes"],
      b"\x00\x01\x02")
check("apply_read_mode: text file content is not refused at a terminal",
      cs.apply_read_mode("full", _FILE, to_terminal=True)["newline"], False)


# ---------------------------------------------------------------- doctor ---
# health_rows: the row set is the interop contract, and until it moved out of
# cmd_doctor the only way to reach it was to run a process. These need no
# project and no key -- everything before the project rows always reports.

_rows = cs.health_rows()
_checks = [r["Check"] for r in _rows]

check("health_rows: names the implementation first",
      _checks[0], "python")
check("health_rows: reports the providers, then the home directory",
      _checks[1:3], ["provider:age", "cred home"])
check("health_rows: every row carries the four contract fields",
      sorted(set(k for r in _rows for k in r)),
      ["Check", "Detail", "Fix", "Status"])
check("health_rows: every status is one of Ok, Warn, Fail",
      sorted(set(r["Status"] for r in _rows)) and
      all(r["Status"] in ("Ok", "Warn", "Fail") for r in _rows), True)
check("health_rows: an Ok row never carries advice",
      [r for r in _rows if r["Status"] == "Ok" and r["Fix"]], [])
check("health_rows: check names are unique",
      len(_checks) == len(set(_checks)), True)
check("health_rows: reports rather than raising when there is no project",
      "project" in _checks, True)
check("health_rows: a missing project is a Warn, not a Fail",
      [r["Status"] for r in _rows if r["Check"] == "project"] in
      ([], ["Warn"], ["Ok"]), True)

# The keystore row existed only in Python for a while, and the identity
# protection row only in PowerShell before that. Both are in the contract now.
_identity_rows = [c for c in _checks if c.startswith("identity") or c == "keystore"]
check("health_rows: the identity rows keep their contract order",
      [c for c in _identity_rows
       if c in ("identity", "identity permissions", "identity protection", "keystore")],
      _identity_rows if not _identity_rows else
      [c for c in ("identity", "identity permissions", "identity protection",
                   "keystore") if c in _identity_rows])


# -------------------------------------------------------------- keystore ---
# The dispatch is testable everywhere; the systemd-creds backend can only be
# tested where it exists, so it is probed rather than assumed. A machine
# without it still runs everything above.

check("keystore_unprotect: a blob from another mechanism is refused by name",
      _error_code(lambda: cs.keystore_unprotect(b"x", "macos-keychain")),
      cs.EXIT_KEY)

check("keystore_unprotect: a DPAPI blob off Windows names Windows",
      "DPAPI" in _error_text(lambda: cs.keystore_unprotect(b"x", cs.KEYSTORE_DPAPI))
      or cs.is_windows(), True)

check("identity_protection: a plain key file reports file-permissions",
      cs.identity_protection(Path(__file__)), "file-permissions")

if cs.systemd_creds_available():
    check("keystore_name: systemd-creds where it is available",
          cs.keystore_name(), cs.KEYSTORE_SYSTEMD)

    # The property that matters is that arbitrary bytes survive: an age
    # identity is ASCII, but nothing in the format promises that, and a
    # keystore that quietly mangles a NUL would corrupt a key silently.
    awkward = b"a\x00b\xff\xfe AGE-SECRET-KEY-1EXAMPLE\n"
    check("systemd-creds: round-trips arbitrary bytes exactly",
          cs.systemd_creds_unprotect(cs.systemd_creds_protect(awkward)), awkward)

    wrapped = cs.wrap_identity("AGE-SECRET-KEY-1EXAMPLE")
    meta = json.loads(wrapped)
    check("wrap_identity: names the mechanism that sealed it",
          (meta["format"], meta["protection"]),
          (cs.IDENTITY_FORMAT, cs.KEYSTORE_SYSTEMD))
    check("wrap_identity: keeps no key material in the file",
          "AGE-SECRET-KEY-1EXAMPLE" in wrapped, False)

    # A damaged blob must fail loudly rather than return plausible bytes.
    torn = bytearray(cs.systemd_creds_protect(b"secret"))
    torn[len(torn) // 2] ^= 0xFF
    check("systemd-creds: a damaged blob is refused, not silently decoded",
          _error_code(lambda: cs.systemd_creds_unprotect(bytes(torn))), cs.EXIT_KEY)
else:
    print("skip  systemd-creds backend (not available on this machine)")

print()
if FAILURES:
    print(f"{len(FAILURES)} failure(s):")
    for f in FAILURES:
        print("  " + f)
    sys.exit(1)
print("all python unit checks passed")
