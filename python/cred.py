#!/usr/bin/env python3
"""
cred -- command-line front end, in Python.

A peer of bin/cred.ps1, not a wrapper around it. Both read and write the same
age-encrypted stores, so you can use whichever is convenient on a given machine
and they will not notice each other. See ARCHITECTURE.md.

Like its PowerShell counterpart this file holds no behaviour: it parses argv,
calls cred_store, prints, and picks an exit code.
"""

from __future__ import annotations

import getpass
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cred_store as cs   # noqa: E402

USAGE = """\
cred - per-repository encrypted credentials (Python implementation)

USAGE
  cred <command> [args] [options]

GETTING STARTED
  cred init [name]                 Set up .creds/ in this repo (commit it)
  cred add <project>/<key>         Add a credential; prompts, no echo
  cred get <project>/<key>         Print one secret to stdout
  cred exec <project> -- <cmd>     Run <cmd> with the secrets as env vars

COMMANDS
  init [name]                      Create a store here
      --recipient <key>            Recipient(s) instead of your own key
      --force                      Overwrite an existing store

  add|set <project>/<key>          Add or replace a credential
      --user <name>                Make it a username/password pair
      --value <secret>             Non-interactive (leaks to shell history)
      --stdin                      Read the value from stdin
      --env <NAME>                 Environment variable name to map it to
      --desc <text>                What it is for

  get <project>/<key>              Print a secret
      --field <secret|user>        Which half of a userpass pair
      -n, --no-newline             Omit the trailing newline

  list [project]                   Show credential names (never values)
      --json                       Machine-readable

  exec <project> -- <cmd> [args]   Run with secrets injected as env vars
      --only <a,b>                 Inject only these credentials
      --except <a,b>               Inject everything but these
      --prefix <P>                 Prefix every variable name

  rm <project>/<key>               Delete a credential
  env [project]                    Print export lines (--format posix|powershell)

  recipients [project]             Who can decrypt this project
  recipients add <key>...          Grant access and re-encrypt
  recipients rm <key>...           Revoke access and re-encrypt

  keygen                           Create this machine's key (--show, --force)
  key                              Show where your key is and how it is held
  project list                     Registered projects on this machine
  doctor [project]                 Check the setup and say how to fix it
  version | help

ENVIRONMENT
  CRED_HOME            Config directory (default %APPDATA%\\cred, ~/.config/cred)
  CRED_IDENTITY_FILE   Path to the age key
  CRED_PROJECT         Default project when none is named
  CRED_AGE_PATH        Explicit path to the age binary

EXIT CODES
  0 ok   2 usage   3 not found   4 key/decrypt   5 backend missing
  6 corrupt store   7 locked   8 child command failed
"""


# ------------------------------------------------------------------- argv ---

def split_argv(argv: List[str]):
    """Split at the first bare '--'. Everything after it is passed through."""
    if "--" not in argv:
        return argv, []
    i = argv.index("--")
    return argv[:i], argv[i + 1:]


def read_options(argv: List[str], switches=(), short=None):
    """Parse --flag, --opt value, --opt=value and -x short forms."""
    short = short or {}
    opts: Dict[str, Any] = {}
    positional: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--") and len(a) > 2:
            name, _, inline = a[2:].partition("=")
            name = name.lower()
            if name in switches:
                opts[name] = True
            elif inline:
                opts[name] = inline
            elif i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                opts[name] = argv[i + 1]
                i += 1
            else:
                opts[name] = True
        elif len(a) == 2 and a[0] == "-" and a[1] in short:
            name = short[a[1]]
            if name in switches:
                opts[name] = True
            elif i + 1 < len(argv):
                opts[name] = argv[i + 1]
                i += 1
            else:
                opts[name] = True
        else:
            positional.append(a)
        i += 1
    return opts, positional


# ----------------------------------------------------------------- output ---

def out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def write_secret(value: str, newline: bool = True) -> None:
    """Write a secret to stdout as exact UTF-8 bytes.

    Goes through the buffer rather than print() so the console encoding cannot
    mangle a non-ASCII password, and so piping yields the bytes that went in.
    """
    data = (value + ("\n" if newline else "")).encode("utf-8")
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def table(rows: List[Dict[str, Any]], columns: List[str]) -> None:
    if not rows:
        return
    widths = {c: max(len(c), max(len(str(r.get(c, ""))) for r in rows))
              for c in columns}
    out("  ".join(c.ljust(widths[c]) for c in columns).rstrip())
    out("  ".join("-" * widths[c] for c in columns).rstrip())
    for r in rows:
        out("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in columns).rstrip())


def prompt_secret(label: str) -> str:
    if not sys.stdin.isatty():
        raise cs.CredError(
            "No value was supplied and there is no terminal to prompt on.",
            ["Pipe it in:  cat secret.txt | cred add <project>/<key> --stdin",
             "Or pass it:  cred add <project>/<key> --value '<value>'   "
             "(beware shell history)"],
            cs.EXIT_USAGE)
    return getpass.getpass(f"{label}: ")


def read_stdin_secret() -> str:
    # Raw bytes, decoded as UTF-8 by us -- never the console code page.
    data = sys.stdin.buffer.read().decode("utf-8")
    if data.endswith("\n"):
        data = data[:-1]
    if data.endswith("\r"):
        data = data[:-1]
    return data


# --------------------------------------------------------------- commands ---

def cmd_init(rest: List[str]) -> int:
    opts, pos = read_options(rest, switches=("force",))
    root = Path(opts.get("path") or Path.cwd()).resolve()
    name = pos[0] if pos else (opts.get("project") or root.name)

    if not cs.valid_key_name(name):
        raise cs.CredError(f"'{name}' is not a usable project name.",
                           ["Use letters, digits, dot, dash or underscore."],
                           cs.EXIT_USAGE)

    config_path = root / cs.CREDS_DIR / cs.CONFIG_NAME
    if config_path.is_file() and not opts.get("force"):
        raise cs.CredError(f"'{root}' already has a credential store.",
                           [f"Add a credential:  cred add {name}/<key>",
                            f"See what is there: cred list {name}",
                            "Start over:        cred init --force"],
                           cs.EXIT_USAGE)

    recipients = ([r.strip() for r in str(opts["recipient"]).split(",")]
                  if opts.get("recipient") else None)
    if not recipients:
        ident = cs.identity_path(None)
        if not ident.is_file():
            cs.age_new_identity(ident)
        recipients = [cs.age_recipient(None)]

    (root / cs.CREDS_DIR).mkdir(parents=True, exist_ok=True)
    config = {"version": cs.CONFIG_VERSION, "project": name, "provider": "age",
              "store": "store.age", "recipients": recipients, "credentials": {}}
    cs.write_text_atomic(config_path, cs.dump_json(config))

    project = cs.Project(root)
    with cs.StoreLock(project.creds_dir):
        cs.write_values(project, {})

    cs.write_text_atomic(root / cs.CREDS_DIR / ".gitignore",
                         "# Managed by cred. The encrypted store and the config are meant to be\n"
                         "# committed; only these transient files are not.\n"
                         ".lock\n*.tmp*\n")
    cs.register_project(name, root)

    out(f"Created {name} in {root}")
    out(f"  store      {project.store_path}")
    out("  provider   age")
    out(f"  recipient  {', '.join(recipients)}")
    out("")
    out(f"Commit .creds/ -- it is encrypted. Then: cred add {name}/<key>")
    return cs.EXIT_OK


def cmd_add(rest: List[str]) -> int:
    opts, pos = read_options(rest, switches=("stdin", "allow-empty"))
    if not pos:
        raise cs.CredError("cred add <project>/<key> [--user <name>]",
                           ["Run 'cred help' for the full surface."], cs.EXIT_USAGE)

    proj_ref, key = cs.split_reference(pos[0])
    if not cs.valid_key_name(key):
        raise cs.CredError(f"'{key}' is not a usable credential name.",
                           ["Use letters, digits, dot, dash or underscore."],
                           cs.EXIT_USAGE)

    project = cs.resolve_project(opts.get("project") or proj_ref, opts.get("path"))
    user = opts.get("user")

    if opts.get("stdin"):
        secret = read_stdin_secret()
    elif opts.get("value") is not None and opts.get("value") is not True:
        secret = str(opts["value"])
    elif len(pos) > 1:
        secret = pos[1]
    else:
        label = (f"Password for '{user}' ({project.name}/{key})" if user
                 else f"Secret for {project.name}/{key}")
        secret = prompt_secret(label)

    if not secret and not opts.get("allow-empty"):
        raise cs.CredError("An empty value was given.",
                           ["Provide a value, or pass --allow-empty."],
                           cs.EXIT_USAGE)

    created = {"v": False}

    def mutate(values, proj):
        existing = values.get(key)
        created["v"] = existing is None
        kind = "userpass" if (user or (existing and "user" in existing)) else "secret"
        entry: Dict[str, str] = {}
        if kind == "userpass":
            entry["user"] = user or (existing or {}).get("user", "")
        entry["secret"] = secret
        values[key] = entry

        defs = proj.config.setdefault("credentials", {})
        d = defs.get(key)
        if d is None:
            d = {"type": kind, "env": cs.default_env_names(key, kind)}
            defs[key] = d
        d["type"] = kind
        d.setdefault("env", cs.default_env_names(key, kind))
        if kind == "userpass" and "user" not in d["env"]:
            d["env"]["user"] = cs.default_env_names(key, kind)["user"]
        if opts.get("desc"):
            d["description"] = str(opts["desc"])
        if opts.get("env"):
            d["env"]["secret"] = str(opts["env"])

    cs.update_store(project, mutate)
    kind = project.config["credentials"][key]["type"]
    out(f"{'Added' if created['v'] else 'Updated'} {project.name}/{key} ({kind})")
    return cs.EXIT_OK


def cmd_get(rest: List[str]) -> int:
    opts, pos = read_options(rest, switches=("no-newline",), short={"n": "no-newline"})
    if not pos:
        raise cs.CredError("cred get <project>/<key>", [], cs.EXIT_USAGE)

    proj_ref, key = cs.split_reference(pos[0])
    project = cs.resolve_project(opts.get("project") or proj_ref, opts.get("path"))
    values = cs.read_values(project)
    entry = cs.entry_or_raise(project, key, values)

    field = str(opts.get("field") or "secret")
    if field not in entry:
        kind = (project.config.get("credentials", {}).get(key) or {}).get("type", "secret")
        raise cs.CredError(
            f"'{project.name}/{key}' has no '{field}' field.",
            [f"It is a '{kind}' credential with: {', '.join(entry)}",
             f"To give it a username: cred add {project.name}/{key} --user <name>"],
            cs.EXIT_NOT_FOUND)

    write_secret(str(entry[field]), newline=not opts.get("no-newline"))
    return cs.EXIT_OK


def cmd_list(rest: List[str]) -> int:
    opts, pos = read_options(rest, switches=("json", "verify"))
    project = cs.resolve_project(pos[0] if pos else opts.get("project"),
                                 opts.get("path"))
    defs = project.config.get("credentials") or {}
    values = cs.read_values(project) if opts.get("verify") else None

    keys = sorted(set(defs) | set(values or {}))
    rows = []
    for k in keys:
        d = defs.get(k) or {}
        row = {"Project": project.name, "Key": k,
               "Type": d.get("type", "secret"),
               "Environment": ", ".join(str(v) for v in (d.get("env") or {}).values()),
               "Description": d.get("description", "")}
        if values is not None:
            row["HasValue"] = bool(values.get(k, {}).get("secret"))
        rows.append(row)

    if opts.get("json"):
        import json as _json
        out(_json.dumps(rows, indent=2, ensure_ascii=False))
    elif not rows:
        out(f"No credentials defined. Add one with: cred add {project.name}/<key>")
    else:
        cols = ["Key", "Type", "Environment", "Description"]
        if values is not None:
            cols.insert(2, "HasValue")
        table(rows, cols)
    return cs.EXIT_OK


def cmd_exec(rest: List[str], tail: List[str]) -> int:
    opts, pos = read_options(rest)
    if not tail:
        raise cs.CredError("cred exec <project> -- <command> [args]", [], cs.EXIT_USAGE)

    project = cs.resolve_project(pos[0] if pos else opts.get("project"),
                                 opts.get("path"))
    only = [s.strip() for s in str(opts["only"]).split(",")] if opts.get("only") else None
    exclude = [s.strip() for s in str(opts["except"]).split(",")] if opts.get("except") else None

    if only:
        values = cs.read_values(project)
        missing = [k for k in only if k not in values]
        if missing:
            known = sorted(values)
            names = "', '".join(missing)
            raise cs.CredError(
                f"Project '{project.name}' has no credential named '{names}'.",
                [f"It has: {', '.join(known)}" if known else "It has no credentials yet.",
                 f"Add one with: cred add {project.name}/{missing[0]}"],
                cs.EXIT_NOT_FOUND)

    secrets = cs.build_environment(project, only, exclude,
                                   str(opts.get("prefix") or ""))
    env = dict(os.environ)
    env.update(secrets)
    env["CRED_PROJECT"] = project.name
    env["CRED_PROJECT_ROOT"] = str(project.root)
    env["CRED_INJECTED"] = ",".join(sorted(secrets))

    try:
        # No redirection: the child talks straight to this terminal, so its
        # output never passes through us.
        return subprocess.call(tail, env=env)
    except FileNotFoundError:
        raise cs.CredError(
            f"Command not found: '{tail[0]}'.",
            ["Check the spelling, or give a full path.",
             "Everything after '--' is run verbatim: "
             "cred exec <project> -- <command> [args]"],
            cs.EXIT_COMMAND)
    except OSError as exc:
        raise cs.CredError(f"Could not run '{tail[0]}': {exc}",
                           ["Check that it is an executable this shell can start."],
                           cs.EXIT_COMMAND)


def cmd_rm(rest: List[str]) -> int:
    opts, pos = read_options(rest, switches=("yes", "keep-definition"),
                             short={"y": "yes"})
    if not pos:
        raise cs.CredError("cred rm <project>/<key>", [], cs.EXIT_USAGE)

    proj_ref, key = cs.split_reference(pos[0])
    project = cs.resolve_project(opts.get("project") or proj_ref, opts.get("path"))

    if not opts.get("yes"):
        if not sys.stdin.isatty():
            raise cs.CredError("Refusing to delete without confirmation.",
                               ["Pass --yes to delete non-interactively."],
                               cs.EXIT_USAGE)
        answer = input(f"Remove {project.name}/{key}? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            out("Cancelled.")
            return cs.EXIT_OK

    def mutate(values, proj):
        cs.entry_or_raise(proj, key, values)
        del values[key]
        if not opts.get("keep-definition"):
            proj.config.get("credentials", {}).pop(key, None)

    cs.update_store(project, mutate)
    out(f"Removed {project.name}/{key}")
    return cs.EXIT_OK


def cmd_env(rest: List[str]) -> int:
    opts, pos = read_options(rest)
    project = cs.resolve_project(pos[0] if pos else opts.get("project"),
                                 opts.get("path"))
    only = [s.strip() for s in str(opts["only"]).split(",")] if opts.get("only") else None
    exclude = [s.strip() for s in str(opts["except"]).split(",")] if opts.get("except") else None
    values = cs.build_environment(project, only, exclude,
                                  str(opts.get("prefix") or ""))

    fmt = str(opts.get("format") or "posix")
    posix_quote = "'" + chr(92) + "''"
    for k in sorted(values):
        v = values[k]
        if fmt == "powershell":
            line = "$env:{} = '{}'".format(k, v.replace("'", "''"))
        else:
            line = "export {}='{}'".format(k, v.replace("'", posix_quote))
        write_secret(line)
    return cs.EXIT_OK


def cmd_recipients(rest: List[str]) -> int:
    sub = rest[0].lower() if rest else ""
    if sub in ("add", "rm", "remove"):
        opts, pos = read_options(rest[1:], switches=("yes",))
        if not pos:
            raise cs.CredError(f"cred recipients {sub} <public-key>", [], cs.EXIT_USAGE)
        project = cs.resolve_project(opts.get("project"), opts.get("path"))

        if sub == "add":
            for r in pos:
                looks_right = (r.startswith("age1") or r.startswith("ssh-ed25519 ")
                               or r.startswith("ssh-rsa "))
                if not looks_right:
                    raise cs.CredError(
                        f"'{r}' does not look like an age recipient.",
                        ["age public keys start with 'age1'.",
                         "Ask the other person for: cred keygen --show"],
                        cs.EXIT_USAGE)

        def mutate(values, proj):
            current = list(proj.config.get("recipients") or [])
            if sub == "add":
                for r in pos:
                    if r not in current:
                        current.append(r)
            else:
                current = [c for c in current if c not in pos]
                if not current:
                    raise cs.CredError(
                        "Removing that would leave the store with no recipients, "
                        "so nobody could ever read it again.",
                        ["Add a replacement first: cred recipients add <public-key>"],
                        cs.EXIT_USAGE)
            proj.config["recipients"] = current

        cs.update_store(project, mutate)
        n = len(project.config["recipients"])
        verb = "Added" if sub == "add" else "Removed"
        out(f"{verb} recipient(s); store re-encrypted for {n}.")
        if sub != "add":
            out("Anyone who held a removed key can still read this store from "
                "git history -- rotate the secrets themselves.")
        return cs.EXIT_OK

    opts, pos = read_options(rest)
    project = cs.resolve_project(pos[0] if pos else opts.get("project"),
                                 opts.get("path"))
    try:
        mine = cs.age_recipient(project.config)
    except cs.CredError:
        mine = None
    rows = [{"Recipient": r, "IsMe": str(r == mine)}
            for r in (project.config.get("recipients") or [])]
    table(rows, ["Recipient", "IsMe"])
    return cs.EXIT_OK


def cmd_keygen(rest: List[str]) -> int:
    opts, _ = read_options(rest, switches=("show", "force"))
    path = Path(opts["path"]) if opts.get("path") else cs.identity_path(None)

    if opts.get("show"):
        write_secret(cs.age_recipient(None))
        return cs.EXIT_OK

    if path.is_file() and not opts.get("force"):
        out(f"Key already exists at {path}")
        out(f"Public key: {cs.age_recipient(None)}")
        return cs.EXIT_OK

    if path.is_file() and opts.get("force"):
        import datetime
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
        backup = path.with_suffix(path.suffix + f".{stamp}.bak")
        path.replace(backup)
        cs.restrict_path(backup)
        out(f"Existing key moved to {backup}")

    created, pub = cs.age_new_identity(path)
    out(f"Created a new key at {created}")
    out(f"Public key: {pub}")
    out("")
    out("Back this file up. Without it you cannot read any store encrypted to it.")
    return cs.EXIT_OK


def cmd_key(rest: List[str]) -> int:
    sub = rest[0].lower() if rest else ""
    path = cs.identity_path(None)
    if sub in ("protect", "unprotect", "unwrap"):
        raise cs.CredError(
            "Wrapping and unwrapping the key is done by the PowerShell cred.",
            ["Run: cred key " + sub + "   (from bin/cred.ps1 or bin/cred)",
             "The Python cred can read a wrapped key, but does not create one."],
            cs.EXIT_USAGE)

    out(f"path        {path}")
    out(f"exists      {path.is_file()}")
    out(f"protection  {'dpapi-currentuser' if cs.identity_is_wrapped(path) else 'file-permissions'}")
    if path.is_file():
        try:
            out(f"public key  {cs.age_recipient(None)}")
        except cs.CredError:
            pass
    return cs.EXIT_OK


def cmd_project(rest: List[str]) -> int:
    sub = rest[0].lower() if rest else "list"
    reg = cs.read_registry()
    if sub in ("rm", "remove"):
        if len(rest) < 2:
            raise cs.CredError("cred project rm <name>", [], cs.EXIT_USAGE)
        name = rest[1]
        if name not in reg["projects"]:
            raise cs.CredError(f"No project named '{name}' is registered.",
                               ["See what is: cred project list"], cs.EXIT_NOT_FOUND)
        del reg["projects"][name]
        cs.write_registry(reg)
        out(f"Forgot {name}. Its .creds directory was left alone.")
        return cs.EXIT_OK

    rows = []
    for name in sorted(reg["projects"]):
        p = Path(reg["projects"][name]["path"])
        rows.append({"Name": name, "Path": str(p),
                     "Available": str((p / cs.CREDS_DIR / cs.CONFIG_NAME).is_file())})
    if not rows:
        out("No projects registered. Run: cd <repo>; cred init")
    else:
        table(rows, ["Name", "Available", "Path"])
    return cs.EXIT_OK


def cmd_doctor(rest: List[str]) -> int:
    opts, pos = read_options(rest)
    rows = []

    def row(check, status, detail, fix=""):
        rows.append({"Check": check, "Status": status, "Detail": detail,
                     "Fix": "" if status == "Ok" else fix})

    row("python", "Ok", f"{sys.version.split()[0]} ({sys.platform})")

    age = cs.find_executable("age", "CRED_AGE_PATH")
    keygen = cs.find_executable("age-keygen", "CRED_AGE_KEYGEN_PATH")
    if age and keygen:
        row("provider:age", "Ok", "age and age-keygen found.")
    else:
        row("provider:age", "Fail", "age or age-keygen was not found.",
            "Install age: winget install FiloSottile.age (or brew/apt install age)")

    home = cs.cred_home()
    row("cred home", "Ok" if home.is_dir() else "Warn", str(home), "Run: cred init")

    ident = cs.identity_path(None)
    if ident.is_file():
        row("identity", "Ok", str(ident))
        row("identity protection", "Ok",
            "dpapi-currentuser" if cs.identity_is_wrapped(ident) else "file-permissions")
    else:
        row("identity", "Warn", f"No key at '{ident}'.", "Run: cred keygen")

    try:
        project = cs.resolve_project(pos[0] if pos else opts.get("project"),
                                     opts.get("path"))
    except cs.CredError:
        row("project", "Warn", "Not inside a project (and none named).", "Run: cred init")
        table(rows, ["Check", "Status", "Detail", "Fix"])
        return cs.EXIT_OK

    row("project", "Ok", f"{project.name} at {project.root}")
    if project.store_path.is_file():
        row("store", "Ok", str(project.store_path))
        try:
            n = len(cs.read_values(project))
            row("decrypt", "Ok", f"{n} credential(s) readable.")
        except cs.CredError as exc:
            row("decrypt", "Fail", exc.message.splitlines()[0], "See: cred recipients")
    else:
        row("store", "Warn", f"No store at '{project.store_path}'.",
            f"Run: cred add {project.name}/<key>")

    try:
        mine = cs.age_recipient(project.config)
    except cs.CredError:
        mine = None
    recipients = project.config.get("recipients") or []
    if mine and mine in recipients:
        row("recipients", "Ok", f"{len(recipients)} recipient(s); you are one.")
    elif mine:
        row("recipients", "Fail", "Your key is not a recipient of this project.",
            f"Ask a current recipient to run: cred recipients add {mine}")
    else:
        row("recipients", "Warn", f"{len(recipients)} recipient(s); could not determine yours.",
            "Run: cred keygen")

    table(rows, ["Check", "Status", "Detail", "Fix"])
    return cs.EXIT_GENERAL if any(r["Status"] == "Fail" for r in rows) else cs.EXIT_OK


# --------------------------------------------------------------- dispatch ---

def dispatch(argv: List[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(USAGE)
        return cs.EXIT_OK

    head, tail = split_argv(argv)
    verb = (head[0] if head else "").lower()
    rest = head[1:]

    if verb in ("version", "--version", "-v"):
        out(f"cred 1.0.0  (Python {sys.version.split()[0]})")
        return cs.EXIT_OK

    handlers = {
        "init": cmd_init, "add": cmd_add, "set": cmd_add, "get": cmd_get,
        "list": cmd_list, "rm": cmd_rm, "remove": cmd_rm, "delete": cmd_rm,
        "env": cmd_env, "recipients": cmd_recipients, "keygen": cmd_keygen,
        "key": cmd_key, "project": cmd_project, "doctor": cmd_doctor,
        "check": cmd_doctor,
    }
    if verb == "exec":
        return cmd_exec(rest, tail)
    if verb in handlers:
        return handlers[verb](rest)

    raise cs.CredError(f"Unknown command '{verb}'.",
                       ["Run 'cred help' to see what there is."], cs.EXIT_USAGE)


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        return dispatch(args)
    except cs.CredError as exc:
        for line in exc.render().splitlines():
            sys.stderr.write(f"cred: {line}\n")
        return exc.code
    except KeyboardInterrupt:
        sys.stderr.write("cred: interrupted\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
