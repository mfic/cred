#!/usr/bin/env python3
"""
cred -- command-line front end, in Python.

A peer of bin/cred-ps.ps1, not a wrapper around it. Both read and write the same
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
cred - per-repository encrypted credentials

USAGE
  cred <command> [args] [options]

GETTING STARTED
  cred init [name]                 Set up .creds/ in this repo (commit it)
  cred add <project>/<key>         Add a credential; prompts, no echo
  cred get <project>/<key>         Print one secret to stdout
  cred exec <project> -- <cmd>     Run <cmd> with the secrets as env vars

COMMANDS
  init [name]                      Create a store here
      --provider <name>            Encryption backend (default: age)
      --recipient <key>            Recipient(s) instead of your own key
      --force                      Overwrite an existing store
      -y, --yes                    Skip the confirmation --force asks for

  add|set <project>/<key>          Add or replace a credential
      --user <name>                Make it a username/password pair
      --value <secret>             Non-interactive (leaks to shell history)
      --stdin                      Read the value from stdin
      --file <path>                Store a file's exact bytes (PEM, cert, key)
      --filename <name>            Record a different name than the source
      --env <NAME>                 Environment variable name to map it to
      --desc <text>                What it is for (--description too)
      --env-user <NAME>            Variable name for the username half
      --allow-empty                Permit an empty value

  get <project>/<key>              Print a secret
      --field <secret|user>        Which half of a userpass pair
      --reveal full                 The value in the clear (default; explicit name for it)
      --reveal partial             A few trailing characters and the length
      --stat                       Length and character composition, no characters
      --check                      Compare to a candidate read from stdin; prints
                                   match/no match, exits 0/1 -- no value either way
      -n, --no-newline             Omit the trailing newline
      --out <path>                 Write to a file instead of stdout
      --force                      Allow --out to overwrite

  list [project]                   Show credential names (never values)
      --verify                     Also decrypt and flag missing values
      --json                       Machine-readable

  exec <project> -- <cmd> [args]   Run with secrets injected as env vars
      --only <a,b>                 Inject only these credentials
      --except <a,b>               Inject everything but these
      --prefix <P>                 Prefix every variable name

  rm <project>/<key>               Delete a credential
      --yes                        Skip the confirmation
      --keep-definition            Remove the value, keep the declaration

  env [project]                    Print export lines for the current shell
      --format <powershell|posix>

  recipients [project]             Who can decrypt this project
  recipients add <key>...          Grant access and re-encrypt
  recipients rm <key>...           Revoke access and re-encrypt

  keygen                           Create this machine's key
      --show                       Print the public key instead
      --protect                    Wrap it with the OS keystore
      --force                      Replace the existing key (backs it up)

  key                              Show where your key is and how it is held
  key protect                      Wrap it with the OS keystore
      --backup <file>              Save the unwrapped key first (do this)
  key unprotect                    Unwrap it, before moving machine or account
      --provider <name>            Which backend's key (default: age)

  import <path>                    Import PSCredential files into a store
      --name <key>                 Name for a single file
      --desc <text>                Description for what is imported
      --force                      Overwrite credentials that already exist
      --dry-run                    Show what would happen, change nothing

  export <folder>                  Write credentials out as PSCredential files
      --only <a,b>                 Just these
      --yes                        Skip the confirmation

  project list                     Registered projects on this machine
  project add [path]               Register an existing store (default: here)
  project rm <name>                Forget a project mapping

  providers                        Encryption backends and their status
  doctor [project]                 Check the setup and say how to fix it
                                   Re-registers a cloned or renamed project
      --repair                     Re-apply restrictive permissions

  claude [project]                 Markdown brief for a Claude Code session
      --write                      Write it into the repo's CLAUDE.md

  version | help

ENVIRONMENT
  CRED_HOME            Config directory (default %APPDATA%\\cred, ~/.config/cred)
  CRED_IDENTITY_FILE   Path to the age key (default <CRED_HOME>/identity.txt)
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


def read_options(argv: List[str], switches=(), short=None, known=None):
    """Parse --flag, --opt value, --opt=value and -x short forms.

    `known`, when given, is every option name a command accepts -- value
    options and switches together. Anything else raises rather than being
    silently ignored: a typo'd flag (`--partial` for `--reveal partial`) must
    not fall through to the command's default behaviour, which for `cred get`
    is printing the whole secret.
    """
    short = short or {}
    opts: Dict[str, Any] = {}
    positional: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--") and len(a) > 2:
            name, eq, inline = a[2:].partition("=")
            name = name.lower()
            if name in switches:
                opts[name] = True
            elif eq:
                # An explicit '=' means the value is whatever follows it, even
                # the empty string. Testing `inline` instead made `--prefix=`
                # a flag here and an empty prefix in the PowerShell peer.
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
    if known is not None:
        unknown = sorted(set(opts) - set(known))
        if unknown:
            raise cs.CredError(f"Unknown option '--{unknown[0]}'.",
                               ["Run 'cred help' to see what there is."], cs.EXIT_USAGE)
    return opts, positional



# ------------------------------------------------------------- commands ---
# What each verb accepts, in one table rather than transcribed at every call
# site. `known` is the point of it: read_options rejects anything not listed,
# and it used to be passed at one of fifteen call sites, so a mistyped flag was
# silently ignored on the other fourteen -- for `cred list --verfiy` that meant
# quietly not verifying. Mirrored by Get-CredCommandSpec in the PowerShell
# module, which needs it in the module for the same reason: inside a script the
# table's only interface is a process.
#
# `value` names the options that take a value; `switches` those that do not.
# Every verb accepts --project and --path unless it has no project.

_PROJECT = ("project", "path")

COMMANDS: Dict[str, Dict[str, Any]] = {
    "init":       {"switches": ("force", "yes"), "short": {"y": "yes"},
                   "value": ("provider", "recipient") + _PROJECT},
    "add":        {"switches": ("stdin", "allow-empty", "force"),
                   "value": ("user", "value", "file", "filename", "env",
                             "env-user", "desc", "description") + _PROJECT},
    "get":        {"switches": ("no-newline", "force", "check", "stat"),
                   "short": {"n": "no-newline"},
                   "value": ("field", "out", "reveal") + _PROJECT},
    "list":       {"switches": ("json", "verify"), "value": _PROJECT},
    "exec":       {"value": ("only", "except", "prefix") + _PROJECT},
    "rm":         {"switches": ("yes", "keep-definition"), "short": {"y": "yes"},
                   "value": _PROJECT},
    "env":        {"value": ("only", "except", "prefix", "format") + _PROJECT},
    "recipients": {"switches": ("yes",), "short": {"y": "yes"}, "value": _PROJECT},
    "keygen":     {"switches": ("show", "force", "protect"),
                   "value": ("provider", "path")},
    "key":        {"switches": ("force",), "value": ("backup", "provider", "path")},
    "project":    {"value": ()},
    "providers":  {"value": ()},
    "doctor":     {"switches": ("repair",), "value": _PROJECT},
    "claude":     {"switches": ("write",), "value": ("file",) + _PROJECT},
    "import":     {"switches": ("force", "dry-run"),
                   "value": ("name", "desc") + _PROJECT},
    "export":     {"switches": ("yes", "force"), "short": {"y": "yes"},
                   "value": ("only",) + _PROJECT},
}


# The spellings that mean the same verb. Here rather than only in the dispatch
# switch, so `cred set --bogus` is refused by the same table that refuses
# `cred add --bogus`.
ALIASES = {"set": "add", "remove": "rm", "delete": "rm", "check": "doctor",
           "agent": "claude", "brief": "claude", "provider": "providers",
           "newkey": "keygen"}


def command_spec(verb: str) -> Dict[str, Any]:
    """The switches, short forms and full option set one verb accepts.

    Peer of Get-CredCommandSpec in src/Cred/Public/CommandLine.ps1.
    """
    spec = COMMANDS.get(ALIASES.get(verb, verb), {})
    switches = tuple(spec.get("switches", ()))
    value = tuple(spec.get("value", ()))
    return {"switches": switches, "short": dict(spec.get("short", {})),
            "known": switches + value}


def parse_command(verb: str, argv: List[str]):
    """Parse one verb's argv against its spec. Unknown options are refused."""
    spec = command_spec(verb)
    return read_options(argv, switches=spec["switches"], short=spec["short"],
                        known=spec["known"])

# ----------------------------------------------------------------- output ---

def out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def note(text: str) -> None:
    """An aside for the human, on stderr so it cannot pollute a pipe."""
    sys.stderr.write(text + "\n")


def write_secret(value, newline: bool = True) -> None:
    """Write a secret to stdout as exact bytes.

    Goes through the buffer rather than print() so the console encoding cannot
    mangle a non-ASCII password, and so piping yields the bytes that went in.
    Takes bytes as well as text, because `cred get` hands back file content
    that must not make a round trip through str.
    """
    data = value if isinstance(value, bytes) else value.encode("utf-8")
    sys.stdout.buffer.write(data + (b"\n" if newline else b""))
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


def confirm(question: str, yes: bool = False, require_tty: bool = True,
            message: Optional[str] = None,
            next_steps: Optional[List[str]] = None) -> bool:
    """Ask the one question a destructive command needs. True means proceed.

    The peer of Confirm-CredCliAction in bin/cred-ps.ps1, and here for the same
    reason: the decision belongs to the CLI, in one place, so every destructive
    command asks it the same way and behaves the same way when nobody is there
    to answer.

    `require_tty` makes an unanswerable prompt an error rather than a silent
    yes. EOF counts as unanswerable: a Windows shell can hand us a handle that
    claims to be a terminal but has no input behind it, and that used to reach
    the user as a traceback.
    """
    if yes:
        return True
    if sys.stdin.isatty():
        # The prompt goes to stderr, like note(), so it cannot end up in a pipe
        # -- input()'s own prompt argument writes to stdout.
        sys.stderr.write(f"{question} [y/N] ")
        sys.stderr.flush()
        try:
            return input().strip().lower() in ("y", "yes")
        except EOFError:
            sys.stderr.write("\n")
    if not require_tty:
        return True
    raise cs.CredError(message or question,
                       next_steps or ["Pass --yes to confirm non-interactively."],
                       cs.EXIT_USAGE)


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
    opts, pos = parse_command("init", rest)
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
                            "If it was renamed or cloned: cred doctor",
                            "Start over (erases it): cred init --force"],
                           cs.EXIT_USAGE)

    # --force means "overwrite", and overwriting an empty store is cheap. It is
    # only a real decision when there is something to lose, so that is the only
    # time it asks -- and it names the number, because the whole failure mode is
    # someone reaching for --force to fix a stale path after a rename.
    if config_path.is_file() and opts.get("force"):
        losing = cs.existing_credential_count(root)
        if losing and not confirm(
                f"cred init --force will erase {losing} credential(s) in '{root}'.",
                yes=bool(opts.get("yes")),
                next_steps=[
                    "Nothing has been changed.",
                    "If this folder was renamed or cloned, --force is not the "
                    "fix: run 'cred doctor' here instead.",
                    "To start over anyway: cred init --force --yes"]):
            out("Cancelled.")
            return cs.EXIT_OK

    provider_name = str(opts.get("provider") or "age")
    prov = cs.get_provider(provider_name)
    available, detail = prov["test"]()
    if not available:
        raise cs.CredError(
            f"Encryption backend '{provider_name}' is not available: {detail}",
            [prov["install_hint"], "Then re-run 'cred doctor'."],
            cs.EXIT_BACKEND)

    recipients = ([r.strip() for r in str(opts["recipient"]).split(",")]
                  if opts.get("recipient") else None)
    if not recipients:
        # Was `if provider_name == "age"`. A provider that keeps its own keys
        # returns no path and is simply skipped.
        if prov.get("supports_keystore") or prov["identity_path"](None):
            ident = cs.provider_identity_path(None, provider_name)
            if not ident.is_file():
                prov["new_identity"](ident)
        recipients = [prov["recipient"](None)]

    (root / cs.CREDS_DIR).mkdir(parents=True, exist_ok=True)
    config = {"version": cs.CONFIG_VERSION, "project": name,
              "provider": provider_name, "store": prov["store_file"],
              "recipients": recipients, "credentials": {}}
    cs.write_text_atomic(config_path, cs.dump_json(config))

    project = cs.Project(root)
    with cs.StoreLock(project.creds_dir):
        cs.write_values(project, {})

    cs.write_text_atomic(root / cs.CREDS_DIR / ".gitignore",
                         "# Managed by cred. The encrypted store and the config are meant to be\n"
                         "# committed; only these transient files are not.\n"
                         ".lock\n*.tmp*\n")
    # The store is already on disk by now, so a registry failure must not throw
    # away a successful init. Report it and say how to finish the job -- the
    # alternative stranded a working store that `cred project list` denied.
    registry_error: Optional[cs.CredError] = None
    try:
        cs.register_project(name, root)
    except cs.CredError as exc:
        registry_error = exc

    out(f"Created {name} in {root}")
    out(f"  store      {project.store_path}")
    out(f"  provider   {provider_name}")
    out(f"  recipient  {', '.join(recipients)}")
    out("")
    out(f"Commit .creds/ -- it is encrypted. Then: cred add {name}/<key>")

    if registry_error is not None:
        note("")
        note(f"Warning: the store was created, but '{name}' could not be added "
             f"to the project registry:")
        note(f"  {registry_error.message}")
        note(f"Fix that, then register it with: cred project add '{root}'")
    return cs.EXIT_OK


def cmd_add(rest: List[str]) -> int:
    opts, pos = parse_command("add", rest)
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
    file_spec = opts.get("file")
    is_file = file_spec is not None and file_spec is not True

    if is_file and user:
        raise cs.CredError(
            "--file and --user cannot be combined.",
            ["A file credential is one blob of content; it has no username.",
             "If you need both, store them as two credentials."],
            cs.EXIT_USAGE)

    encoding: Optional[str] = None
    filename = ""
    if is_file:
        data = cs.read_import_file(str(file_spec), bool(opts.get("force")))
        # Byte-exact: no newline stripping, no line-ending translation. A PEM
        # that round-trips through `cred get --out` must be the same file.
        secret, encoding = cs.encode_file_content(data)
        filename = str(opts.get("filename") or Path(str(file_spec)).name)
    elif opts.get("stdin"):
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
        raise cs.CredError(
            "The file is empty." if is_file else "An empty value was given.",
            ["Provide a value, or pass --allow-empty."],
            cs.EXIT_USAGE)

    r = cs.set_credential(project, key, secret, user=user, is_file=is_file,
                          filename=filename, encoding=encoding,
                          env_secret=opts.get("env"),
                          env_user=opts.get("env-user"),
                          description=opts.get("desc") or opts.get("description"))

    out(f"{'Added' if r['created'] else 'Updated'} {project.name}/{key} ({r['kind']})")
    if is_file:
        detail = "base64" if encoding else "text"
        out(f"  {filename}, {len(data)} bytes, stored as {detail}")
        out(f"  Not injected by 'cred exec'. Read it back with: "
            f"cred get {project.name}/{key} --out <path>")
    return cs.EXIT_OK


def cmd_get(rest: List[str]) -> int:
    opts, pos = parse_command("get", rest)
    if not pos:
        raise cs.CredError("cred get <project>/<key>", [], cs.EXIT_USAGE)

    field = str(opts.get("field") or "secret")
    out_spec = opts.get("out")

    mode = cs.resolve_read_mode(reveal=opts.get("reveal"),
                                check=bool(opts.get("check")),
                                stat=bool(opts.get("stat")),
                                out=out_spec is not None)

    if out_spec is not None and out_spec is not True:
        resolved = cs.entry_view(pos[0], opts.get("project"), opts.get("path"))
        wrote = cs.export_credential_file(resolved["project"], resolved["view"],
                                          str(out_spec), bool(opts.get("force")),
                                          field)
        out(f"Wrote {wrote['file']} ({wrote['byte_count']} bytes), "
            "readable only by you.")
        out("This is plaintext on disk. Delete it when you are done.")
        return cs.EXIT_OK

    # One call, one decryption: the bytes and what they are.
    value = cs.read_value(pos[0], opts.get("project"), opts.get("path"), field)
    cs.assert_read_mode_applies(mode, value)

    # The candidate for --check comes from stdin, and only after the refusal
    # above, so a file credential does not first block on input. Whether stdout
    # is a terminal is the one thing the store cannot know for itself.
    readout = cs.apply_read_mode(
        mode, value,
        candidate=read_stdin_secret() if mode == "check" else None,
        to_terminal=sys.stdout.isatty())
    write_secret(readout["bytes"],
                 newline=readout["newline"] and not opts.get("no-newline"))
    return readout["exit_code"]


def cmd_list(rest: List[str]) -> int:
    opts, pos = parse_command("list", rest)
    project = cs.resolve_project(pos[0] if pos else opts.get("project"),
                                 opts.get("path"))
    defs = project.config.get("credentials") or {}
    values = cs.read_values(project) if opts.get("verify") else None

    keys = sorted(set(defs) | set(values or {}))
    rows = []
    for k in keys:
        d = defs.get(k) or {}
        # Ask the entry what it is rather than reading 'type' off the
        # declaration. Without --verify there is no entry to ask, so an empty
        # one still lets the definition speak for itself; with --verify the
        # store wins over a config.json that has fallen behind it.
        view = cs.resolve_entry(k, (values or {}).get(k) or {}, d)
        row = {"Project": project.name, "Key": k,
               "Type": view["kind"],
               "Environment": view["display"],
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
    opts, pos = parse_command("exec", rest)
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

    secrets, skipped = cs.environment_and_skipped(
        project, only, exclude, str(opts.get("prefix") or ""))
    if skipped:
        note(f"Not injected (file credentials): {', '.join(skipped)}. "
             f"Read one with: cred get {project.name}/{skipped[0]} --out <path>")
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
    opts, pos = parse_command("rm", rest)
    if not pos:
        raise cs.CredError("cred rm <project>/<key>", [], cs.EXIT_USAGE)

    proj_ref, key = cs.split_reference(pos[0])
    project = cs.resolve_project(opts.get("project") or proj_ref, opts.get("path"))

    if not confirm(f"Remove {project.name}/{key}?",
                   yes=bool(opts.get("yes")),
                   message="Refusing to delete without confirmation.",
                   next_steps=["Pass --yes to delete non-interactively."]):
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
    opts, pos = parse_command("env", rest)
    project = cs.resolve_project(pos[0] if pos else opts.get("project"),
                                 opts.get("path"))
    only = [s.strip() for s in str(opts["only"]).split(",")] if opts.get("only") else None
    exclude = [s.strip() for s in str(opts["except"]).split(",")] if opts.get("except") else None
    values, skipped = cs.environment_and_skipped(
        project, only, exclude, str(opts.get("prefix") or ""))
    if skipped:
        note(f"Not shown (file credentials): {', '.join(skipped)}. "
             f"Read one with: cred get {project.name}/{skipped[0]} --out <path>")

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
        opts, pos = parse_command("recipients", rest[1:])
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

    opts, pos = parse_command("recipients", rest)
    project = cs.resolve_project(pos[0] if pos else opts.get("project"),
                                 opts.get("path"))
    try:
        mine = cs.provider_for(project.config)["recipient"](project.config)
    except cs.CredError:
        mine = None
    rows = [{"Recipient": r, "IsMe": str(r == mine)}
            for r in (project.config.get("recipients") or [])]
    table(rows, ["Recipient", "IsMe"])
    return cs.EXIT_OK


def cmd_keygen(rest: List[str]) -> int:
    opts, _ = parse_command("keygen", rest)
    prov = cs.provider_for(None, opts.get("provider") or None)
    path = (Path(opts["path"]) if opts.get("path")
            else cs.provider_identity_path(None, prov["name"]))

    if opts.get("show"):
        write_secret(prov["recipient"](None))
        return cs.EXIT_OK

    # --protect means "and make sure it is wrapped", so it applies to the key
    # that is already here just as much as to one this call creates -- which is
    # what `cred-ps keygen --protect` does.
    if path.is_file() and not opts.get("force"):
        out(f"Key already exists at {path}")
        out(f"Public key: {prov['recipient'](None)}")
        if opts.get("protect"):
            return _key_protect(path, {"force": True})
        return cs.EXIT_OK

    if path.is_file() and opts.get("force"):
        import datetime
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
        backup = path.with_suffix(path.suffix + f".{stamp}.bak")
        path.replace(backup)
        cs.restrict_path(backup)
        out(f"Existing key moved to {backup}")

    created, pub = prov["new_identity"](path)
    out(f"Created a new key at {created}")
    out(f"Public key: {pub}")

    # The wrap warns about the missing backup itself, so the "back this file
    # up" line below would contradict it -- there is no such file any more.
    if opts.get("protect"):
        return _key_protect(path, {"force": True})

    out("")
    out("Back this file up. Without it you cannot read any store encrypted to it.")
    return cs.EXIT_OK


def cmd_key(rest: List[str]) -> int:
    sub = rest[0].lower() if rest else ""
    opts, _ = parse_command("key", rest[1:] if rest else [])
    # Wrapping is meaningless for a provider that keeps its own keys, and
    # silently wrapping age's key for such a project would be worse than a
    # refusal.
    prov = cs.assert_keystore_supported(None, opts.get("provider") or None)
    path = cs.provider_identity_path(None, prov["name"])

    if sub == "protect":
        return _key_protect(path, opts)
    if sub in ("unprotect", "unwrap"):
        return _key_unprotect(path)

    out(f"path        {path}")
    out(f"exists      {path.is_file()}")
    out(f"protection  {cs.identity_protection(path)}")
    out(f"keystore    {cs.keystore_name() if cs.keystore_available() else 'none available here'}")
    if path.is_file():
        try:
            out(f"public key  {prov['recipient'](None)}")
        except cs.CredError:
            pass
    return cs.EXIT_OK


def _key_protect(path, opts) -> int:
    """Wrap the key with the OS keystore.

    Only the key is bound to this account. The store stays plain age, so it
    still travels with the code and still opens on Linux.
    """
    if not cs.keystore_available():
        raise cs.keystore_unavailable()
    if not path.is_file():
        raise cs.CredError(f"No key at '{path}' to wrap.",
                           ["Create one first: cred keygen"], cs.EXIT_KEY)
    if cs.identity_is_wrapped(path):
        out(f"Key was already wrapped ({cs.keystore_name()}).")
        return cs.EXIT_OK

    text = cs.read_text(path)

    backup = opts.get("backup")
    if backup and backup is not True:
        backup_path = Path(str(backup))
        if backup_path.exists() and not opts.get("force"):
            raise cs.CredError(f"'{backup_path}' already exists.",
                               ["Choose another path, or pass --force."],
                               cs.EXIT_USAGE)
        cs.write_private_text(backup_path, text)
        out(f"Unwrapped key copied to '{backup_path}'. That file is the key -- "
            "store it somewhere safe and offline.")
    else:
        out("No --backup given. If this account or machine is lost, a wrapped "
            "key cannot be recovered.")

    target = path.parent / cs.WRAPPED_IDENTITY_NAME
    cs.write_private_text(target, cs.wrap_identity(text))

    # Prove the wrapped copy opens before removing the original.
    if cs.identity_text(target).strip() != text.strip():
        target.unlink(missing_ok=True)
        raise cs.CredError(
            "The wrapped key did not read back identically, so nothing was changed.",
            [f"Your original key at '{path}' is untouched. Please report this."],
            cs.EXIT_KEY)

    if path != target:
        path.unlink()
    out(f"Key wrapped with {cs.keystore_name()} at {target}")
    return cs.EXIT_OK


def _key_unprotect(path) -> int:
    if not cs.identity_is_wrapped(path):
        out("Key was not wrapped.")
        return cs.EXIT_OK

    text = cs.identity_text(path)
    target = path.parent / "identity.txt"
    cs.write_private_text(target, text)
    path.unlink()
    out(f"Key unwrapped to {target}")
    out(f"'{target}' is now a plaintext key, protected only by file permissions.")
    return cs.EXIT_OK


def cmd_project(rest: List[str]) -> int:
    sub = rest[0].lower() if rest else "list"
    if sub == "add":
        # The way back from an init whose registry write failed after the store
        # was already written. The name comes from the project's own config,
        # not from the folder, so the registry agrees with the store.
        target = Path(rest[1]).expanduser().resolve() if len(rest) > 1 else Path.cwd()
        root = cs.find_project_root(target) or target
        if not (root / cs.CREDS_DIR / cs.CONFIG_NAME).is_file():
            raise cs.CredError(f"'{root}' has no .creds/config.json.",
                               [f"Create one with: cd '{root}'; cred init"],
                               cs.EXIT_NOT_FOUND)
        project = cs.Project(root)
        cs.register_project(project.name, root)
        out(f"Registered {project.name} at {root}.")
        return cs.EXIT_OK

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
    opts, pos = parse_command("doctor", rest)

    if opts.get("repair"):
        # On stderr, so the table on stdout stays byte-identical to cred-ps's.
        home, failed = cs.repair_permissions()
        if failed:
            note(f"Could not tighten permissions on {len(failed)} path(s) under '{home}':")
            for f in failed:
                note(f"  {f}")
        else:
            note(f"Re-applied permissions under {home}.")

    rows = cs.health_rows(pos[0] if pos else opts.get("project"), opts.get("path"))
    table(rows, ["Check", "Status", "Detail", "Fix"])
    return cs.EXIT_GENERAL if any(r["Status"] == "Fail" for r in rows) else cs.EXIT_OK


def cmd_providers(rest: List[str]) -> int:
    rows = []
    for name in sorted(cs.PROVIDERS):
        prov = cs.PROVIDERS[name]
        available, detail = prov["test"]()
        rows.append({"Name": name, "Available": str(available),
                     "StoreFile": prov["store_file"], "Detail": detail})
    table(rows, ["Name", "Available", "StoreFile", "Detail"])
    return cs.EXIT_OK


def cmd_claude(rest: List[str]) -> int:
    opts, pos = parse_command("claude", rest)
    project = cs.resolve_project(pos[0] if pos else opts.get("project"),
                                 opts.get("path"))
    brief = build_agent_brief(project)

    if not opts.get("write"):
        sys.stdout.write(brief)
        return cs.EXIT_OK

    target = Path(opts["file"]) if opts.get("file") else project.root / "CLAUDE.md"
    block = f"{BRIEF_BEGIN}\n{brief}{BRIEF_END}\n"
    existing = cs.read_text(target) if target.is_file() else ""

    import re
    pattern = re.compile(re.escape(BRIEF_BEGIN) + ".*?" + re.escape(BRIEF_END) + r"\r?\n?",
                         re.DOTALL)
    if pattern.search(existing):
        updated = pattern.sub(lambda _m: block, existing)
    elif existing:
        updated = existing.rstrip() + "\n\n" + block
    else:
        updated = block

    cs.write_text_atomic(target, updated)
    n = len(project.config.get("credentials") or {})
    out(f"Wrote the cred block for {project.name} into {target} "
        f"({n} credential(s)).")
    return cs.EXIT_OK


BRIEF_BEGIN = "<!-- cred:begin -->"
BRIEF_END = "<!-- cred:end -->"


def build_agent_brief(project) -> str:
    """Markdown describing what exists, never a value.

    The advice is deliberate: prefer `cred exec`, which hands the secret to a
    child process the agent cannot read, over `cred get`, which puts it in the
    agent's transcript.
    """
    defs = project.config.get("credentials") or {}
    lines = [
        "## Credentials",
        "",
        "This repository's secrets live encrypted in `.creds/` and are handed "
        "out by the `cred` CLI. Never write a secret into a file, a commit, or "
        "your reply.",
        "",
    ]
    if not defs:
        lines.append(f"_No credentials are defined yet. Add one with_ "
                     f"`cred add {project.name}/<key>`.")
    else:
        lines.append("| Credential | Type | Environment variables | What it is |")
        lines.append("| --- | --- | --- | --- |")
        for key in sorted(defs):
            d = defs[key]
            view = cs.resolve_entry(key, {}, d)
            if view["kind"] == "file":
                env = f"none — file `{view['filename'] or key}`"
            else:
                env = "`" + ", ".join(view["env_names"].values()) + "`"
            lines.append(f"| `{project.name}/{key}` | {view['kind']} "
                         f"| {env} | {d.get('description', '')} |")
    has_files = any(cs.resolve_entry(k, {}, d or {})["kind"] == "file"
                    for k, d in defs.items())
    lines += [
        "",
        "**Preferred — run a command with the secrets injected.** The value "
        "never enters this conversation:",
        "",
        "```",
        f"cred exec {project.name} -- <command> [args]",
        "```",
        "",
        "**Only when a value must actually be read** (and then treat the output "
        "as poison — do not echo it back):",
        "",
        "```",
        f"cred get {project.name}/<key>",
        "```",
        "",
        "**To see what exists without decrypting anything:**",
        "",
        "```",
        f"cred list {project.name}",
        "```",
        "",
    ]
    if has_files:
        lines += [
            "**File credentials** (private keys, certificates) are not injected "
            "by `cred exec`, because their content is not usable as an "
            "environment variable. When a command genuinely needs one as a "
            "file on disk:",
            "",
            "```",
            f"cred get {project.name}/<key> --out <path>",
            "```",
            "",
            "That writes plaintext to disk. Only do it when a tool requires a "
            "path, tell the user you did, and delete the file afterwards.",
            "",
        ]
    lines += [
        "If `cred` reports that it cannot decrypt, stop and tell the user: their "
        "key is missing or is not a recipient. Do not attempt to work around it.",
        "",
    ]
    return "\n".join(lines)


def cmd_import(rest: List[str]) -> int:
    opts, pos = parse_command("import", rest)
    if not pos:
        raise cs.CredError("cred import <file-or-folder> [--name <key>]",
                           ["Run 'cred help' for the full surface."], cs.EXIT_USAGE)

    src = Path(pos[0])
    if not src.exists():
        raise cs.CredError(f"'{src}' does not exist.",
                           ["Point at a credential file or a folder of them."],
                           cs.EXIT_NOT_FOUND)

    project = cs.resolve_project(opts.get("project"), opts.get("path"))
    dry = bool(opts.get("dry-run"))

    if src.is_dir():
        files = sorted(f for f in src.iterdir()
                       if f.is_file() and f.suffix.lower() in
                       (".xml", ".clixml", ".txt", ".cred"))
    else:
        files = [src]

    if not files:
        out(f"No credential files found in '{src}' "
            "(looking for *.xml, *.clixml, *.txt, *.cred).")
        return cs.EXIT_OK

    rows = []
    for f in files:
        try:
            parsed = _read_legacy_credential(f)
        except cs.CredError as exc:
            out(f"Skipping '{f.name}': {exc.message}")
            continue
        if not parsed:
            out(f"Skipping '{f.name}': not a recognised credential file.")
            continue
        user, secret = parsed

        raw = (opts["name"] if opts.get("name") and len(files) == 1
               else f.name[:-len(f.suffix)])
        if raw.endswith(".cred"):
            raw = raw[:-5]
        key = _sanitise_key(raw, f.name)

        if key in (project.config.get("credentials") or {}) and not opts.get("force"):
            out(f"Skipping '{key}': it already exists. Pass --force to overwrite.")
            rows.append({"Key": key, "Action": "skipped", "Source": f.name})
            continue

        if dry:
            rows.append({"Key": key, "Action": "would import", "Source": f.name})
            continue

        existed = key in (project.config.get("credentials") or {})
        cs.set_credential(project, key, secret, user=user,
                          description=opts.get("desc"))
        rows.append({"Key": key, "Source": f.name,
                     "Action": "replaced" if existed else "imported"})

    if not rows:
        out("Nothing to import.")
    else:
        table(rows, ["Key", "Action", "Source"])
    return cs.EXIT_OK


def _sanitise_key(raw: str, source: str) -> str:
    import re
    if cs.valid_key_name(raw):
        return raw
    clean = re.sub(r"[^A-Za-z0-9._-]", "-", raw)
    clean = re.sub(r"^[^A-Za-z0-9]+", "", clean)
    if not cs.valid_key_name(clean):
        raise cs.CredError(
            f"Cannot derive a usable credential name from '{source}'.",
            [f"Import it on its own and name it: "
             f"cred import '{source}' --name <key>"],
            cs.EXIT_USAGE)
    return clean


def _read_legacy_credential(path: Path):
    """(user, secret) from an Export-Clixml file or ConvertFrom-SecureString hex."""
    if path.suffix.lower() in (".xml", ".clixml"):
        return cs.read_clixml_credential(path)

    text = cs.read_text(path).strip()
    import re
    if not re.fullmatch(r"[0-9a-fA-F]+", text or "x") or len(text) < 32:
        return None
    return None, cs.dpapi_hex_to_text(text)


def cmd_export(rest: List[str]) -> int:
    opts, pos = parse_command("export", rest)
    if not pos:
        raise cs.CredError("cred export <folder> [--only <a,b>]", [], cs.EXIT_USAGE)

    if not cs.is_windows() and not opts.get("force"):
        raise cs.CredError(
            "Off Windows there is no DPAPI, so these files would hold the "
            "secret in plain text.",
            ["Use cred exec or the PowerShell module instead, or",
             "pass --force if you genuinely want plaintext files on disk."],
            cs.EXIT_USAGE)

    project = cs.resolve_project(opts.get("project"), opts.get("path"))
    only = [s.strip() for s in str(opts["only"]).split(",")] if opts.get("only") else None
    dest = Path(pos[0])
    dest.mkdir(parents=True, exist_ok=True)
    cs.restrict_path(dest)

    # Unlike rm, a non-interactive export proceeds: it is reached from migration
    # scripts, and refusing there would be a behaviour change, not a safety win.
    if not confirm(f"Write credential files into '{dest}'?",
                   yes=bool(opts.get("yes")), require_tty=False):
        out("Cancelled.")
        return cs.EXIT_OK

    values = cs.read_values(project)
    defs = project.config.get("credentials") or {}
    rows = []
    for key in sorted(values):
        if only and key not in only:
            continue
        view = cs.resolve_entry(key, values[key], defs.get(key))
        # A file credential has no PSCredential shape, so it goes back out as
        # the file it came in as -- which is what anyone exporting one wants.
        if view["kind"] == "file":
            target = dest / (view["filename"] or key)
            cs.write_private_file(target, cs.entry_bytes(view, project_name=project.name))
            rows.append({"Key": key, "UserName": "-", "File": str(target)})
            continue
        user = view["fields"].get("user") or key
        target = dest / f"{key}.cred.xml"
        cs.write_clixml_credential(target, user, str(view["fields"]["secret"]))
        rows.append({"Key": key, "UserName": user, "File": str(target)})

    table(rows, ["Key", "UserName", "File"])
    if rows:
        out(f"{len(rows)} credential file(s) written to '{dest}'. "
            "Delete them once the migration is done.")
    return cs.EXIT_OK

# --------------------------------------------------------------- dispatch ---

def dispatch(argv: List[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(USAGE)
        return cs.EXIT_OK

    head, tail = split_argv(argv)
    verb = (head[0] if head else "").lower()
    rest = head[1:]

    if verb in ("version", "--version", "-v"):
        out(f"cred 1.1.0  (Python {sys.version.split()[0]} on {sys.platform})")
        return cs.EXIT_OK

    handlers = {
        "init": cmd_init, "add": cmd_add, "set": cmd_add, "get": cmd_get,
        "list": cmd_list, "rm": cmd_rm, "remove": cmd_rm, "delete": cmd_rm,
        "env": cmd_env, "recipients": cmd_recipients, "keygen": cmd_keygen,
        "key": cmd_key, "project": cmd_project, "doctor": cmd_doctor,
        "check": cmd_doctor, "providers": cmd_providers, "provider": cmd_providers,
        "claude": cmd_claude, "agent": cmd_claude, "brief": cmd_claude,
        "import": cmd_import, "export": cmd_export,
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
