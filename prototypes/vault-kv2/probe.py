"""PROTOTYPE -- throwaway harness for mfic/cred#11. Run: python probe.py

Drives vault_kv2.py against the live Vault and prints the wire shape of every
step, so the spec can quote observed bytes instead of documented behaviour.
Nothing here is shipped; the line count that matters is vault_kv2.py's.

Everything it touches lives under the scratch mount `cred/test`, which #2
provisioned to be churned freely.
"""

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vault_kv2 import VaultError, VaultKV2  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
except Exception:
    pass

ADDR = os.environ.get("VAULT_ADDR", "https://vault.qn.questnet.eu")
MOUNT = "cred/test"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CRED = [sys.executable, os.path.join(REPO, "python", "cred.py")]

PREFIX = "probe-%d" % int(time.time())


def cred_get(key):
    """A value out of the localhost store. The name is on the command line;
    the value only ever comes back on a pipe."""
    out = subprocess.run(CRED + ["get", key, "-n"], capture_output=True, check=True)
    return out.stdout.decode("utf-8")


def step(n, title):
    print("\n" + "=" * 72)
    print("%s  %s" % (n, title))
    print("=" * 72)


def show(label, fn):
    """Run fn, printing either its value or the verbatim error response."""
    try:
        value = fn()
    except VaultError as exc:
        print("  %-38s -> %s %s" % (label, exc.status, exc.body.decode("utf-8", "replace")))
        return exc
    print("  %-38s -> %s" % (label, value))
    return value


def raw(client, label, method, path):
    """A request whose *status and body* are the finding, exactly as received."""
    try:
        status, body = client.request(method, path)
    except VaultError as exc:
        status, body = exc.status, exc.body
    except Exception as exc:  # DNS, TLS, timeout -- a finding too, not a crash
        print("  %s\n    %s %s\n    !! %s: %s" % (label, method, path, type(exc).__name__, exc))
        return None, b""
    print("  %s\n    %s %s\n    %s %s"
          % (label, method, path, status, body.decode("utf-8", "replace")))
    return status, body


def main():
    client = VaultKV2(ADDR, MOUNT)

    step("0", "Anchor: what this Vault actually is")
    for path in ("sys/health", "sys/seal-status"):
        raw(client, path, "GET", path)

    step("1", "AppRole login (no credential on any command line)")
    role_id = cred_get("localhost/vault-role-id")
    secret_id = cred_get("localhost/vault-secret-id")
    print("  role_id   %d chars, from localhost store via pipe" % len(role_id))
    print("  secret_id %d chars, from localhost store via pipe" % len(secret_id))
    auth = client.login_approle(role_id, secret_id)
    print("  token     %d chars, orphan=%s, ttl=%ss, policies=%s"
          % (len(auth["client_token"]), auth.get("orphan"),
             auth.get("lease_duration"), auth.get("token_policies")))

    step("2", "The mount reports its own KV version")
    admin = VaultKV2(ADDR, MOUNT, token=cred_get("localhost/vault-admin"))
    raw(admin, "sys/mounts/%s/tune" % MOUNT, "GET", "sys/mounts/%s/tune" % MOUNT)
    try:
        mounts = admin._json("GET", "sys/mounts")
        entry = mounts.get("data", mounts).get(MOUNT + "/", {})
        print("  type=%s options=%s" % (entry.get("type"), entry.get("options")))
    except VaultError as exc:
        print("  sys/mounts -> %s %s" % (exc.status, exc.body.decode("utf-8", "replace")))

    key = "%s/db" % PREFIX
    step("3", "cas=0 twice: create-only semantics")
    show("write cas=0 (first)", lambda: client.write(key, {"secret": "one"}, cas=0))
    show("write cas=0 (again)", lambda: client.write(key, {"secret": "two"}, cas=0))

    step("4", "One GET returns value and version together")
    show("read", lambda: client.read(key))

    step("5", "Stale cas -- the load-bearing error string")
    show("write cas=0 against version 1", lambda: client.write(key, {"secret": "x"}, cas=0))
    show("write cas=99 against version 1", lambda: client.write(key, {"secret": "x"}, cas=99))

    step("6", "cas omitted entirely, under cas_required=true")
    show("write with no cas", lambda: client.write(key, {"secret": "x"}))

    step("7", "LIST a project prefix")
    show("write second key", lambda: client.write("%s/api" % PREFIX, {"secret": "a"}, cas=0))
    show("list %s/" % PREFIX, lambda: client.list(PREFIX))
    show("list mount root", lambda: client.list())

    step("8", "What the cred-test policy can actually do")
    raw(admin, "the policy as provisioned", "GET", "sys/policies/acl/cred-test")

    step("8b", "The three absence states on the wire")
    # undelete and destroy are run as admin: the AppRole policy denies them
    # (see step 8), which is itself a finding for #10 but must not stop the
    # absence states being observed.
    raw(client, "present", "GET", "%s/data/%s" % (MOUNT, key))
    show("soft-delete latest (approle)", lambda: client.delete(key))
    raw(client, "soft-deleted", "GET", "%s/data/%s" % (MOUNT, key))
    show("undelete v1 (approle)", lambda: client.undelete(key, [1]))
    show("undelete v1 (admin)", lambda: admin.undelete(key, [1]))
    raw(client, "undeleted", "GET", "%s/data/%s" % (MOUNT, key))
    show("destroy v1 (approle)", lambda: client.destroy(key, [1]))
    show("destroy v1 (admin)", lambda: admin.destroy(key, [1]))
    raw(client, "destroyed", "GET", "%s/data/%s" % (MOUNT, key))
    raw(client, "never existed", "GET", "%s/data/%s/no-such-key" % (MOUNT, PREFIX))

    step("9", "cas=0 against a soft-deleted and a destroyed path")
    show("write cas=0 onto destroyed path", lambda: client.write(key, {"secret": "z"}, cas=0))
    soft = "%s/soft" % PREFIX
    show("create soft", lambda: client.write(soft, {"secret": "s"}, cas=0))
    show("soft-delete it", lambda: client.delete(soft))
    show("write cas=0 onto soft-deleted", lambda: client.write(soft, {"secret": "s2"}, cas=0))

    step("10", "Version numbering after erasing the metadata")
    show("erase %s (approle)" % key, lambda: client.erase(key))
    show("erase %s (admin)" % key, lambda: admin.erase(key))
    show("write cas=0 after erase", lambda: client.write(key, {"secret": "fresh"}, cas=0))

    step("11", "Non-ASCII and awkward values, byte-exact through urllib")
    awkward = {
        "secret": "tok-äöü-\U0001f511",
        "user": "a/b c  d",
        "encoding": "utf-8",
    }
    wkey = "%s/awkward" % PREFIX
    show("write", lambda: client.write(wkey, awkward, cas=0))
    got, version = client.read(wkey)
    print("  read back v%s" % version)
    for field, sent in awkward.items():
        back = got.get(field)
        print("    %-9s %-14s sent=%r back=%r"
              % (field, "IDENTICAL" if back == sent else "DIFFERENT", sent, back))
    print("    utf-8 bytes  sent=%r\n                 back=%r"
          % (awkward["secret"].encode("utf-8"), str(got.get("secret")).encode("utf-8")))

    step("12", "403 next to 404, from a deliberately insufficient policy")
    try:
        admin.request("PUT", "sys/policies/acl/cred-probe-nothing")
    except VaultError:
        pass
    admin._json("PUT", "sys/policies/acl/cred-probe-nothing",
                {"policy": 'path "cred/nowhere/*" { capabilities = ["read"] }'})
    weak_auth = admin._json("POST", "auth/token/create",
                            {"policies": ["cred-probe-nothing"], "ttl": "5m",
                             "no_parent": True})
    weak = VaultKV2(ADDR, MOUNT, token=weak_auth["auth"]["client_token"])
    raw(weak, "existing secret, no capability", "GET", "%s/data/%s" % (MOUNT, wkey))
    raw(weak, "nonexistent secret, no capability", "GET", "%s/data/%s/ghost" % (MOUNT, PREFIX))
    raw(weak, "LIST, no capability", "LIST", "%s/metadata/%s" % (MOUNT, PREFIX))
    raw(client, "nonexistent secret, WITH capability", "GET", "%s/data/%s/ghost" % (MOUNT, PREFIX))

    step("13", "Does urllib re-send X-Vault-Token through a 302?")
    public = VaultKV2("https://vault.questnet.eu", MOUNT, token="hvs.CANARY-NOT-A-REAL-TOKEN")
    raw(public, "public address, redirects disabled", "GET", "sys/health")

    step("14", "Cleanup")
    for name in (key, soft, wkey, "%s/api" % PREFIX):
        show("erase %s" % name, lambda n=name: admin.erase(n))

    print("\nprefix used: %s" % PREFIX)


if __name__ == "__main__":
    main()
