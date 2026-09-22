"""PROTOTYPE -- throwaway. Which capabilities does each KV v2 operation need?

The cred-test policy from #2 turned out to deny undelete and destroy (see
transcript.txt step 8b). Rather than infer the fix from the docs, this mints a
throwaway token per candidate policy and finds out which grant lets each
operation through. Output is the minimal policy for #10.

Run: python prototypes/vault-kv2/policy_probe.py
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vault_kv2 import VaultError, VaultKV2  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
except Exception:
    pass

ADDR = "https://vault.qn.questnet.eu"
MOUNT = "cred/test"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def cred_get(key):
    out = subprocess.run([sys.executable, os.path.join(REPO, "python", "cred.py"),
                          "get", key, "-n"], capture_output=True, check=True)
    return out.stdout.decode("utf-8")


admin = VaultKV2(ADDR, MOUNT, token=cred_get("localhost/vault-admin"))


def token_for(grants):
    """A fresh token holding exactly `grants` -- {subpath: [capabilities]}."""
    policy = "\n".join('path "%s/%s" { capabilities = %s }'
                       % (MOUNT, sub, str(list(caps)).replace("'", '"'))
                       for sub, caps in grants.items())
    admin._json("PUT", "sys/policies/acl/cred-capprobe", {"policy": policy})
    auth = admin._json("POST", "auth/token/create",
                       {"policies": ["cred-capprobe"], "ttl": "2m", "no_parent": True})
    return VaultKV2(ADDR, MOUNT, token=auth["auth"]["client_token"])


# Each operation, and the single grant we believe it needs.
# fresh=True means the key is recreated before the attempt.
OPS = [
    ("create a secret",        {"data/*": ["create"]},      "create"),
    ("update a secret",        {"data/*": ["update"]},      "update"),
    ("read a secret",          {"data/*": ["read"]},        "read"),
    ("soft-delete latest",     {"data/*": ["delete"]},      "del_latest"),
    ("soft-delete a version",  {"delete/*": ["update"]},    "del_version"),
    ("undelete a version",     {"undelete/*": ["update"]},  "undelete"),
    ("destroy a version",      {"destroy/*": ["update"]},   "destroy"),
    ("list keys",              {"metadata/*": ["list"]},    "list"),
    ("read metadata",          {"metadata/*": ["read"]},    "read_meta"),
    ("erase all history",      {"metadata/*": ["delete"]},  "erase"),
    ("write metadata (new)",   {"metadata/*": ["update"]},  "write_meta_new"),
    ("write metadata (new)",   {"metadata/*": ["create"]},  "write_meta_new"),
    ("write metadata (new)",   {"metadata/*": ["create", "update"]}, "write_meta_new"),
    ("write metadata (exists)", {"metadata/*": ["update"]}, "write_meta_old"),
]

KEY = "capprobe/k"


def reset(with_metadata=False):
    """A known starting point: one secret at version 2, nothing deleted."""
    try:
        admin.erase(KEY)
    except VaultError:
        pass
    # the mount is cas_required=true, so even setup writes carry a cas
    admin.write(KEY, {"secret": "a"}, cas=0)
    admin.write(KEY, {"secret": "b"}, cas=1)
    if with_metadata:
        admin.request("POST", "%s/metadata/%s" % (MOUNT, KEY), {"max_versions": 9})


def attempt(client, op):
    if op == "create":
        # create against a path with no metadata entry at all
        try:
            admin.erase(KEY)
        except VaultError:
            pass
        return client.write(KEY, {"secret": "new"}, cas=0)
    if op == "update":
        return client.write(KEY, {"secret": "c"}, cas=2)
    if op == "read":
        return client.read(KEY)[1]
    if op == "del_latest":
        return client.delete(KEY) or "ok"
    if op == "del_version":
        return client.delete(KEY, [1]) or "ok"
    if op == "undelete":
        admin.delete(KEY, [1])
        return client.undelete(KEY, [1]) or "ok"
    if op == "destroy":
        return client.destroy(KEY, [1]) or "ok"
    if op == "list":
        return client.list("capprobe")
    if op == "read_meta":
        return "v%s" % client.metadata(KEY)["current_version"]
    if op == "erase":
        return client.erase(KEY) or "ok"
    if op == "write_meta_new":
        fresh = "capprobe/fresh"
        try:
            admin.erase(fresh)
        except VaultError:
            pass
        return client.request("POST", "%s/metadata/%s" % (MOUNT, fresh),
                              {"max_versions": 5})[0]
    if op == "write_meta_old":
        return client.request("POST", "%s/metadata/%s" % (MOUNT, KEY),
                              {"max_versions": 5})[0]
    raise AssertionError(op)


print("Each row: one operation, attempted with ONLY the grant shown.\n")
print("  %-26s %-40s %s" % ("operation", "grant", "result"))
print("  " + "-" * 84)
for label, grants, op in OPS:
    reset(with_metadata=(op == "write_meta_old"))
    client = token_for(grants)
    grant_text = ", ".join("%s %s" % (k, "+".join(v)) for k, v in grants.items())
    try:
        value = attempt(client, op)
        print("  %-26s %-40s ALLOWED (%s)" % (label, grant_text, value))
    except VaultError as exc:
        body = exc.body.decode("utf-8", "replace")
        short = "permission denied" if "permission denied" in body else body[:60]
        print("  %-26s %-40s %s %s" % (label, grant_text, exc.status, short))

try:
    admin.erase(KEY)
    admin.erase("capprobe/fresh")
except VaultError:
    pass
admin.request("DELETE", "sys/policies/acl/cred-capprobe")
print("\ncleaned up: capprobe keys and the cred-capprobe policy")
