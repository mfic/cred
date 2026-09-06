"""Dump the Python implementation's view of a fixture store, as JSON.

Not part of the shipped CLI. It exists so tests/Conformance.Tests.ps1 can hold
both implementations to the same fixed bytes, instead of round-tripping them
through each other -- a round-trip passes whenever both sides are wrong in the
same way, which is how four format divergences survived undetected.

    python tests/conformance.py entries     <fixture-dir>
    python tests/conformance.py environment <fixture-dir>
    python tests/conformance.py store-name  <fixture-dir>
    python tests/conformance.py restrict    <path>
    python tests/conformance.py canonical   <compact-json-file>
"""
import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))
import cred_store as cs  # noqa: E402


def emit(obj):
    """Exact UTF-8 bytes on stdout.

    The fixtures carry non-ASCII on purpose, and a Windows console code page
    must not get a vote in whether they can be compared.
    """
    text = json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True)
    sys.stdout.buffer.write(text.encode("utf-8") + b"\n")
    sys.stdout.buffer.flush()


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    mode, fixture = argv[0], Path(argv[1]).resolve()

    # Not a project layout: a bare path whose permissions are the subject.
    if mode == "restrict":
        emit({"ok": cs.restrict_path(fixture)})
        return 0

    # Re-serialise a compact document into the canonical form. The document
    # lives in the fixture rather than in this file so that both implementations
    # format the same input rather than each formatting its own transcription.
    if mode == "canonical":
        with open(fixture, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8"))
        sys.stdout.buffer.write(cs.dump_json(doc).encode("utf-8"))
        sys.stdout.buffer.flush()
        return 0

    # Every fixture is a real project layout, so nothing here needs to know
    # more about the on-disk shape than the implementation does.
    os.environ["CRED_IDENTITY_FILE"] = str(fixture.parent / "identity.txt")
    proj = cs.Project(fixture)

    if mode == "store-name":
        emit({"store": proj.config["store"]})
        return 0

    if mode == "environment":
        variables, skipped = cs.environment_and_skipped(proj)
        emit({"variables": variables, "skipped": skipped})
        return 0

    if mode != "entries":
        raise SystemExit(f"unknown mode {mode!r}")

    values = cs.read_values(proj)
    defs = proj.config.get("credentials") or {}
    out = {}
    for key in sorted(set(values) | set(defs)):
        view = cs.resolve_entry(key, values.get(key) or {}, defs.get(key))
        out[key] = {
            "kind": view["kind"],
            "filename": view["filename"],
            "is_binary": view["is_binary"],
            "env": view["env_vars"],
            "display": view["display"],
            "bytes_b64": base64.b64encode(
                cs.entry_bytes(view, project_name=proj.name)).decode("ascii"),
        }
    emit(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
