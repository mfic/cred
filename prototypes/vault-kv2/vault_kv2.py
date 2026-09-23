"""PROTOTYPE -- throwaway, not shipped code. See prototypes/vault-kv2/README.md.

A stdlib-only HashiCorp Vault KV v2 client. This file *is* the claim under test
for mfic/cred#11: map decision 7 commits to `urllib.request` with no dependency,
and the honest measure of that commitment is how much code it takes. So the
probe harness lives next door in probe.py, and nothing in here exists for the
probe's convenience -- every line would have to be written for real.
"""

import json
import urllib.error
import urllib.request


class VaultError(Exception):
    """A non-2xx response, with the wire bytes kept intact.

    Keeping `body` as bytes rather than a parsed dict is the whole point: the
    CAS conflict is separable from a malformed request only by matching an
    undocumented string, so the caller needs what was actually sent.
    """

    def __init__(self, status, body, url):
        self.status = status
        self.body = body
        self.url = url
        super().__init__("%s %s: %r" % (status, url, body))

    @property
    def errors(self):
        """The `errors` array, or None if the body was not the usual envelope."""
        try:
            return json.loads(self.body).get("errors")
        except Exception:
            return None


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A 3xx is a configuration error, never something to follow.

    Following one re-sends X-Vault-Token to wherever it points -- observed on
    both PowerShell editions in #4, and the reason Cloudflare Access has to be
    a hard error rather than a login flow.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class VaultKV2:
    def __init__(self, addr, mount, token=None, timeout=10, headers=None):
        self.addr = addr.rstrip("/")
        self.mount = mount.strip("/")
        self.token = token
        self.timeout = timeout
        # Extra headers as a parameter, not X-Vault-Token hardcoded as the only
        # one: what stage 2 (Cloudflare Access) needs, per the map's Out of scope.
        self.headers = dict(headers or {})
        self._opener = urllib.request.build_opener(_NoRedirects)

    def request(self, method, path, body=None):
        """(status, raw bytes). Raises VaultError on any non-2xx, 3xx included."""
        url = "%s/v1/%s" % (self.addr, path.lstrip("/"))
        data = None
        if body is not None:
            # ensure_ascii=False puts real UTF-8 on the wire rather than \uXXXX
            # escapes, so a non-ASCII round trip tests the transport and not
            # just JSON's escaping.
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("X-Vault-Token", self.token)
        for name, value in self.headers.items():
            req.add_header(name, value)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            raise VaultError(exc.code, exc.read(), url) from None

    def _json(self, method, path, body=None):
        _, raw = self.request(method, path, body)
        return json.loads(raw) if raw else {}

    def login_approle(self, role_id, secret_id, mount="approle"):
        """Log in and keep the token. Returns the whole `auth` block."""
        out = self._json("POST", "auth/%s/login" % mount,
                         {"role_id": role_id, "secret_id": secret_id})
        self.token = out["auth"]["client_token"]
        return out["auth"]

    def read(self, key, version=None):
        """(value, version) in one request. Raises VaultError if absent."""
        query = "?version=%d" % version if version else ""
        out = self._json("GET", "%s/data/%s%s" % (self.mount, key, query))
        return out["data"]["data"], out["data"]["metadata"]["version"]

    def write(self, key, value, cas=None):
        """Write, returning the new version.

        `cas` is the version the secret must already be at. 0 means *no
        metadata entry exists*, which is not the same as "absent" -- a
        soft-deleted or destroyed path still has one.
        """
        body = {"data": value}
        if cas is not None:
            body["options"] = {"cas": cas}
        out = self._json("POST", "%s/data/%s" % (self.mount, key), body)
        return out["data"]["version"]

    def list(self, prefix=""):
        path = ("%s/metadata/%s" % (self.mount, prefix)).rstrip("/")
        return self._json("LIST", path)["data"]["keys"]

    def metadata(self, key):
        return self._json("GET", "%s/metadata/%s" % (self.mount, key))["data"]

    def delete(self, key, versions=None):
        """Soft-delete. No versions means the latest."""
        if versions is None:
            self.request("DELETE", "%s/data/%s" % (self.mount, key))
        else:
            self.request("POST", "%s/delete/%s" % (self.mount, key),
                         {"versions": versions})

    def undelete(self, key, versions):
        self.request("POST", "%s/undelete/%s" % (self.mount, key),
                     {"versions": versions})

    def destroy(self, key, versions):
        self.request("POST", "%s/destroy/%s" % (self.mount, key),
                     {"versions": versions})

    def erase(self, key):
        """Drop the path and its whole history -- the only thing that resets
        version numbering."""
        self.request("DELETE", "%s/metadata/%s" % (self.mount, key))
