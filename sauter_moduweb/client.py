"""HTTP client for Sauter moduWeb-style building-automation web front ends.

Some building controllers expose their data only through a login-protected
web UI (no BACnet).  This client logs in with a session cookie and scrapes
the point tables (name / value / unit) out of the HTML.

Security notes
--------------
* Credentials are read from the environment (MODUWEB_USER / MODUWEB_PASS),
  never from code or files in the repository.
* The host is mandatory (argument or MODUWEB_HOST); there is no default.
* Plain HTTP is allowed only for private/loopback addresses; anything else
  requires ``https=True``.
* Redirects are not followed off-host.

Discovery CLI::

    MODUWEB_HOST=192.0.2.20 MODUWEB_USER=... MODUWEB_PASS=... python -m sauter_moduweb.client
    ... python -m sauter_moduweb.client /some/page
"""
from __future__ import annotations

import http.cookiejar
import ipaddress
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 10


class ModuWebError(Exception):
    pass


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(req.full_url).netloc:
            raise ModuWebError("Redirect to a different host blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host == "localhost"
    return ip.is_private or ip.is_loopback


class ModuWebClient:
    def __init__(self, host: str | None = None, user: str | None = None,
                 password: str | None = None, https: bool = False):
        self.host = host or os.environ.get("MODUWEB_HOST")
        if not self.host:
            raise ModuWebError("Host required: pass host= or set MODUWEB_HOST")
        if not https and not _is_private(self.host):
            raise ModuWebError("Plain HTTP is only allowed for private addresses; use https=True")
        self.base = f"{'https' if https else 'http'}://{self.host}"
        self.user = user or os.environ.get("MODUWEB_USER")
        self.password = password or os.environ.get("MODUWEB_PASS")
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies), _SameHostRedirect())
        self.authenticated = False

    def fetch(self, path: str = "/", form: dict | None = None) -> str:
        url = urllib.parse.urljoin(self.base, path)
        if urllib.parse.urlparse(url).netloc != self.host:
            raise ModuWebError("Path points outside the configured host")
        body = urllib.parse.urlencode(form).encode() if form else None
        req = urllib.request.Request(url, data=body, headers={"User-Agent": "moduweb-client/1.0"})
        with self.opener.open(req, timeout=TIMEOUT) as r:
            return r.read().decode("utf-8", errors="replace")

    def login(self) -> bool:
        if not self.user or not self.password:
            raise ModuWebError("Missing credentials: set MODUWEB_USER and MODUWEB_PASS")
        self.fetch("/")                                  # initial session cookie
        html = self.fetch("/login", {"locale": "en", "login": self.user,
                                     "password": self.password, "submit": "Login"})
        self.authenticated = "loginForm" not in html
        if not self.authenticated:
            raise ModuWebError("Login rejected")
        return True

    def links(self, path: str = "/") -> list[tuple[str, str]]:
        """Internal links of a page; useful to map the menu tree."""
        html = self.fetch(path)
        seen, out = set(), []
        for href, text in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html, re.S):
            if href.startswith(("http", "#", "javascript")) or href in seen:
                continue
            seen.add(href)
            out.append((href, re.sub(r"<[^>]+>", "", text).strip()))
        return out

    def points(self, path: str) -> list[dict]:
        """Parse name/value/unit rows from a point table."""
        html = self.fetch(path)
        rows = []
        for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S | re.I):
            cells = [re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", c)).strip()
                     for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", tr, re.S | re.I)]
            cells = [c for c in cells if c]
            if len(cells) >= 2:
                m = re.match(r"^(-?[\d.,]+)\s*(\S*)$", cells[1])
                rows.append({"name": cells[0],
                             "value": m.group(1) if m else cells[1],
                             "unit": m.group(2) if m else "",
                             "raw": cells})
        return rows


def _cli() -> None:
    c = ModuWebClient()
    c.login()
    print(f"Session opened on {c.base}\n")
    if len(sys.argv) > 1:
        for p in c.points(sys.argv[1]):
            print(f"  {p['name']:<45} {p['value']} {p['unit']}")
    else:
        for href, text in c.links("/"):
            print(f"  {href:<45} {text}")


if __name__ == "__main__":
    _cli()
