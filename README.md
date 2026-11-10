# PAC file support for `urllib.request`

A small, tested recipe for making `urllib.request` obey a proxy auto-config
(PAC) file, using [PyPAC](https://pypac.readthedocs.io/) for discovery and
JavaScript evaluation.

Written to answer [python/cpython#52330](https://github.com/python/cpython/issues/52330),
*urllib proxy interface is too limited*.

Licensed under the MIT License; see [LICENSE](LICENSE).

## The problem

`urllib.request` models proxies as one `{scheme: proxy_url}` mapping, built
once by `getproxies()` and consumed by `ProxyHandler`. A PAC file does not fit
that shape: `FindProxyForURL(url, host)` can route different URLs to different
proxies, list several proxies for failover, or answer `DIRECT` for some hosts.

PyPAC already solves discovery (Windows registry, macOS System Preferences,
DNS WPAD), JavaScript evaluation, and proxy selection with failover, but its
ready-made integration is `PACSession`, a `requests.Session` subclass. Its own
documentation notes that other HTTP libraries are left to the caller, "though
PyPAC has all the building blocks needed to make one easily". This is that
glue for `urllib.request`.

## Install

```console
$ python -m pip install -r requirements.txt
```

## Use

```python
from pac_urllib import build_pac_opener

opener = build_pac_opener()                     # discover a PAC
with opener.open("https://example.com") as response:
    body = response.read()
```

Pass `pac_url` when you already know where the PAC lives, which skips
discovery and its network round trips:

```python
opener = build_pac_opener(pac_url="http://corp.local/proxy.pac")
```

`pac_url` is downloaded over HTTP. PyPAC reads PAC files from disk only when
it finds the path in the OS settings, so for a local file, parse it yourself
and pass the result:

```python
from pypac.parser import PACFile

with open("/etc/proxy.pac") as f:
    opener = build_pac_opener(pac=PACFile(f.read()))
```

For a PAC served with an unexpected content type, or to switch off DNS WPAD,
forward keyword arguments to `pypac.get_pac`:

```python
opener = build_pac_opener(
    pac_url="http://corp.local/proxy.txt",
    allowed_content_types=["text/plain"],
    from_dns=False,
)
```

PAC discovery makes network requests, so build the opener once at startup and
reuse it. To make code that calls `urllib.request.urlopen` use it, hand it to
`urllib.request.install_opener`; failover survives, because the opener is a
real `OpenerDirector` subclass.

### Proxy authentication

Any object with `username` and `password` attributes will do, so there is no
need to import from `requests`:

```python
import types

auth = types.SimpleNamespace(username="user", password="s3cret")
opener = build_pac_opener(proxy_auth=auth)
```

PyPAC embeds percent-encoded credentials in the proxy URLs it returns, and
`urllib.request` turns them into a `Proxy-Authorization: Basic` header. For
HTTPS the header rides on the `CONNECT` request only and is never forwarded to
the origin server.

### HTTPS-inspecting proxies

A proxy that decrypts HTTPS presents its own certificate, which `urllib` will
reject unless you supply a context trusting your organization's root:

```python
import ssl, urllib.request

context = ssl.create_default_context(cafile="/etc/ssl/certs/corp-root.pem")
opener = build_pac_opener(handlers=(urllib.request.HTTPSHandler(context=context),))
```

## How it works

| Piece | Responsibility |
| --- | --- |
| `pypac.get_pac` | Find and parse the PAC file |
| `pypac.resolver.ProxyResolver` | Choose a proxy per URL; keep the ban list |
| `PACProxyHandler` | Resolve per request instead of from a static dict |
| `PACOpenerDirector` | Retry with the next proxy when one is unreachable |
| `build_pac_opener` | Assemble the above, or fall back to a plain opener |

`PACProxyHandler` subclasses `ProxyHandler` and passes it an empty mapping,
which suppresses the per-scheme `*_open` methods it would otherwise generate.
It then defines `http_open` and `https_open` itself. Because `ProxyHandler`
carries `handler_order = 100`, those run before `HTTPHandler`'s, and returning
`None` for `DIRECT` falls through to the normal chain.

Failover cannot live in the handler: `urllib.request` connects to the proxy
inside the HTTP handler, after the proxy handler has already returned. So
`PACOpenerDirector.open` wraps the attempt, bans the proxy on a connection
failure, and tries again. When a `Request` object is passed instead of a URL
string, the proxy-related attributes that `set_proxy` mutates are snapshotted
and restored between attempts.

## Behaviour choices

Three decisions are baked in, and two are adjustable.

**`no_proxy` wins by default.** The inherited `proxy_open` consults
`proxy_bypass()`, so `no_proxy` and the OS bypass list can divert a request the
PAC assigned to a proxy. That is arguably correct, since the user asked for it
explicitly. Pass `strict=True` to use `StrictPACProxyHandler` and let the PAC
file override them. The strict handler reimplements `proxy_open` without the
bypass check, so it duplicates a little standard library logic; the tests cover
what it depends on, so breakage will show up rather than go unnoticed.

**Only connection failures count as proxy failures.** `is_proxy_failure`
matches a `URLError` whose `reason` is a `ConnectionError`, `TimeoutError`, or
`socket.timeout`, mirroring PyPAC's default for `PACSession`. An `HTTPError`
propagates untouched: a response from the origin says nothing about the proxy.
Whether an HTTP 407 should trigger failover is a policy question PyPAC also
leaves open; add it to `is_proxy_failure` if your proxies warrant it.

**No PAC means no PAC behaviour.** If discovery finds nothing, or the file is
malformed, `build_pac_opener` returns a plain `build_opener()` result and the
usual environment and OS proxy settings apply.

## Limitations

- **SOCKS proxies are not supported.** A PAC file may legally return `SOCKS5`,
  and `urllib.request` has no transport for it, so `PACProxyHandler` raises
  `URLError` rather than failing obscurely. This is the one gap documentation
  alone cannot close.
- **`FindProxyForURL` runs on every request.** PyPAC caches on the function's
  return value, not the URL, so the JavaScript is always evaluated. A PAC using
  `dnsResolve` or `isInNet` will do blocking DNS inside your request path; add
  per-host memoization if this is a hot path.
- **PAC files go stale.** Nothing here refetches. Decide whether to rebuild the
  opener periodically, and call `opener.resolver.unban_all()` after an outage so
  a transient failure does not blacklist a proxy forever.
- **Thread safety is unverified.** `ProxyResolver` keeps its cache in a plain
  dict and its bans in a plain set, and dukpy's thread-safety is undocumented.
  Check before sharing one opener across threads.
- **Retries need a replayable body.** Failover re-sends the request, so a
  stream passed as `data` may already be partly consumed. Prefer `bytes`.
- **PAC files are untrusted JavaScript.** PyPAC's own documentation warns that
  dukpy was not designed for it. This matters most with DNS WPAD discovery,
  where the file comes from whoever answers `wpad.<domain>`; pinning `pac_url`
  avoids that exposure.

## Trying it by hand

The `demo/` directory runs a real proxy and a real PAC file, so the example
can be checked interactively rather than only through the test suite.

| File | Purpose |
| --- | --- |
| `demo/run_proxy.py` | Starts a forward proxy, a server for the PAC file, and an origin server |
| `demo/example.pac` | A PAC file with one rule per kind of answer a PAC can give |
| `demo/pac_opener.py` | The documented handler, runnable, reporting each decision |

In one terminal:

```console
$ python demo/run_proxy.py
proxy    http://127.0.0.1:8899
PAC file http://127.0.0.1:8900/example.pac
origin   http://127.0.0.1:8901
```

It logs every request each server handles, so the route a request took is
visible. Port 8902 is deliberately left unused, because `example.pac` names it
as a dead proxy. In another terminal:

```console
$ python demo/pac_opener.py
http://127.0.0.1:8901/
    PAC says : http://127.0.0.1:8899
    result   : HTTP 200, 54 bytes
    body     : demo origin server

http://127.0.0.1:8901/direct/page
    PAC says : DIRECT
    result   : HTTP 200, 56 bytes
    body     : demo origin server

http://127.0.0.1:8901/failover/page
    PAC says : http://127.0.0.1:8902
    result   : URLError: [Errno 111] Connection refused

http://127.0.0.1:8901/blocked/page
    PAC says : None
    result   : URLError: no proxy available

http://127.0.0.1:8901/socks/page
    PAC says : socks5://127.0.0.1:1080
    result   : URLError: SOCKS proxies are not supported
```

The origin server reports whether the proxy fetched the page or the client
reached it directly, which is what distinguishes the first two cases.

The `/failover/` URL fails on purpose: the documented handler has no retry
logic, so it stops at the dead proxy. Add `--failover` to see
`ProxyResolver.ban_proxy()` move on to the next candidate:

```console
$ python demo/pac_opener.py --failover http://127.0.0.1:8901/failover/page
    PAC says : http://127.0.0.1:8902
    result   : URLError: [Errno 111] Connection refused
    banning  : http://127.0.0.1:8902
    PAC says : http://127.0.0.1:8899
    result   : HTTP 200, 67 bytes
```

To exercise PAC discovery over HTTP, including the content type PyPAC
insists on, read the PAC file from the demo's web server instead of from
disk:

```console
$ python demo/pac_opener.py --pac-url http://127.0.0.1:8900/example.pac
```

Any URL given on the command line is used instead of the demo ones, so with
internet access the proxy can be driven against real sites. The proxy log
shows the `CONNECT` tunnel that an HTTPS request goes through:

```console
$ python demo/pac_opener.py https://www.python.org/
```

## Tests

```console
$ python -m unittest -v test_pac_urllib
```

27 tests, no network access. A CONNECT-capable proxy and an origin server run
on loopback, and behaviour is driven by real PAC JavaScript so PyPAC's
evaluation is exercised rather than mocked. The HTTPS cases generate a
self-signed certificate with the `openssl` command line tool, and skip
themselves if it is unavailable.

Coverage includes: plain HTTP through a proxy (absolute-URI request), HTTPS
through a proxy (`CONNECT` tunnel), `DIRECT` routing, per-URL routing within
one PAC, an empty PAC result refusing the request, SOCKS rejection, failover to
the next proxy and to a final `DIRECT`, proxy exhaustion, bans persisting
across requests, the attempt limit, an origin 404 not banning the proxy, proxy
credentials on both `GET` and `CONNECT` but not at the origin, credentials
surviving failover, `Request` objects with and without failover, `no_proxy`
precedence in both modes, and opener construction when no PAC is found.
