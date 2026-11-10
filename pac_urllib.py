"""PAC-aware proxy support for :mod:`urllib.request`, built on PyPAC.

:mod:`urllib.request` models proxies as a single ``{scheme: proxy_url}``
mapping, which cannot express a proxy auto-config (PAC) file: a PAC picks a
proxy per URL, may list several proxies for failover, and may answer
``DIRECT`` for some hosts.  PyPAC finds and evaluates PAC files; this module
supplies the :mod:`urllib.request` glue that PyPAC leaves to the caller.

Basic use::

    from pac_urllib import build_pac_opener

    opener = build_pac_opener()  # discover a PAC via the OS and DNS WPAD
    with opener.open("https://example.com") as response:
        body = response.read()

See https://github.com/python/cpython/issues/52330.
"""

import base64
import socket
import urllib.error
import urllib.request
from socket import _GLOBAL_DEFAULT_TIMEOUT
from urllib.parse import unquote, urlsplit

from pypac import get_pac
from pypac.parser import MalformedPacError
from pypac.resolver import ProxyResolver

__all__ = [
    "PACProxyHandler",
    "StrictPACProxyHandler",
    "PACOpenerDirector",
    "build_pac_opener",
    "is_proxy_failure",
]


class PACProxyHandler(urllib.request.ProxyHandler):
    """Ask a PAC file which proxy to use, once per request.

    The inherited :meth:`~urllib.request.ProxyHandler.proxy_open` honours
    :envvar:`no_proxy` and the operating system's bypass list, so those can
    override the PAC file.  Use :class:`StrictPACProxyHandler` to make the
    PAC authoritative instead.
    """

    def __init__(self, resolver):
        self._resolver = resolver
        # An empty mapping suppresses the per-scheme *_open methods that
        # ProxyHandler would otherwise generate from a static proxy dict.
        super().__init__({})

    def _pac_open(self, req, scheme):
        proxy = self._resolver.get_proxy(req.full_url)
        if proxy is None:
            raise urllib.error.URLError(
                "PAC file provided no usable proxy for %s" % req.full_url)
        if proxy == "DIRECT":
            return None  # fall through to the normal handler chain
        if proxy.startswith("socks"):
            raise urllib.error.URLError(
                "urllib.request cannot use the SOCKS proxy %s" % proxy)
        return self.proxy_open(req, proxy, scheme)

    def http_open(self, req):
        return self._pac_open(req, "http")

    def https_open(self, req):
        return self._pac_open(req, "https")


class StrictPACProxyHandler(PACProxyHandler):
    """A :class:`PACProxyHandler` for which the PAC file always wins.

    This reimplements :meth:`urllib.request.ProxyHandler.proxy_open` without
    its ``proxy_bypass()`` check, so :envvar:`no_proxy` and the OS bypass
    list cannot divert a request that the PAC file assigned to a proxy.
    Being a reimplementation, it may need revisiting when the standard
    library changes; the accompanying tests cover the behaviour it relies on.
    """

    def proxy_open(self, req, proxy, type):
        orig_type = req.type
        parsed = urlsplit(proxy)
        proxy_type = parsed.scheme or orig_type
        hostport = unquote(parsed.netloc.rpartition("@")[2])

        if parsed.username and parsed.password:
            user_pass = "%s:%s" % (unquote(parsed.username),
                                   unquote(parsed.password))
            creds = base64.b64encode(user_pass.encode()).decode("ascii")
            req.add_header("Proxy-authorization", "Basic " + creds)

        req.set_proxy(hostport, proxy_type)
        if orig_type == proxy_type or orig_type == "https":
            return None  # the HTTP(S) handler can take it from here
        return self.parent.open(req, timeout=req.timeout)


def is_proxy_failure(exc):
    """Should *exc* cause the proxy that was used to be considered dead?

    Mirrors PyPAC's default for ``PACSession``: a failure to reach the proxy
    at all.  A response from the origin server, however unwelcome, says
    nothing about the proxy and is not matched here.
    """
    return isinstance(exc, urllib.error.URLError) and isinstance(
        exc.reason, (ConnectionError, TimeoutError, socket.timeout))


# set_proxy() and the Proxy-Authorization header mutate the Request, so a
# Request object must be returned to its original state before a retry.
_PROXY_MUTATED_ATTRS = ("host", "selector", "type", "_tunnel_host")


def _snapshot(req):
    return (
        {name: getattr(req, name) for name in _PROXY_MUTATED_ATTRS},
        dict(req.headers),
        dict(req.unredirected_hdrs),
    )


def _restore(req, snapshot):
    attrs, headers, unredirected_hdrs = snapshot
    for name, value in attrs.items():
        setattr(req, name, value)
    req.headers = dict(headers)
    req.unredirected_hdrs = dict(unredirected_hdrs)


class PACOpenerDirector(urllib.request.OpenerDirector):
    """An opener that fails over to the PAC file's next proxy.

    urllib.request connects to the proxy inside the HTTP handler, after the
    proxy handler has returned, so a handler cannot retry a dead proxy on its
    own.  Failover therefore belongs here, around :meth:`open`.
    """

    def __init__(self, resolver, attempts=5):
        super().__init__()
        self.resolver = resolver
        self.attempts = attempts

    def open(self, fullurl, data=None, timeout=_GLOBAL_DEFAULT_TIMEOUT):
        is_request = isinstance(fullurl, urllib.request.Request)
        url = fullurl.full_url if is_request else fullurl
        snapshot = _snapshot(fullurl) if is_request else None
        last_exc = None

        for _ in range(self.attempts):
            # Resolving here and in the handler yields the same answer: the
            # resolver caches the parsed PAC result and both calls see the
            # same ban list.
            proxy = self.resolver.get_proxy(url)
            try:
                return super().open(fullurl, data, timeout)
            except urllib.error.HTTPError:
                raise  # the origin answered; not the proxy's doing
            except urllib.error.URLError as exc:
                if proxy in (None, "DIRECT") or not is_proxy_failure(exc):
                    raise
                self.resolver.ban_proxy(proxy)
                last_exc = exc
                if is_request:
                    _restore(fullurl, snapshot)

        raise urllib.error.URLError(
            "every proxy the PAC file offered for %s failed" % url) from last_exc


def build_pac_opener(pac_url=None, pac=None, proxy_auth=None, handlers=(),
                     attempts=5, strict=False, **pac_kwargs):
    """Build an opener that routes requests according to a PAC file.

    :param pac_url: HTTP(S) URL of the PAC file.  Skips discovery.  PyPAC
        only reads local paths found in the OS settings, so to use a PAC
        file on disk, read it and pass ``pac=PACFile(text)`` instead.
    :param pac: An already parsed :class:`pypac.parser.PACFile`.  Skips
        discovery, and takes precedence over *pac_url*.
    :param proxy_auth: Any object with ``username`` and ``password``
        attributes, for proxies that require Basic authentication.
    :param handlers: Extra :mod:`urllib.request` handlers, for instance an
        ``HTTPSHandler`` carrying an :class:`ssl.SSLContext` that trusts an
        HTTPS-inspecting proxy's certificate.
    :param attempts: Maximum number of proxies to try per request.
    :param strict: Use :class:`StrictPACProxyHandler`, making the PAC file
        override :envvar:`no_proxy` and the OS bypass list.
    :param pac_kwargs: Passed through to :func:`pypac.get_pac`, for instance
        ``allowed_content_types`` or ``from_dns``.
    :returns: A :class:`PACOpenerDirector`, or a plain
        :class:`~urllib.request.OpenerDirector` if no PAC file was found, in
        which case the usual environment and OS proxy settings apply.

    PAC discovery makes network requests, so build the opener once and reuse
    it rather than calling this per request.
    """
    if pac is None:
        try:
            pac = get_pac(url=pac_url, **pac_kwargs)
        except MalformedPacError:
            pac = None
    if pac is None:
        return urllib.request.build_opener(*handlers)

    resolver = ProxyResolver(pac, proxy_auth=proxy_auth)
    handler_cls = StrictPACProxyHandler if strict else PACProxyHandler

    # Let build_opener assemble the default handler chain, then move those
    # handlers onto a director that knows how to fail over.
    staged = urllib.request.build_opener(handler_cls(resolver), *handlers)
    opener = PACOpenerDirector(resolver, attempts=attempts)
    for handler in staged.handlers:
        opener.add_handler(handler)
    return opener
