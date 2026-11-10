#!/usr/bin/env python3
"""The PAC handler from the urllib.request documentation, made runnable.

``PACProxyHandler`` below is the same code as the example proposed for
Doc/library/urllib.request.rst.  Everything after it exists only to drive
that example from the command line, printing the PAC file's decision and
then the outcome for each URL, so the documented snippet can be checked by
hand against the servers that run_proxy.py starts.

Start run_proxy.py in another terminal first, then:

    python demo/pac_opener.py              # try each rule in example.pac
    python demo/pac_opener.py --failover   # retry past a dead proxy
    python demo/pac_opener.py https://www.python.org/   # needs internet
"""

# --- begin documentation example -------------------------------------------

import urllib.error
import urllib.request
from pypac import get_pac
from pypac.resolver import ProxyResolver

class PACProxyHandler(urllib.request.ProxyHandler):

    def __init__(self, resolver):
        self.resolver = resolver
        # An empty mapping suppresses the <protocol>_open methods that
        # ProxyHandler would make from a static proxies mapping.
        super().__init__({})

    def _pac_open(self, req, protocol):
        proxy = self.resolver.get_proxy(req.full_url)
        if proxy is None:
            raise urllib.error.URLError('no proxy available')
        if proxy == 'DIRECT':
            return None  # continue with the remaining handlers
        if proxy.startswith('socks'):
            raise urllib.error.URLError('SOCKS proxies are not supported')
        return self.proxy_open(req, proxy, protocol)

    def http_open(self, req):
        return self._pac_open(req, 'http')

    def https_open(self, req):
        return self._pac_open(req, 'https')

# --- end documentation example ---------------------------------------------

import argparse
import os

from pypac.parser import PACFile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PAC_FILE = os.path.join(HERE, "example.pac")


def demo_urls(origin_port):
    """One URL for each rule in example.pac."""
    origin = "http://127.0.0.1:%d" % origin_port
    return [
        origin + "/",                 # PROXY, the catch-all rule
        origin + "/direct/page",      # DIRECT
        origin + "/failover/page",    # a dead proxy, then a live one
        origin + "/blocked/page",     # "", no proxy and no fallback
        origin + "/socks/page",       # SOCKS5, which urllib cannot use
        "http://localhost:%d/" % origin_port,  # isPlainHostName, so DIRECT
    ]


def load_pac(args):
    if args.pac_url:
        pac = get_pac(url=args.pac_url)
        if pac is None:
            raise SystemExit("no PAC file found at %s" % args.pac_url)
        return pac
    with open(args.pac_file) as pac_file:
        return PACFile(pac_file.read())


def fetch(opener, resolver, url, failover=False):
    """Fetch *url*, reporting the PAC decision and the outcome."""
    print(url)
    while True:
        proxy = resolver.get_proxy(url)
        print("    PAC says : %s" % (proxy if proxy else repr(proxy)))
        try:
            with opener.open(url, timeout=10) as response:
                body = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            exc.close()
            print("    result   : HTTP %d %s" % (exc.code, exc.reason))
            return
        except urllib.error.URLError as exc:
            print("    result   : URLError: %s" % (exc.reason,))
            retryable = (failover and proxy not in (None, "DIRECT")
                         and not proxy.startswith("socks"))
            if not retryable:
                return
            # The documented sentence about ban_proxy(), in practice: exclude
            # the proxy that failed so get_proxy() offers the next candidate.
            print("    banning  : %s" % proxy)
            resolver.ban_proxy(proxy)
            continue

        first_line = body.decode("utf-8", "replace").strip().splitlines()[:1]
        print("    result   : HTTP %d, %d bytes" % (status, len(body)))
        for line in first_line:
            print("    body     : %s" % line)
        return


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("urls", nargs="*",
                        help="URLs to fetch (default: one per PAC rule)")
    parser.add_argument("--pac-file", default=DEFAULT_PAC_FILE,
                        help="PAC file to read (default: %(default)s)")
    parser.add_argument("--pac-url",
                        help="download the PAC file from this URL instead")
    parser.add_argument("--origin-port", type=int, default=8901,
                        help="origin server run_proxy.py started")
    parser.add_argument("--failover", action="store_true",
                        help="ban an unreachable proxy and try the next one")
    return parser.parse_args()


def main():
    args = parse_args()
    resolver = ProxyResolver(load_pac(args))
    opener = urllib.request.build_opener(PACProxyHandler(resolver))

    for url in args.urls or demo_urls(args.origin_port):
        fetch(opener, resolver, url, failover=args.failover)
        print()


if __name__ == "__main__":
    main()
