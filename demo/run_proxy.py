#!/usr/bin/env python3
"""Run the servers needed to try the PAC example by hand.

Three servers are started on loopback, and every request each one handles is
logged to stdout, so it is visible which route a request actually took:

  * a forward proxy on port 8899, which fetches HTTP URLs on a client's
    behalf and tunnels HTTPS with CONNECT;
  * a web server on port 8900, serving example.pac with the content type
    that PyPAC requires of a downloaded PAC file;
  * an origin server on port 8901, so that the demo needs no internet
    access.  It reports whether it was reached through the proxy.

Port 8902 is deliberately left unused: example.pac names it as a dead proxy
so that failover can be tried.

Leave this running and drive it from another terminal with pac_opener.py.
"""

import argparse
import http.client
import http.server
import os
import select
import socket
import sys
import threading
from urllib.parse import urlsplit

# Headers that apply to one connection and must not be forwarded.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
})

# Added by the proxy so that the origin server can report how it was reached.
VIA_HEADER = "X-Demo-Proxy"

_print_lock = threading.Lock()


def log(tag, message):
    with _print_lock:
        print("[%-6s] %s" % (tag, message), flush=True)


class QuietHTTPServer(http.server.ThreadingHTTPServer):
    """Keep the log readable when a client drops a connection."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        if not isinstance(sys.exception(), (ConnectionResetError, BrokenPipeError)):
            super().handle_error(request, client_address)


class LoggingHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass  # each handler below logs what matters instead


class ForwardProxyHandler(LoggingHandler):
    """A forward proxy, as a PAC file expects to be able to name."""

    protocol_version = "HTTP/1.1"
    server_version = "pac-demo-proxy"

    def do_GET(self):
        self._forward("GET")

    def do_HEAD(self):
        self._forward("HEAD")

    def _forward(self, method):
        if not self.path.startswith("http://"):
            # A client that did not know to use a proxy sends only the path.
            log("proxy", "%s %s -> 400, not an absolute URI" % (method, self.path))
            self.send_error(400, "a proxy request needs an absolute URI")
            return

        parts = urlsplit(self.path)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        headers = {name: value for name, value in self.headers.items()
                   if name.lower() not in HOP_BY_HOP}
        headers["Connection"] = "close"
        headers[VIA_HEADER] = "1"

        connection = http.client.HTTPConnection(
            parts.hostname, parts.port or 80, timeout=10)
        try:
            connection.request(method, target, headers=headers)
            upstream = connection.getresponse()
            body = upstream.read()
        except OSError as exc:
            log("proxy", "%s %s -> 502, %s" % (method, self.path, exc))
            self.send_error(502, "cannot reach %s" % parts.hostname)
            return
        finally:
            connection.close()

        log("proxy", "%s %s -> %d" % (method, self.path, upstream.status))
        self.send_response(upstream.status, upstream.reason)
        for name, value in upstream.getheaders():
            if name.lower() not in HOP_BY_HOP and name.lower() != "content-length":
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError as exc:
            log("proxy", "CONNECT %s -> 502, %s" % (self.path, exc))
            self.send_error(502, "cannot reach %s" % host)
            return
        log("proxy", "CONNECT %s -> 200, tunnel open" % self.path)
        self.send_response(200, "Connection established")
        self.end_headers()
        with upstream:
            self._relay(self.connection, upstream)
        log("proxy", "CONNECT %s -> tunnel closed" % self.path)

    @staticmethod
    def _relay(client, upstream):
        """Copy bytes in both directions until either side hangs up."""
        sockets = [client, upstream]
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 60)
            if errored or not readable:
                return
            for source in readable:
                target = upstream if source is client else client
                try:
                    data = source.recv(8192)
                except OSError:
                    return
                if not data:
                    return
                target.sendall(data)


class PACFileHandler(LoggingHandler):
    """Serve the PAC file, so get_pac(url=...) can be tried too."""

    def do_GET(self):
        try:
            with open(self.server.pac_path, "rb") as pac_file:
                body = pac_file.read()
        except OSError as exc:
            log("pac", "GET %s -> 404, %s" % (self.path, exc))
            self.send_error(404, "no PAC file to serve")
            return
        log("pac", "GET %s -> 200, %d bytes" % (self.path, len(body)))
        self.send_response(200)
        # PyPAC rejects a downloaded PAC file served as anything else,
        # unless get_pac() is passed allowed_content_types.
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OriginHandler(LoggingHandler):
    """Stand in for the website being fetched."""

    def do_GET(self):
        via_proxy = self.headers.get(VIA_HEADER) is not None
        log("origin", "GET %s, reached %s"
            % (self.path, "through the proxy" if via_proxy else "directly"))
        body = ("demo origin server\npath: %s\nreached: %s\n"
                % (self.path, "through the proxy" if via_proxy else "directly")
                ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--proxy-port", type=int, default=8899)
    parser.add_argument("--pac-port", type=int, default=8900)
    parser.add_argument("--origin-port", type=int, default=8901)
    parser.add_argument(
        "--pac-file",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "example.pac"),
        help="PAC file to serve (default: the example.pac beside this script)")
    return parser.parse_args()


def main():
    args = parse_args()

    proxy = QuietHTTPServer(("127.0.0.1", args.proxy_port), ForwardProxyHandler)
    pac = QuietHTTPServer(("127.0.0.1", args.pac_port), PACFileHandler)
    pac.pac_path = args.pac_file
    origin = QuietHTTPServer(("127.0.0.1", args.origin_port), OriginHandler)

    servers = (proxy, pac, origin)
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()

    print("proxy    http://127.0.0.1:%d" % args.proxy_port)
    print("PAC file http://127.0.0.1:%d/example.pac  (%s)"
          % (args.pac_port, args.pac_file))
    print("origin   http://127.0.0.1:%d" % args.origin_port)
    print()
    print("In another terminal:")
    print("    python demo/pac_opener.py")
    print("    python demo/pac_opener.py --failover")
    print("    python demo/pac_opener.py --pac-url http://127.0.0.1:%d/example.pac"
          % args.pac_port)
    print()
    print("Ctrl-C to stop.")
    sys.stdout.flush()  # the banner should appear even when redirected

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
