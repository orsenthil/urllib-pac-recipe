"""Tests for pac_urllib.  No network access required.

A CONNECT-capable proxy and an origin server are run on loopback, and
behaviour is driven by real PAC JavaScript so that PyPAC's evaluation is
exercised rather than mocked.  The HTTPS tests need a certificate, which is
generated with the ``openssl`` command line tool and skipped if absent.
"""

import base64
import http.server
import os
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
from unittest import mock

from pypac.parser import PACFile

import pac_urllib
from pac_urllib import build_pac_opener

CERT_FILE = None
_cert_dir = None


def setUpModule():
    """Generate a self-signed certificate for localhost, if openssl exists."""
    global CERT_FILE, _cert_dir
    if shutil.which("openssl") is None:
        return
    _cert_dir = tempfile.mkdtemp(prefix="pac-urllib-test-")
    cert_file = os.path.join(_cert_dir, "keycert.pem")
    completed = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", cert_file, "-out", cert_file, "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
        capture_output=True,
    )
    if completed.returncode == 0:
        CERT_FILE = cert_file


def tearDownModule():
    if _cert_dir:
        shutil.rmtree(_cert_dir, ignore_errors=True)


def unused_port():
    """Return a port number that nothing is listening on."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class ProxyRequestHandler(http.server.BaseHTTPRequestHandler):
    """A minimal forward proxy that records what it was asked to do."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.log.append(("GET", self.path,
                                self.headers.get("Proxy-Authorization")))
        body = b"via-proxy"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_CONNECT(self):
        self.server.log.append(("CONNECT", self.path,
                                self.headers.get("Proxy-Authorization")))
        host, _, port = self.path.partition(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=5)
        except OSError:
            self.send_error(502)
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        with upstream:
            self._relay(self.connection, upstream)

    @staticmethod
    def _relay(client, upstream):
        sockets = [client, upstream]
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 5)
            if errored or not readable:
                return
            for source in readable:
                target = upstream if source is client else client
                data = source.recv(8192)
                if not data:
                    return
                target.sendall(data)

    def log_message(self, *args):
        pass


class OriginRequestHandler(http.server.BaseHTTPRequestHandler):
    """An origin server that records whether it was reached directly."""

    def do_GET(self):
        self.server.log.append(("GET", self.path,
                                self.headers.get("Proxy-Authorization")))
        if self.path == "/missing":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"from-origin"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class QuietHTTPServer(http.server.ThreadingHTTPServer):
    """Don't dump a traceback when a client drops a tunnelled connection."""

    def handle_error(self, request, client_address):
        if not isinstance(sys.exception(), (ConnectionResetError, BrokenPipeError)):
            super().handle_error(request, client_address)


def start_server(handler_class, tls=False):
    server = QuietHTTPServer(("127.0.0.1", 0), handler_class)
    server.log = []
    server.daemon_threads = True
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT_FILE)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class PACTestCase(unittest.TestCase):
    """Fixtures shared by the test cases below."""

    @classmethod
    def setUpClass(cls):
        cls.proxy = start_server(ProxyRequestHandler)
        cls.origin = start_server(OriginRequestHandler)
        cls.proxy_url = "127.0.0.1:%d" % cls.proxy.server_port
        cls.origin_url = "http://127.0.0.1:%d/doc" % cls.origin.server_port
        cls.dead_url = "127.0.0.1:%d" % unused_port()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.proxy, cls.origin):
            server.shutdown()
            server.server_close()

    def setUp(self):
        del self.proxy.log[:]
        del self.origin.log[:]

    def opener_for(self, pac_body, **kwargs):
        pac = PACFile("function FindProxyForURL(url, host) { %s }" % pac_body)
        return build_pac_opener(pac=pac, **kwargs)


class TestRouting(PACTestCase):

    def test_http_request_goes_through_proxy(self):
        opener = self.opener_for('return "PROXY %s";' % self.proxy_url)
        with opener.open(self.origin_url) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"via-proxy")
        # A forward proxy receives the absolute URI, not just the path.
        self.assertEqual(self.proxy.log[0][:2], ("GET", self.origin_url))
        self.assertEqual(self.origin.log, [])

    def test_direct_bypasses_proxy(self):
        opener = self.opener_for('return "DIRECT";')
        with opener.open(self.origin_url) as response:
            self.assertEqual(response.read(), b"from-origin")
        self.assertEqual(self.origin.log[0][:2], ("GET", "/doc"))
        self.assertEqual(self.proxy.log, [])

    def test_pac_can_route_by_url(self):
        opener = self.opener_for(
            'if (shExpMatch(url, "*/internal/*")) { return "DIRECT"; }'
            'return "PROXY %s";' % self.proxy_url)
        base = "http://127.0.0.1:%d" % self.origin.server_port
        opener.open(base + "/internal/x").close()
        opener.open(base + "/external/x").close()
        self.assertEqual(len(self.origin.log), 1)
        self.assertEqual(len(self.proxy.log), 1)

    def test_empty_pac_result_refuses_request(self):
        opener = self.opener_for('return "";')
        with self.assertRaises(urllib.error.URLError) as caught:
            opener.open(self.origin_url)
        self.assertIn("no usable proxy", str(caught.exception))
        self.assertEqual(self.proxy.log, [])
        self.assertEqual(self.origin.log, [])

    def test_socks_proxy_is_rejected(self):
        opener = self.opener_for('return "SOCKS5 127.0.0.1:1080";')
        with self.assertRaises(urllib.error.URLError) as caught:
            opener.open(self.origin_url)
        self.assertIn("SOCKS", str(caught.exception))

    def test_request_object_is_accepted(self):
        opener = self.opener_for('return "PROXY %s";' % self.proxy_url)
        request = urllib.request.Request(self.origin_url,
                                         headers={"X-Test": "1"})
        with opener.open(request) as response:
            self.assertEqual(response.read(), b"via-proxy")


class TestFailover(PACTestCase):

    def test_falls_over_to_next_proxy(self):
        opener = self.opener_for(
            'return "PROXY %s; PROXY %s";' % (self.dead_url, self.proxy_url))
        with opener.open(self.origin_url) as response:
            self.assertEqual(response.read(), b"via-proxy")
        self.assertEqual(len(self.proxy.log), 1)

    def test_falls_over_to_direct(self):
        opener = self.opener_for(
            'return "PROXY %s; DIRECT";' % self.dead_url)
        with opener.open(self.origin_url) as response:
            self.assertEqual(response.read(), b"from-origin")

    def test_exhausted_proxies_raise(self):
        opener = self.opener_for('return "PROXY %s";' % self.dead_url)
        with self.assertRaises(urllib.error.URLError):
            opener.open(self.origin_url)

    def test_dead_proxy_is_banned_for_later_requests(self):
        opener = self.opener_for(
            'return "PROXY %s; PROXY %s";' % (self.dead_url, self.proxy_url))
        opener.open(self.origin_url).close()
        opener.open(self.origin_url).close()
        self.assertEqual(len(self.proxy.log), 2)
        self.assertIn("http://" + self.dead_url,
                      opener.resolver._offline_proxies)

    def test_origin_error_does_not_ban_proxy(self):
        opener = self.opener_for('return "PROXY %s; PROXY %s";'
                                 % (self.proxy_url, self.dead_url))
        proxy = opener.resolver.get_proxy(self.origin_url)
        # The stand-in proxy answers every request itself, so ask the origin
        # server for the 404 by going direct instead.
        direct = self.opener_for('return "DIRECT";')
        with self.assertRaises(urllib.error.HTTPError) as caught:
            direct.open("http://127.0.0.1:%d/missing" % self.origin.server_port)
        self.addCleanup(caught.exception.close)
        self.assertEqual(caught.exception.code, 404)
        self.assertNotIn(proxy, opener.resolver._offline_proxies)

    def test_failover_with_request_object(self):
        opener = self.opener_for(
            'return "PROXY %s; PROXY %s";' % (self.dead_url, self.proxy_url))
        request = urllib.request.Request(self.origin_url)
        with opener.open(request) as response:
            self.assertEqual(response.read(), b"via-proxy")

    def test_attempt_limit_is_honoured(self):
        many = "; ".join("PROXY 127.0.0.1:%d" % unused_port()
                         for _ in range(4))
        opener = self.opener_for('return "%s";' % many, attempts=2)
        with self.assertRaises(urllib.error.URLError):
            opener.open(self.origin_url)
        self.assertEqual(len(opener.resolver._offline_proxies), 2)

    def test_is_proxy_failure_classification(self):
        refused = urllib.error.URLError(ConnectionRefusedError(111, "nope"))
        self.assertTrue(pac_urllib.is_proxy_failure(refused))
        dns = urllib.error.URLError(socket.gaierror(-2, "no such host"))
        self.assertFalse(pac_urllib.is_proxy_failure(dns))
        http_error = urllib.error.HTTPError(
            self.origin_url, 404, "Not Found", {}, None)
        self.addCleanup(http_error.close)
        self.assertFalse(pac_urllib.is_proxy_failure(http_error))


class TestProxyAuth(PACTestCase):

    def test_credentials_are_sent_to_proxy(self):
        auth = types.SimpleNamespace(username="user", password="p@ss word")
        opener = self.opener_for('return "PROXY %s";' % self.proxy_url,
                                 proxy_auth=auth)
        opener.open(self.origin_url).close()
        expected = "Basic " + base64.b64encode(b"user:p@ss word").decode()
        self.assertEqual(self.proxy.log[0][2], expected)

    def test_credentials_survive_failover(self):
        auth = types.SimpleNamespace(username="user", password="pw")
        opener = self.opener_for(
            'return "PROXY %s; PROXY %s";' % (self.dead_url, self.proxy_url),
            proxy_auth=auth)
        opener.open(self.origin_url).close()
        expected = "Basic " + base64.b64encode(b"user:pw").decode()
        self.assertEqual(self.proxy.log[0][2], expected)


class TestBypassInteraction(PACTestCase):

    def test_no_proxy_overrides_pac_by_default(self):
        opener = self.opener_for('return "PROXY %s";' % self.proxy_url)
        with mock.patch.dict(os.environ, {"no_proxy": "127.0.0.1"}):
            opener.open(self.origin_url).close()
        self.assertEqual(self.proxy.log, [])
        self.assertEqual(len(self.origin.log), 1)

    def test_strict_handler_ignores_no_proxy(self):
        opener = self.opener_for('return "PROXY %s";' % self.proxy_url,
                                 strict=True)
        with mock.patch.dict(os.environ, {"no_proxy": "127.0.0.1"}):
            opener.open(self.origin_url).close()
        self.assertEqual(len(self.proxy.log), 1)
        self.assertEqual(self.origin.log, [])

    def test_strict_handler_sends_credentials(self):
        auth = types.SimpleNamespace(username="user", password="p@ss word")
        opener = self.opener_for('return "PROXY %s";' % self.proxy_url,
                                 proxy_auth=auth, strict=True)
        opener.open(self.origin_url).close()
        expected = "Basic " + base64.b64encode(b"user:p@ss word").decode()
        self.assertEqual(self.proxy.log[0][2], expected)


class TestHTTPS(PACTestCase):

    @classmethod
    def setUpClass(cls):
        # Checked here rather than with skipIf, because decorators run at
        # import time, before setUpModule has made the certificate.
        if CERT_FILE is None:
            raise unittest.SkipTest("openssl unavailable to make a certificate")
        super().setUpClass()
        cls.tls_origin = start_server(OriginRequestHandler, tls=True)
        cls.tls_url = "https://localhost:%d/doc" % cls.tls_origin.server_port
        cls.ssl_handler = urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile=CERT_FILE))

    @classmethod
    def tearDownClass(cls):
        cls.tls_origin.shutdown()
        cls.tls_origin.server_close()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        del self.tls_origin.log[:]

    def https_opener(self, pac_body, **kwargs):
        return self.opener_for(pac_body, handlers=(self.ssl_handler,), **kwargs)

    def test_https_tunnels_through_proxy(self):
        opener = self.https_opener('return "PROXY %s";' % self.proxy_url)
        with opener.open(self.tls_url) as response:
            self.assertEqual(response.read(), b"from-origin")
        method, target, _ = self.proxy.log[0]
        self.assertEqual(method, "CONNECT")
        self.assertEqual(target, "localhost:%d" % self.tls_origin.server_port)

    def test_https_failover(self):
        opener = self.https_opener(
            'return "PROXY %s; PROXY %s";' % (self.dead_url, self.proxy_url))
        with opener.open(self.tls_url) as response:
            self.assertEqual(response.read(), b"from-origin")

    def test_https_failover_with_request_object(self):
        opener = self.https_opener(
            'return "PROXY %s; PROXY %s";' % (self.dead_url, self.proxy_url))
        request = urllib.request.Request(self.tls_url)
        with opener.open(request) as response:
            self.assertEqual(response.read(), b"from-origin")

    def test_credentials_go_on_connect_only(self):
        auth = types.SimpleNamespace(username="user", password="pw")
        opener = self.https_opener('return "PROXY %s";' % self.proxy_url,
                                   proxy_auth=auth)
        opener.open(self.tls_url).close()
        expected = "Basic " + base64.b64encode(b"user:pw").decode()
        self.assertEqual(self.proxy.log[0][2], expected)
        # Proxy-Authorization must not be forwarded to the origin server.
        self.assertIsNone(self.tls_origin.log[0][2])


class TestOpenerConstruction(unittest.TestCase):

    def test_plain_opener_when_no_pac_found(self):
        with mock.patch.object(pac_urllib, "get_pac", return_value=None):
            opener = build_pac_opener()
        self.assertIsInstance(opener, urllib.request.OpenerDirector)
        self.assertNotIsInstance(opener, pac_urllib.PACOpenerDirector)

    def test_plain_opener_when_pac_is_malformed(self):
        from pypac.parser import MalformedPacError
        with mock.patch.object(pac_urllib, "get_pac",
                               side_effect=MalformedPacError()):
            opener = build_pac_opener()
        self.assertNotIsInstance(opener, pac_urllib.PACOpenerDirector)

    def test_pac_kwargs_are_passed_through(self):
        with mock.patch.object(pac_urllib, "get_pac",
                               return_value=None) as get_pac:
            build_pac_opener(pac_url="http://x/proxy.pac", from_dns=False)
        get_pac.assert_called_once_with(url="http://x/proxy.pac",
                                        from_dns=False)

    def test_opener_can_be_installed_globally(self):
        pac = PACFile('function FindProxyForURL(url, host)'
                      ' { return "DIRECT"; }')
        opener = build_pac_opener(pac=pac)
        self.assertIsInstance(opener, pac_urllib.PACOpenerDirector)
        original = urllib.request._opener
        try:
            urllib.request.install_opener(opener)
            self.assertIs(urllib.request._opener, opener)
        finally:
            urllib.request._opener = original


if __name__ == "__main__":
    unittest.main()
