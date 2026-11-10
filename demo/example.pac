// Example PAC file for trying the urllib.request + PyPAC recipe by hand.
//
// The ports below match the defaults of run_proxy.py:
//
//   127.0.0.1:8899   the forward proxy that run_proxy.py starts
//   127.0.0.1:8902   deliberately left unused, so failover can be tried
//
// Each rule exercises a different answer a real PAC file can give.

function FindProxyForURL(url, host) {

    // Refuse the request outright.  An empty return value leaves the
    // handler with neither a proxy nor a DIRECT fallback.
    if (shExpMatch(url, "*/blocked/*")) {
        return "";
    }

    // Reach the origin server without a proxy.
    if (shExpMatch(url, "*/direct/*")) {
        return "DIRECT";
    }

    // A SOCKS proxy, which urllib.request has no transport for.
    if (shExpMatch(url, "*/socks/*")) {
        return "SOCKS5 127.0.0.1:1080";
    }

    // Two proxies, of which the first is dead.  Reaching the second one
    // requires ProxyResolver.ban_proxy().
    if (shExpMatch(url, "*/failover/*")) {
        return "PROXY 127.0.0.1:8902; PROXY 127.0.0.1:8899";
    }

    // An unqualified host name is usually on the local network.
    if (isPlainHostName(host)) {
        return "DIRECT";
    }

    // Hosts in this imaginary internal domain need no proxy either.
    if (dnsDomainIs(host, "internal.example")) {
        return "DIRECT";
    }

    // Everything else goes through the proxy.
    return "PROXY 127.0.0.1:8899";
}
