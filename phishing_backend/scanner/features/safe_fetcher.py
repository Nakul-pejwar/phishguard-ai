import ipaddress
import socket
import urllib.parse
from urllib.request import Request, urlopen

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS metadata
    ipaddress.ip_network("172.16.0.0/12"),  # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),  # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
]

BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),  # Loopback
    ipaddress.ip_network("::/128"),  # Unspecified
    ipaddress.ip_network("fc00::/7"),  # Unique local
    ipaddress.ip_network("fe80::/10"),  # Link-local
]


class SSRFSecurityError(ValueError):
    """Raised when an outbound network request targets a private or restricted IP address."""
    pass


def is_ip_allowed(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False

        if isinstance(ip, ipaddress.IPv4Address):
            for network in BLOCKED_IP_NETWORKS:
                if ip in network:
                    return False
        elif isinstance(ip, ipaddress.IPv6Address):
            for network in BLOCKED_IPV6_NETWORKS:
                if ip in network:
                    return False
        return True
    except ValueError:
        return False


def validate_url_for_ssrf(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFSecurityError(f"Unsupported scheme: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFSecurityError("URL has no hostname.")

    # Check for direct IP address in hostname
    try:
        if not is_ip_allowed(hostname):
            raise SSRFSecurityError(f"Direct IP {hostname} is in a restricted range.")
    except Exception:
        pass

    # Resolve domain through DNS and verify all returned IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        resolved_ips = {item[4][0] for item in addr_info}
        for ip in resolved_ips:
            if not is_ip_allowed(ip):
                raise SSRFSecurityError(f"Domain {hostname} resolves to restricted IP: {ip}")
    except socket.gaierror as err:
        raise SSRFSecurityError(f"Could not resolve host {hostname}: {err}") from err

    return url


def safe_unshorten_url(url: str, max_hops: int = 3, timeout: float = 3.0) -> str:
    """
    Safely follows HTTP redirect chains for URL shorteners without SSRF exposure.
    """
    current_url = url
    for _ in range(max_hops):
        try:
            validate_url_for_ssrf(current_url)
            req = Request(current_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            with urlopen(req, timeout=timeout) as response:
                final_url = response.geturl()
                if final_url and final_url != current_url:
                    validate_url_for_ssrf(final_url)
                    current_url = final_url
                else:
                    break
        except Exception:
            break
    return current_url
