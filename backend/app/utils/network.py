"""
app/utils/network.py

Network safety and DNS Rebinding prevention.

Why this is needed:
An attacker might register a public domain (e.g., evil-domain.com) that points
to a benign public IP at registration time, but subsequently updates the DNS
A-record so evil-domain.com resolves to 127.0.0.1 or 169.254.169.254.

Mitigation:
Before any external HTTP request is made, resolve_and_verify_host() performs
a live DNS lookup and verifies that ALL returned IP addresses are public and
safe. If any IP resolves to a private, loopback, or cloud metadata address,
the request is aborted immediately before establishing a socket connection.
"""

import socket
import ipaddress
from urllib.parse import urlparse
from typing import List


class DNSRebindingError(Exception):
    """Raised when a target host resolves to a private or forbidden IP address."""
    pass


FORBIDDEN_IPS = {
    "169.254.169.254",  # Cloud metadata
    "169.254.169.253",
}


def verify_ip_safety(ip_str: str) -> None:
    """Checks an individual IP string against forbidden/private ranges."""
    if ip_str in FORBIDDEN_IPS:
        raise DNSRebindingError(f"DNS Rebinding Protection: IP {ip_str} is a forbidden metadata target.")

    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            raise DNSRebindingError(f"DNS Rebinding Protection: IP {ip_str} resolves to a loopback address.")
        if ip.is_link_local:
            raise DNSRebindingError(f"DNS Rebinding Protection: IP {ip_str} resolves to a link-local address.")
        if ip.is_private:
            raise DNSRebindingError(f"DNS Rebinding Protection: IP {ip_str} resolves to a private network.")
        if ip.is_multicast:
            raise DNSRebindingError(f"DNS Rebinding Protection: IP {ip_str} resolves to a multicast address.")
        if ip.is_reserved:
            raise DNSRebindingError(f"DNS Rebinding Protection: IP {ip_str} resolves to a reserved address.")
        if ip.is_unspecified:
            raise DNSRebindingError(f"DNS Rebinding Protection: IP {ip_str} resolves to an unspecified address.")
    except ValueError as exc:
        raise DNSRebindingError(f"Invalid IP address returned from DNS lookup: {ip_str}") from exc


def resolve_and_verify_host(url_or_hostname: str) -> List[str]:
    """
    Parses hostname, executes DNS resolution, and validates all resolved IP addresses.
    Returns the list of verified safe IPs.
    Raises DNSRebindingError if resolution fails or resolves to an unsafe IP.
    """
    if "://" in url_or_hostname:
        parsed = urlparse(url_or_hostname)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    else:
        hostname = url_or_hostname
        port = 80

    if not hostname:
        raise DNSRebindingError("Cannot resolve empty hostname.")

    # 1. First check if hostname is already a raw IP
    try:
        ipaddress.ip_address(hostname)
        verify_ip_safety(hostname)
        return [hostname]
    except ValueError:
        pass  # It's a domain name, proceed with DNS lookup

    # 2. Perform live DNS resolution
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise DNSRebindingError(f"DNS resolution failed for hostname '{hostname}': {exc}") from exc

    resolved_ips = list({item[4][0] for item in addr_info})

    if not resolved_ips:
        raise DNSRebindingError(f"No IP addresses resolved for hostname '{hostname}'.")

    # 3. Verify every resolved IP
    for resolved_ip in resolved_ips:
        verify_ip_safety(resolved_ip)

    return resolved_ips
