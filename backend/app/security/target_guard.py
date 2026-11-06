"""Target guard: decides whether SentinelQA may send traffic to a URL.

This is the platform's main defence against misuse and SSRF (Server-Side
Request Forgery: tricking a server into making requests to places the
attacker cannot reach directly, such as cloud metadata services or the
internal network).

A URL is accepted only if ALL of these hold:
1. The scheme is http or https, with no credentials, query or fragment.
2. The host name is exactly on the ALLOWED_TARGET_HOSTS list (server-side
   configuration; users cannot change it from the UI).
3. The host resolves, and EVERY address it resolves to is acceptable:
   - link-local / cloud metadata / multicast / reserved ranges: always blocked;
   - private or loopback addresses: only for hosts on ALLOWED_PRIVATE_LAB_HOSTS.
4. A lab target (allowed to receive active security tests) must be a host on
   ALLOWED_PRIVATE_LAB_HOSTS.

The worker calls validate_target() again right before scanning, because DNS
answers can change between registration and scan time (DNS rebinding).
"""

import ipaddress
import socket
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

from app.config import Settings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

ALLOWED_SCHEMES = frozenset({"http", "https"})
MAX_URL_LENGTH = 2048
FORBIDDEN_CHARACTERS = frozenset(" \t\r\n\\")

# Never reachable through SentinelQA, even for lab hosts.
ALWAYS_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",  # "this network"
        "169.254.0.0/16",  # link-local, includes cloud metadata 169.254.169.254
        "100.100.100.200/32",  # Alibaba Cloud metadata
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved
        "255.255.255.255/32",  # broadcast
        "::/128",  # unspecified
        "fe80::/10",  # IPv6 link-local
        "fd00:ec2::254/128",  # AWS metadata over IPv6
        "ff00::/8",  # IPv6 multicast
    )
)


class TargetValidationError(ValueError):
    """Raised with a message that is safe to show to the user."""


class AddressKind(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class ValidatedTarget:
    base_url: str
    host: str
    port: int
    addresses: tuple[str, ...]
    is_private: bool


def resolve_host(host: str, port: int) -> list[str]:
    """Return every IP address the host resolves to (tests replace this function)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise TargetValidationError("Target host could not be resolved") from exc
    return sorted({str(info[4][0]) for info in infos})


def normalize_ip(raw: str) -> IPAddress:
    ip = ipaddress.ip_address(raw)
    # "::ffff:169.254.169.254" is IPv4 wearing an IPv6 costume: judge the IPv4 address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def classify_address(ip: IPAddress) -> AddressKind:
    for network in ALWAYS_BLOCKED_NETWORKS:
        if ip.version == network.version and ip in network:
            return AddressKind.BLOCKED
    # is_global is False for loopback, RFC 1918, carrier-grade NAT, documentation ranges...
    if not ip.is_global:
        return AddressKind.PRIVATE
    return AddressKind.PUBLIC


def validate_target(url: str, settings: Settings, *, is_lab: bool = False) -> ValidatedTarget:
    url = url.strip()
    if not url or len(url) > MAX_URL_LENGTH:
        raise TargetValidationError(f"URL must be between 1 and {MAX_URL_LENGTH} characters")
    if any(character in FORBIDDEN_CHARACTERS for character in url):
        raise TargetValidationError("URL contains spaces, backslashes or control characters")

    try:
        parts = urlsplit(url)
        port_in_url = parts.port  # raises ValueError for a bad port such as :99999
    except ValueError as exc:
        raise TargetValidationError("URL is malformed or has an invalid port") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetValidationError("Only http:// and https:// URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise TargetValidationError("URL must not contain a username or password")
    if parts.query or parts.fragment:
        raise TargetValidationError("Base URL must not contain a query string or fragment")

    host = (parts.hostname or "").rstrip(".")  # hostname is already lower-case
    if not host:
        raise TargetValidationError("URL must include a host name")

    if host not in settings.target_hosts:
        raise TargetValidationError(
            "Host is not an authorized target. An administrator must add it to "
            "ALLOWED_TARGET_HOSTS in the server configuration."
        )
    is_lab_host = host in settings.private_lab_hosts
    if is_lab and not is_lab_host:
        raise TargetValidationError(
            "Only hosts listed in ALLOWED_PRIVATE_LAB_HOSTS can be marked as lab targets"
        )

    port = port_in_url or (443 if scheme == "https" else 80)
    addresses = resolve_host(host, port)
    if not addresses:
        raise TargetValidationError("Target host could not be resolved")

    is_private = False
    for raw_address in addresses:
        try:
            ip = normalize_ip(raw_address)
        except ValueError as exc:
            raise TargetValidationError("Target resolved to an invalid address") from exc
        kind = classify_address(ip)
        if kind is AddressKind.BLOCKED:
            raise TargetValidationError("Target resolves to a blocked address range")
        if kind is AddressKind.PRIVATE:
            if not is_lab_host:
                raise TargetValidationError(
                    "Target resolves to a private or internal address. Only hosts listed "
                    "in ALLOWED_PRIVATE_LAB_HOSTS may do that."
                )
            is_private = True

    display_host = f"[{host}]" if ":" in host else host
    netloc = display_host if port_in_url is None else f"{display_host}:{port_in_url}"
    base_url = urlunsplit((scheme, netloc, parts.path or "/", "", ""))
    return ValidatedTarget(
        base_url=base_url,
        host=host,
        port=port,
        addresses=tuple(addresses),
        is_private=is_private,
    )
