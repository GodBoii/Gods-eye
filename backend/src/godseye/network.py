# SPDX-License-Identifier: Apache-2.0
"""Bounded HTTP/1.1 requests with explicit DNS pinning and TLS hostname verification."""

import asyncio
import ipaddress
import re
import socket
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import quote, urlsplit

import h11

IP = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], Awaitable[list[str]]]
PUBLIC_DENY = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "2001:db8::/32",
        "2001::/23",
        "2002::/16",
        "64:ff9b::/96",
    )
)
V6_GLOBAL = ipaddress.ip_network("2000::/3")
METADATA = ipaddress.ip_network("100.100.100.0/24")


def unmap(value: str) -> IP:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise ValueError("scoped addresses are not supported")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def public_ip(value: str) -> bool:
    try:
        address = unmap(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address not in V6_GLOBAL:
        return False
    return not any(address in network for network in PUBLIC_DENY)


def diagnostic_ip(value: str) -> bool:
    try:
        address = unmap(value)
    except ValueError:
        return False
    return not (
        address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or str(address) == "255.255.255.255"
        or address in METADATA
    )


def valid_host(value: str) -> bool:
    if not value or len(value) > 253 or any(c in value for c in "/\\@?#%\0\t\r\n "):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in value.removesuffix(".").split(".")
        )


async def resolve(host: str) -> list[str]:
    try:
        entries = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ValueError("DNS lookup failed") from error
    addresses = list(dict.fromkeys(str(entry[4][0]) for entry in entries))
    if not addresses:
        raise ValueError("DNS returned no addresses")
    return addresses


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    headers: dict[str, str]
    certificate_expiry: datetime | None


async def head(
    target: str,
    *,
    resolver: Resolver = resolve,
    policy: Literal["public", "diagnostic"] = "public",
    context: ssl.SSLContext | None = None,
) -> Response:
    """One HEAD response. No redirects, cookies, proxy environment or body collection.

    Public callers validate port 443 before calling. The diagnostic policy and
    injected trust store allow real local TLS tests without weakening production.
    """
    try:
        parsed = urlsplit(target)
        host = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(ord(c) < 32 for c in target)
            or re.search(r"%(?![0-9a-fA-F]{2})", target)
        ):
            raise ValueError("invalid URL")
        port = parsed.port or 443
        logical_host = host.encode("idna").decode("ascii")
    except (ValueError, UnicodeError) as error:
        raise ValueError(
            "use an HTTPS URL without credentials, query parameters or fragments"
        ) from error
    tls = context if context is not None else ssl.create_default_context()
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    if tls.verify_mode != ssl.CERT_REQUIRED or not tls.check_hostname:
        raise ValueError("HTTPS checks require certificate and hostname verification")
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(10):
            addresses = await resolver(logical_host)
            if not addresses:
                raise ValueError("DNS returned no addresses")
            allowed = public_ip if policy == "public" else diagnostic_ip
            if not all(allowed(address) for address in addresses):
                raise ValueError("private, local and reserved destinations are not supported")
            # Preserve HEAD's first-address semantics. Passing a numeric address
            # avoids a second lookup; TLS SNI/verification use the logical host.
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    str(unmap(addresses[0])),
                    port,
                    ssl=tls,
                    server_hostname=logical_host,
                    ssl_handshake_timeout=5,
                    limit=64 << 10,
                ),
                5,
            )
            assert writer is not None
            ssl_object = writer.get_extra_info("ssl_object")
            expiry = None
            if ssl_object is not None:
                certificate = ssl_object.getpeercert()
                if certificate and certificate.get("notAfter"):
                    expiry = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(certificate["notAfter"]), UTC
                    )
            connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=64 << 10)
            authority = f"[{logical_host}]" if ":" in logical_host else logical_host
            if port != 443:
                authority += f":{port}"
            path = quote(parsed.path or "/", safe="/%:@&=+$,;~!*'()-._")
            encoded = connection.send(
                h11.Request(
                    method=b"HEAD",
                    target=path.encode("ascii"),
                    headers=[
                        (b"Host", authority.encode("ascii")),
                        (b"User-Agent", b"GodsEye/0.2 authorized-header-check"),
                        (b"Connection", b"close"),
                    ],
                )
            )
            if encoded is not None:
                writer.write(encoded)
            ending = connection.send(h11.EndOfMessage())
            if ending is not None:
                writer.write(ending)
            await writer.drain()
            informational = 0
            while True:
                event = connection.next_event()
                if event is h11.NEED_DATA:
                    data = await asyncio.wait_for(reader.read(16 << 10), 5)
                    connection.receive_data(data)
                    if not data:
                        raise ValueError("HTTPS response ended before its headers")
                elif isinstance(event, h11.Response):
                    if sum(len(k) + len(v) + 4 for k, v in event.headers) > 64 << 10:
                        raise ValueError("HTTPS response headers exceeded the limit")
                    headers: dict[str, str] = {}
                    for key, value in event.headers:
                        headers.setdefault(key.decode("ascii").lower(), value.decode("latin-1"))
                    return Response(event.status_code, headers, expiry)
                elif isinstance(event, h11.InformationalResponse):
                    informational += 1
                    if informational > 16 or event.status_code == 101:
                        raise ValueError("Unsupported HTTPS informational response")
                else:
                    raise ValueError("Invalid HTTPS response")
    except (OSError, TimeoutError, h11.ProtocolError) as error:
        raise ValueError("HTTPS request failed") from error
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (OSError, TimeoutError):
                writer.transport.abort()
