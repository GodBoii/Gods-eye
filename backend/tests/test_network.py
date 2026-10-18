# SPDX-License-Identifier: Apache-2.0
"""Transfers webcheck tests and proves real pinned TLS with local certificates."""

import asyncio
import ipaddress
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from godseye.network import Response, diagnostic_ip, head, public_ip, valid_host
from godseye.webcheck import evaluate, inspect


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.1.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "198.18.0.1",
        "192.0.2.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "64:ff9b::a00:1",
        "2001:db8::1",
        "2002:7f00:1::",
        "0.1.2.3",
        "224.0.0.1",
        "255.255.255.255",
        "240.0.0.1",
        "2001:1::1",
        "2606:4700::1111%eth0",
    ],
)
def test_public_address_policy_rejects(value: str) -> None:
    assert not public_ip(value)


@pytest.mark.parametrize(
    "value", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8", "192.0.1.1"]
)
def test_public_address_policy_accepts(value: str) -> None:
    assert public_ip(value)


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com",
        "https://user:password@example.com",
        "https://example.com/?token=secret",
        "https://example.com:8080",
        "https://127.0.0.1",
        "https://[::1]",
        "https://example.com/#secret",
        "https://example.com:bad",
        "https://example.com/%zz",
        "https://example.com/\r\n",
    ],
)
def test_unsafe_urls_rejected_without_input_echo(target: str) -> None:
    with pytest.raises(ValueError) as error:
        asyncio.run(inspect(target, "website"))
    assert "password" not in str(error.value) and "token=" not in str(error.value)


def test_header_evaluation_never_equates_presence_with_protection() -> None:
    now = datetime(2026, 10, 18, tzinfo=UTC)
    response = Response(
        302,
        {"strict-transport-security": "max-age=0", "x-content-type-options": "nosniff"},
        now + timedelta(days=20),
    )
    checks = {item["name"]: item for item in evaluate(response, "api", now)}
    assert checks["Strict-Transport-Security"]["status"] == "observed"
    assert checks["X-Content-Type-Options"]["status"] == "pass"
    assert checks["TLS certificate"]["status"] == "review"
    assert "Browser content policy" not in checks
    assert checks["Coverage"]["status"] == "limited"
    assert any(
        item["status"] == "review" and item["name"] == "Browser content policy"
        for item in evaluate(response, "website", now)
    )


@pytest.fixture
def tls_contexts(tmp_path: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.invalid")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=60))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("fixture.invalid")]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert = tmp_path / "certificate.pem"
    private = tmp_path / "private.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, private)
    client = ssl.create_default_context(cafile=str(cert))
    return server, client


def test_pinned_tls_preserves_host_verifies_certificate_and_ignores_proxy(
    tls_contexts: tuple[ssl.SSLContext, ssl.SSLContext],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")

    async def exercise() -> None:
        observed = []
        calls = []

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                observed.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(
                    b"HTTP/1.1 302 Found\r\nLocation: https://outside.invalid/\r\n"
                    b"X-Content-Type-Options: nosniff\r\nContent-Length: 0\r\n\r\n"
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        async def resolver(host: str) -> list[str]:
            calls.append(host)
            return ["127.0.0.1"]

        async def forbidden_lookup(*_: object, **__: object) -> list:
            pytest.fail("dialing performed a second DNS lookup")

        server_context, client_context = tls_contexts
        async with await asyncio.start_server(
            handler, "127.0.0.1", 0, ssl=server_context
        ) as server:
            port = server.sockets[0].getsockname()[1]
            monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", forbidden_lookup)
            response = await head(
                f"https://fixture.invalid:{port}/",
                resolver=resolver,
                policy="diagnostic",
                context=client_context,
            )
            assert response.status == 302 and response.certificate_expiry is not None
            assert calls == ["fixture.invalid"] and len(observed) == 1
            assert f"Host: fixture.invalid:{port}".lower().encode() in observed[0].lower()
            assert b"HEAD / HTTP/1.1" in observed[0]
            assert b"Cookie:" not in observed[0] and b"Authorization:" not in observed[0]
            # Same address and trusted certificate, but a different logical name.
            with pytest.raises(ValueError, match="HTTPS request failed"):
                await head(
                    f"https://wrong.invalid:{port}/",
                    resolver=resolver,
                    policy="diagnostic",
                    context=client_context,
                )
            with pytest.raises(ValueError, match="HTTPS request failed"):
                await head(
                    f"https://fixture.invalid:{port}/", resolver=resolver, policy="diagnostic"
                )

    asyncio.run(exercise())


def test_mixed_answers_rejected_before_dial() -> None:
    async def resolver(_: str) -> list[str]:
        return ["8.8.8.8", "127.0.0.1"]

    with pytest.raises(ValueError, match="reserved destinations"):
        asyncio.run(head("https://fixture.invalid", resolver=resolver))


def test_diagnostic_policy_and_host_grammar() -> None:
    assert diagnostic_ip("127.0.0.1") and diagnostic_ip("192.168.1.1")
    assert not diagnostic_ip("169.254.169.254") and not diagnostic_ip("100.100.100.200")
    assert not diagnostic_ip("::ffff:169.254.169.254")
    assert valid_host("example.com.") and valid_host("127.0.0.1") and valid_host("::1")
    assert not valid_host("example.com/path") and not valid_host("-bad.example")
    assert not valid_host("user@example.com")
    assert not valid_host("a" * 64 + ".example")
    assert ipaddress.ip_address("127.0.0.1").is_loopback
