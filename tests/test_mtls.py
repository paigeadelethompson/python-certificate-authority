"""Tests for mutual TLS (mTLS) functionality"""

import datetime
import os
import ssl
import tempfile

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from cryptography.hazmat.primitives import serialization

from CA import CertificateAuthority
from CA.constants import ExtendedKeyUsage, KeyUsage
from CA.models.certificate import CertificateRequest


@pytest_asyncio.fixture
async def mtls_setup():
    """Setup CA and certificates for mTLS testing"""
    # Initialize CA
    with tempfile.TemporaryDirectory(dir="/tmp") as base_dir:
        ca = CertificateAuthority(base_dir)
        await ca.initialize(common_name="Test mTLS CA", org="Test Corp", country="US")

        # Create server certificate
        server_request = CertificateRequest(
            common_name="localhost",
            organization="Test Corp",
            country="US",
            san_dns_names=["localhost"],
            valid_days=365,
            key_usage=KeyUsage.SERVER,
            extended_key_usage=[ExtendedKeyUsage.SERVER_AUTH],
        )
        server_cert = await ca.issue_certificate(server_request, cert_type="server")

        # Create client certificate
        client_request = CertificateRequest(
            common_name="test-client",
            organization="Test Corp",
            country="US",
            valid_days=365,
            key_usage=KeyUsage.CLIENT,
            extended_key_usage=[ExtendedKeyUsage.CLIENT_AUTH],
        )
        client_cert = await ca.issue_certificate(client_request, cert_type="client")

        yield ca, server_cert, client_cert


async def create_test_server(ssl_context):
    """Create a test HTTPS server requiring client certificates"""

    async def handle_request(request):
        # Verify client certificate is present
        assert request.transport.get_extra_info("peercert") is not None
        return web.Response(text="Success")

    app = web.Application()
    app.router.add_get("/", handle_request)

    runner = web.AppRunner(app)
    await runner.setup()

    # Configure SSL context for client authentication
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.purpose = ssl.Purpose.CLIENT_AUTH

    site = web.TCPSite(runner, "localhost", 8443, ssl_context=ssl_context)
    await site.start()

    return runner


@pytest.mark.asyncio
async def test_mtls_successful_connection(mtls_setup):
    """Test successful mTLS connection"""
    ca, server_cert, client_cert = mtls_setup

    # Create server SSL context
    server_ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH)
    server_ssl_context.load_verify_locations(
        cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    )
    server_ssl_context.load_cert_chain(
        certfile=os.path.join(ca.store.base_dir, "localhost.crt"),
        keyfile=os.path.join(ca.store.base_dir, "localhost.key"),
    )
    server_ssl_context.verify_mode = ssl.CERT_REQUIRED

    server = await create_test_server(server_ssl_context)

    try:
        # Create client SSL context
        client_ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH)
        client_ssl_context.load_verify_locations(
            cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        )
        client_ssl_context.load_cert_chain(
            certfile=os.path.join(ca.store.base_dir, "test-client.crt"),
            keyfile=os.path.join(ca.store.base_dir, "test-client.key"),
        )

        async with aiohttp.ClientSession() as session:
            async with session.get("https://localhost:8443", ssl=client_ssl_context) as response:
                assert response.status == 200
                text = await response.text()
                assert text == "Success"
    finally:
        await server.cleanup()


@pytest.mark.asyncio
async def test_mtls_missing_client_cert(mtls_setup):
    """Test connection failure when client certificate is missing"""
    ca, server_cert, client_cert = mtls_setup

    # Create server SSL context
    server_ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH)
    server_ssl_context.load_verify_locations(
        cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    )
    server_ssl_context.load_cert_chain(
        certfile=os.path.join(ca.store.base_dir, "localhost.crt"),
        keyfile=os.path.join(ca.store.base_dir, "localhost.key"),
    )
    server_ssl_context.verify_mode = ssl.CERT_REQUIRED

    server = await create_test_server(server_ssl_context)

    try:
        # Create client SSL context without client certificate
        client_ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH)
        client_ssl_context.load_verify_locations(
            cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        )

        async with aiohttp.ClientSession() as session:
            with pytest.raises((aiohttp.ServerDisconnectedError, aiohttp.ClientOSError)):
                async with session.get(
                    "https://localhost:8443", ssl=client_ssl_context
                ) as response:
                    await response.text()
    finally:
        await server.cleanup()


@pytest.mark.asyncio
async def test_mtls_revoked_client_cert(mtls_setup):
    """Test connection failure with revoked client certificate"""
    ca, server_cert, client_cert = mtls_setup

    # Revoke client certificate
    await ca.revoke_certificate(client_cert.serial_number)

    # Generate CRL
    crl = await ca.generate_crl()
    crl_path = os.path.join(ca.store.base_dir, "crl", "ca.crl")
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    # Create server SSL context
    server_ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH)
    server_ssl_context.load_verify_locations(
        cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    )
    server_ssl_context.load_cert_chain(
        certfile=os.path.join(ca.store.base_dir, "localhost.crt"),
        keyfile=os.path.join(ca.store.base_dir, "localhost.key"),
    )
    server_ssl_context.verify_mode = ssl.CERT_REQUIRED
    server_ssl_context.verify_flags = ssl.VERIFY_CRL_CHECK_CHAIN | ssl.VERIFY_X509_STRICT
    server_ssl_context.load_verify_locations(cafile=crl_path)

    server = await create_test_server(server_ssl_context)

    try:
        # Create client SSL context with revoked certificate
        client_ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH)
        client_ssl_context.load_verify_locations(
            cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        )
        client_ssl_context.load_cert_chain(
            certfile=os.path.join(ca.store.base_dir, "test-client.crt"),
            keyfile=os.path.join(ca.store.base_dir, "test-client.key"),
        )

        async with aiohttp.ClientSession() as session:
            with pytest.raises(
                aiohttp.ServerDisconnectedError
            ):  # Server will disconnect when cert is revoked
                async with session.get(
                    "https://localhost:8443", ssl=client_ssl_context
                ) as response:
                    await response.text()
    finally:
        await server.cleanup()


@pytest.mark.asyncio
async def test_mtls_expired_client_cert(mtls_setup):
    """Test connection failure with expired client certificate"""
    ca, server_cert, client_cert = mtls_setup

    # Create a new expired client certificate
    expired_client_request = CertificateRequest(
        common_name="expired-client",
        organization="Test Corp",
        country="US",
        not_valid_before=datetime.datetime(
            2020,
            1,
            1,
            tzinfo=datetime.timezone.utc),
        not_valid_after=datetime.datetime(
            2020,
            12,
            31,
            tzinfo=datetime.timezone.utc),
        key_usage=KeyUsage.CLIENT,
        extended_key_usage=[
            ExtendedKeyUsage.CLIENT_AUTH],
    )
    expired_client_cert = await ca.issue_certificate(expired_client_request, cert_type="client")

    # Create server SSL context
    server_ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH)
    server_ssl_context.load_verify_locations(
        cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    )
    server_ssl_context.load_cert_chain(
        certfile=os.path.join(ca.store.base_dir, "localhost.crt"),
        keyfile=os.path.join(ca.store.base_dir, "localhost.key"),
    )
    server_ssl_context.verify_mode = ssl.CERT_REQUIRED

    server = await create_test_server(server_ssl_context)

    try:
        # Create client SSL context with expired certificate
        client_ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH)
        client_ssl_context.load_verify_locations(
            cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        )
        client_ssl_context.load_cert_chain(
            certfile=os.path.join(ca.store.base_dir, "expired-client.crt"),
            keyfile=os.path.join(ca.store.base_dir, "expired-client.key"),
        )

        async with aiohttp.ClientSession() as session:
            with pytest.raises((aiohttp.ServerDisconnectedError, aiohttp.ClientOSError)):
                async with session.get(
                    "https://localhost:8443", ssl=client_ssl_context
                ) as response:
                    await response.text()
    finally:
        await server.cleanup()


@pytest.mark.asyncio
async def test_mtls_wrong_key_usage(mtls_setup):
    """Test connection failure with certificate having wrong key usage"""
    ca, server_cert, client_cert = mtls_setup

    # Create a new client certificate with wrong key usage (server usage
    # instead of client)
    wrong_usage_request = CertificateRequest(
        common_name="wrong-usage-client",
        organization="Test Corp",
        country="US",
        valid_days=365,
        key_usage=KeyUsage.SERVER,  # Wrong usage for a client cert
        extended_key_usage=[
            ExtendedKeyUsage.SERVER_AUTH],
        # Wrong EKU for a client cert
    )
    wrong_usage_cert = await ca.issue_certificate(wrong_usage_request, cert_type="client")

    # Create server SSL context
    server_ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH)
    server_ssl_context.load_verify_locations(
        cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    )
    server_ssl_context.load_cert_chain(
        certfile=os.path.join(ca.store.base_dir, "localhost.crt"),
        keyfile=os.path.join(ca.store.base_dir, "localhost.key"),
    )
    server_ssl_context.verify_mode = ssl.CERT_REQUIRED
    # Enable strict certificate checking
    server_ssl_context.verify_flags = ssl.VERIFY_X509_STRICT

    server = await create_test_server(server_ssl_context)

    try:
        # Create client SSL context with wrong key usage
        client_ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH)
        client_ssl_context.load_verify_locations(
            cadata=ca.ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        )
        client_ssl_context.load_cert_chain(
            certfile=os.path.join(ca.store.base_dir, "wrong-usage-client.crt"),
            keyfile=os.path.join(ca.store.base_dir, "wrong-usage-client.key"),
        )

        async with aiohttp.ClientSession() as session:
            with pytest.raises(
                aiohttp.ServerDisconnectedError
            ):  # Server will disconnect when cert has wrong usage
                async with session.get(
                    "https://localhost:8443", ssl=client_ssl_context
                ) as response:
                    await response.text()
    finally:
        await server.cleanup()
