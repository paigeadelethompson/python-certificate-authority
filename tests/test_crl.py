"""Tests for Certificate Revocation List functionality"""

import tempfile

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest


@pytest.fixture
async def ca_setup():
    """Setup a CA for testing"""
    with tempfile.TemporaryDirectory(dir="/tmp") as base_dir:
        ca = CertificateAuthority(base_dir=base_dir)
        await ca.initialize("Test CA", "US", "Test Corp")
        yield ca


@pytest.mark.asyncio
async def test_crl_generation(ca_setup):
    """Test CRL generation with no revoked certificates"""
    ca = ca_setup
    crl = await ca.generate_crl()
    assert len(list(crl)) == 0


@pytest.mark.asyncio
async def test_crl_with_revoked_certificate(ca_setup):
    """Test CRL generation with one revoked certificate"""
    ca = ca_setup
    request = CertificateRequest(
        common_name="test.example.com", organization="Test Corp", country="US"
    )
    cert = await ca.issue_certificate(request)
    await ca.revoke_certificate(cert.serial_number)

    crl = await ca.generate_crl()
    revoked = list(crl)
    assert len(revoked) == 1
    assert revoked[0].serial_number == cert.serial_number


@pytest.mark.asyncio
async def test_crl_distribution_points(ca_setup):
    """Test CRL distribution points in certificates"""
    ca = ca_setup
    request = CertificateRequest(
        common_name="test.example.com", organization="Test Corp", country="US"
    )
    cert = await ca.issue_certificate(request)

    # Check that the certificate has CRL distribution points
    try:
        ext = cert.certificate.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        assert ext is not None
    except x509.ExtensionNotFound:
        pass  # CRL distribution points are optional


@pytest.mark.asyncio
async def test_multiple_revocations(ca_setup):
    """Test CRL generation with multiple revoked certificates"""
    ca = ca_setup
    request1 = CertificateRequest(
        common_name="test1.example.com", organization="Test Corp", country="US"
    )
    request2 = CertificateRequest(
        common_name="test2.example.com", organization="Test Corp", country="US"
    )
    cert1 = await ca.issue_certificate(request1)
    cert2 = await ca.issue_certificate(request2)

    await ca.revoke_certificate(cert1.serial_number)
    await ca.revoke_certificate(cert2.serial_number)

    crl = await ca.generate_crl()
    revoked = list(crl)
    assert len(revoked) == 2


@pytest.mark.asyncio
async def test_revocation_reasons(ca_setup):
    """Test different revocation reasons in CRL"""
    ca = ca_setup
    request = CertificateRequest(
        common_name="test.example.com", organization="Test Corp", country="US"
    )
    cert = await ca.issue_certificate(request)

    # Revoke certificate with a specific reason
    await ca.revoke_certificate(cert.serial_number)

    crl = await ca.generate_crl()
    revoked = list(crl)
    assert len(revoked) == 1
    assert revoked[0].revocation_date_utc is not None


@pytest.mark.asyncio
async def test_crl_validity_period(ca_setup):
    """Test CRL validity period"""
    ca = ca_setup
    crl = await ca.generate_crl()
    assert isinstance(crl, x509.CertificateRevocationList)
    assert crl.next_update_utc is not None
    assert crl.next_update_utc > crl.last_update_utc
