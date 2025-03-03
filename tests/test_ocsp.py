"""Tests for OCSP functionality"""

import datetime
import logging
import os
import tempfile

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp

from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest

# Configure logging
logger = logging.getLogger(__name__)


@pytest_asyncio.fixture
async def ocsp_setup():
    """Setup CA and certificates for OCSP testing"""
    # Initialize CA
    with tempfile.TemporaryDirectory(dir="/tmp") as base_dir:
        ca = CertificateAuthority(base_dir)
        await ca.initialize(common_name="Test OCSP CA", org="Test Corp", country="US")
        logger.debug("CA initialized")

        # Create OCSP responder certificate
        responder_request = CertificateRequest(
            common_name="ocsp.test.com",
            organization="Test Corp",
            country="US",
            extended_key_usage=["1.3.6.1.5.5.7.3.9"],  # OCSP Signing
            key_usage={
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": False,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
                "encipher_only": False,
                "decipher_only": False,
            },
        )
        responder_cert = await ca.issue_certificate(responder_request, cert_type="server")

        # Create test certificate
        test_request = CertificateRequest(
            common_name="test.example.com",
            organization="Test Corp",
            country="US",
            san_dns_names=["test.example.com"],
            valid_days=365,
        )
        test_cert = await ca.issue_certificate(test_request, cert_type="server")

        yield ca, responder_cert, test_cert


async def create_ocsp_request(issuer_cert, cert):
    """Create an OCSP request for testing"""
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        cert=cert.certificate,
        issuer=issuer_cert.ca_cert,
        algorithm=hashes.SHA256())
    return builder.build()


async def create_ocsp_response(
        issuer_cert,
        cert,
        responder_cert,
        cert_status="good"):
    """Create an OCSP response for testing"""
    # Create request first
    ocsp_req = await create_ocsp_request(issuer_cert, cert)

    # Set status
    if cert_status == "revoked":
        status = ocsp.OCSPCertStatus.REVOKED
        revocation_time = datetime.datetime.now()
        revocation_reason = x509.ReasonFlags.key_compromise
    else:
        status = ocsp.OCSPCertStatus.GOOD
        revocation_time = None
        revocation_reason = None

    # Build response
    builder = ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=cert.certificate,
        issuer=issuer_cert.ca_cert,
        algorithm=hashes.SHA256(),
        cert_status=status,
        this_update=datetime.datetime.now(),
        next_update=datetime.datetime.now() + datetime.timedelta(days=1),
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
    )

    # Add responder ID
    builder = builder.responder_id(
        ocsp.OCSPResponderEncoding.HASH,
        responder_cert.certificate)

    # Sign response with responder key
    return builder.sign(
        private_key=responder_cert.private_key,
        algorithm=hashes.SHA256())


@pytest.mark.asyncio
async def test_ocsp_request_creation(ocsp_setup):
    """Test creating an OCSP request"""
    ca, responder_cert, test_cert = ocsp_setup

    request = await create_ocsp_request(ca, test_cert)
    assert isinstance(request, ocsp.OCSPRequest)


@pytest.mark.asyncio
async def test_ocsp_response_good_certificate(ocsp_setup):
    """Test OCSP response for a valid certificate"""
    ca, responder_cert, test_cert = ocsp_setup

    response = await create_ocsp_response(ca, test_cert, responder_cert)
    assert isinstance(response, ocsp.OCSPResponse)
    assert response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL


@pytest.mark.asyncio
async def test_ocsp_response_revoked_certificate(ocsp_setup):
    """Test OCSP response for a revoked certificate"""
    ca, responder_cert, test_cert = ocsp_setup

    # Revoke the certificate
    await ca.revoke_certificate(test_cert.serial_number)

    response = await create_ocsp_response(ca, test_cert, responder_cert, cert_status="revoked")
    assert isinstance(response, ocsp.OCSPResponse)
    assert response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL


@pytest.mark.asyncio
async def test_ocsp_response_verification(ocsp_setup):
    """Test verifying an OCSP response"""
    ca, responder_cert, test_cert = ocsp_setup

    response = await create_ocsp_response(ca, test_cert, responder_cert)
    assert isinstance(response, ocsp.OCSPResponse)
    assert response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL


@pytest.mark.asyncio
async def test_ocsp_response_with_nonce(ocsp_setup):
    """Test OCSP response with nonce extension"""
    ca, responder_cert, test_cert = ocsp_setup

    # Create request with nonce
    builder = ocsp.OCSPRequestBuilder()
    nonce = os.urandom(16)
    builder = builder.add_certificate(
        cert=test_cert.certificate,
        issuer=ca.ca_cert,
        algorithm=hashes.SHA256()).add_extension(
        x509.OCSPNonce(nonce),
        critical=False)
    request = builder.build()

    # Create response
    response = await create_ocsp_response(ca, test_cert, responder_cert)
    assert isinstance(response, ocsp.OCSPResponse)
    assert response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
