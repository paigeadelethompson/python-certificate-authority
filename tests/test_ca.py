"""
Tests for the certificate authority functionality
"""

import logging
import os
import tempfile
from pathlib import Path

import jks
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest
from CA.utils.pkcs import PKCS12Helper

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
async def ca(temp_dir):
    """Create a temporary CA for testing"""
    ca = CertificateAuthority(temp_dir)
    await ca.initialize(
        common_name="Test CA",
        country="US",
        state="California",
        locality="San Francisco",
        org="Test Org",
        org_unit="IT",
    )
    return ca


@pytest.mark.asyncio
async def test_ca_initialization(ca, temp_dir):
    """Test CA initialization"""
    # Check directory structure
    base_path = Path(temp_dir)
    assert (base_path / "ca").exists()
    assert (base_path / "sub-ca").exists()
    assert (base_path / "server-certs").exists()
    assert (base_path / "client-certs").exists()
    assert (base_path / "crl").exists()
    assert (base_path / "cert-db.json").exists()

    # Load CA certificate
    ca_cert = await ca.store.load_ca_cert()
    assert ca_cert is not None

    # Check CA certificate attributes
    subject = ca_cert.subject
    assert subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
        0].value == "Test CA"
    assert subject.get_attributes_for_oid(
        x509.NameOID.COUNTRY_NAME)[0].value == "US"
    assert (subject.get_attributes_for_oid(
        x509.NameOID.STATE_OR_PROVINCE_NAME)[0].value == "California")
    assert subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)[
        0].value == "San Francisco"
    assert subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[
        0].value == "Test Org"
    assert subject.get_attributes_for_oid(
        x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "IT"

    # Check that it's a CA certificate
    basic_constraints = ca_cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.value.ca is True
    assert basic_constraints.critical is True

    # Check key usage
    key_usage = ca_cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.KEY_USAGE)
    assert key_usage.value.key_cert_sign is True
    assert key_usage.value.crl_sign is True
    assert key_usage.critical is True

    # Verify CA key pair
    ca_key = await ca.store.load_ca_key()
    assert ca_key is not None

    # Test that the public/private key pair matches
    message = b"test message"
    signature = ca_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    ca_cert.public_key().verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


@pytest.mark.asyncio
async def test_initialize_with_existing_ca(temp_dir):
    """Test initializing CA with existing key/cert"""
    # Create a CA
    ca1 = CertificateAuthority(temp_dir)
    await ca1.initialize(common_name="Test CA")

    # Get the CA key and cert
    ca_key = await ca1.store.load_ca_key()
    ca_cert = await ca1.store.load_ca_cert()

    key_data = ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_data = ca_cert.public_bytes(serialization.Encoding.PEM)

    # Create new CA instance with existing key/cert
    ca2 = CertificateAuthority(temp_dir, ca_key=key_data, ca_cert=cert_data)
    await ca2.initialize()

    # Verify the certificates match
    new_ca_cert = await ca2.store.load_ca_cert()
    assert new_ca_cert.public_bytes(serialization.Encoding.PEM) == cert_data


@pytest.mark.asyncio
async def test_issue_server_cert(ca):
    """Test issuing a server certificate"""
    request = CertificateRequest(
        common_name="test.example.com",
        country="US",
        organization="Test Org",
        organizational_unit="Web",
        san_dns_names=["test.example.com", "*.test.example.com"],
    )

    cert = await ca.issue_certificate(request, cert_type="server")
    assert cert is not None
    assert cert.common_name == "test.example.com"

    # Check that it's not a CA certificate
    basic_constraints = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.value.ca is False

    # Check SAN extension
    san = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "test.example.com" in dns_names
    assert "*.test.example.com" in dns_names

    # Check key usage
    key_usage = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.KEY_USAGE)
    assert key_usage.value.digital_signature is True
    assert key_usage.value.key_encipherment is True
    assert key_usage.value.key_cert_sign is False

    # Check extended key usage
    ext_key_usage = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
    )
    assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in ext_key_usage.value


@pytest.mark.asyncio
async def test_issue_client_cert(ca):
    """Test issuing a client certificate"""
    request = CertificateRequest(
        common_name="user@example.com",
        country="US",
        organization="Test Org",
        organizational_unit="Users",
        email="user@example.com",
    )

    cert = await ca.issue_certificate(request, cert_type="client")
    assert cert is not None
    assert cert.common_name == "user@example.com"

    # Check extended key usage
    ext_key_usage = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
    )
    assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in ext_key_usage.value

    # Check email in subject alternative name
    san = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    emails = san.value.get_values_for_type(x509.RFC822Name)
    assert "user@example.com" in emails


@pytest.mark.asyncio
async def test_issue_sub_ca_cert(ca):
    """Test issuing a sub-CA certificate"""
    request = CertificateRequest(
        common_name="Sub CA",
        country="US",
        organization="Test Org",
        organizational_unit="PKI",
        is_ca=True,
        path_length=0,  # Can't issue further sub-CAs
    )

    cert = await ca.issue_certificate(request, cert_type="sub-ca")
    assert cert is not None
    assert cert.common_name == "Sub CA"

    # Check that it's a CA certificate with path length constraint
    basic_constraints = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 0
    assert basic_constraints.critical is True

    # Check key usage
    key_usage = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.KEY_USAGE)
    assert key_usage.value.key_cert_sign is True
    assert key_usage.value.crl_sign is True
    assert key_usage.critical is True


@pytest.mark.asyncio
async def test_certificate_revocation(ca):
    """Test certificate revocation"""
    # Issue a certificate
    request = CertificateRequest(
        common_name="test.example.com", country="US", organization="Test Org"
    )

    cert = await ca.issue_certificate(request, cert_type="server")
    serial = cert.serial_number

    # Revoke it
    await ca.revoke_certificate(serial)

    # Check that it's in the revoked list
    revoked = await ca.store.list_revoked()
    assert any(c["serial"] == serial for c in revoked)

    # Check that it's not in the active certificates
    active = await ca.store.list_certificates()
    assert not any(c["serial"] == serial for c in active)


@pytest.mark.asyncio
async def test_export_pkcs12(ca):
    """Test exporting a certificate as PKCS12"""
    request = CertificateRequest(
        common_name="test.example.com", country="US", organization="Test Org"
    )

    cert = await ca.issue_certificate(request, cert_type="server")
    pfx_data = await ca.export_pkcs12(cert, password="test123")

    # Try to load the PKCS12 file
    key, cert, chain = PKCS12Helper.load_pfx(pfx_data, "test123")
    assert key is not None
    assert cert is not None
    assert len(chain) == 1  # Should contain the CA cert


@pytest.mark.asyncio
async def test_export_jks(ca):
    """Test exporting a certificate as JKS"""
    request = CertificateRequest(
        common_name="test.example.com", country="US", organization="Test Org"
    )

    cert = await ca.issue_certificate(request, cert_type="server")
    jks_data = await ca.export_jks(cert, password="test123")

    # Try to load the JKS file
    ks = jks.KeyStore.loads(jks_data, "test123")
    assert len(ks.private_keys) == 1
    assert len(ks.certs) == 0  # Private key entry includes the cert chain


@pytest.mark.asyncio
async def test_certificate_store_persistence(temp_dir):
    """Test that certificates persist in the store"""
    # Create CA and issue certificate
    ca1 = CertificateAuthority(temp_dir)
    await ca1.initialize(common_name="Test CA")

    request = CertificateRequest(
        common_name="test.example.com", country="US", organization="Test Org"
    )

    cert1 = await ca1.issue_certificate(request, cert_type="server")
    serial = cert1.serial_number

    # Create new CA instance and check certificate exists
    ca2 = CertificateAuthority(temp_dir)
    cert_info = await ca2.store.get_certificate(serial)
    assert cert_info is not None
    assert cert_info["subject"]["common_name"] == "test.example.com"


@pytest.mark.asyncio
async def test_list_certificates_by_type(ca):
    """Test listing certificates by type"""
    # Issue certificates of different types
    server_req = CertificateRequest(
        common_name="server.example.com", country="US", organization="Test Org"
    )
    await ca.issue_certificate(server_req, cert_type="server")

    client_req = CertificateRequest(
        common_name="user@example.com", country="US", organization="Test Org"
    )
    await ca.issue_certificate(client_req, cert_type="client")

    # List by type
    server_certs = await ca.store.list_certificates(cert_type="server")
    assert len(server_certs) == 1
    assert server_certs[0]["subject"]["common_name"] == "server.example.com"

    client_certs = await ca.store.list_certificates(cert_type="client")
    assert len(client_certs) == 1
    assert client_certs[0]["subject"]["common_name"] == "user@example.com"


@pytest.mark.asyncio
async def test_certificate_validation(ca):
    """Test certificate validation and chain building"""
    logger.debug("Starting certificate validation test")

    # Issue a server certificate
    server_req = CertificateRequest(
        common_name="server.example.com", country="US", organization="Test Org"
    )
    logger.debug("Issuing server certificate")
    server_cert = await ca.issue_certificate(server_req, cert_type="server")

    # Issue a sub-CA certificate
    sub_ca_req = CertificateRequest(
        common_name="Sub CA",
        country="US",
        organization="Test Org",
        is_ca=True,
        path_length=0)
    logger.debug("Issuing sub-CA certificate")
    sub_ca_cert = await ca.issue_certificate(sub_ca_req, cert_type="sub-ca")

    # Create a new CA instance with the sub-CA
    logger.debug("Creating sub-CA instance")
    sub_ca_dir = os.path.join(ca.base_dir, "sub-ca-instance")
    sub_ca = CertificateAuthority(
        sub_ca_dir,
        ca_key=sub_ca_cert.private_key_to_pem(),
        ca_cert=sub_ca_cert.to_pem())
    await sub_ca.initialize()

    # Issue a certificate from the sub-CA
    leaf_req = CertificateRequest(
        common_name="leaf.example.com", country="US", organization="Test Org"
    )
    logger.debug("Issuing leaf certificate from sub-CA")
    leaf_cert = await sub_ca.issue_certificate(leaf_req, cert_type="server")

    # Verify the certificate chain
    logger.debug("Verifying certificate chain")
    root_cert = await ca.store.load_ca_cert()  # Load root CA from ca/ca.crt

    logger.debug("Root CA Subject: %s", root_cert.subject)
    logger.debug("Sub CA Subject: %s", sub_ca_cert.certificate.subject)
    logger.debug("Sub CA Issuer: %s", sub_ca_cert.certificate.issuer)

    # Verify leaf certificate is signed by sub-CA
    logger.debug("Verifying leaf certificate is signed by sub-CA")
    leaf_cert.certificate.verify_directly_issued_by(sub_ca_cert.certificate)

    # Verify sub-CA certificate is signed by root CA
    logger.debug("Verifying sub-CA certificate is signed by root CA")
    sub_ca_cert.certificate.verify_directly_issued_by(root_cert)

    # Verify basic constraints
    logger.debug("Verifying certificate constraints")
    assert not leaf_cert.is_ca
    assert sub_ca_cert.is_ca
    assert sub_ca_cert.path_length == 0
    logger.debug("Certificate validation test completed successfully")


@pytest.mark.asyncio
async def test_certificate_expiration(ca):
    """Test certificate expiration handling"""
    # Issue a certificate with short validity
    request = CertificateRequest(
        common_name="short-lived.example.com",
        country="US",
        organization="Test Org",
        valid_days=1,  # 1 day validity
    )

    cert = await ca.issue_certificate(request, cert_type="server")
    assert (cert.certificate.not_valid_after_utc -
            cert.certificate.not_valid_before_utc).days == 1

    # Issue a certificate with custom validity
    request = CertificateRequest(
        common_name="long-lived.example.com",
        country="US",
        organization="Test Org",
        valid_days=730,  # 2 years validity
    )

    cert = await ca.issue_certificate(request, cert_type="server")
    assert (cert.certificate.not_valid_after_utc -
            cert.certificate.not_valid_before_utc).days == 730


@pytest.mark.asyncio
async def test_ip_address_san(ca):
    """Test IP address SAN entries"""
    request = CertificateRequest(
        common_name="server.example.com",
        country="US",
        organization="Test Org",
        san_ip_addresses=["192.168.1.1", "2001:db8::1"],
    )

    cert = await ca.issue_certificate(request, cert_type="server")

    # Check SAN extension
    san = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    ip_addresses = san.value.get_values_for_type(x509.IPAddress)
    assert any(str(ip) == "192.168.1.1" for ip in ip_addresses)
    assert any(str(ip) == "2001:db8::1" for ip in ip_addresses)


@pytest.mark.asyncio
async def test_custom_extensions(ca):
    """Test custom extensions"""
    from cryptography.x509.oid import ObjectIdentifier

    # Create a custom extension
    custom_oid = ObjectIdentifier("1.2.3.4.5.6.7")
    custom_extension = x509.Extension(
        oid=custom_oid,
        critical=False,
        value=x509.UnrecognizedExtension(custom_oid, b"custom value"),
    )

    request = CertificateRequest(
        common_name="custom.example.com",
        country="US",
        organization="Test Org",
        custom_extensions=[custom_extension],
    )

    cert = await ca.issue_certificate(request, cert_type="server")

    # Verify custom extension
    ext = cert.certificate.extensions.get_extension_for_oid(custom_oid)
    assert ext.value.value == b"custom value"


@pytest.mark.asyncio
async def test_key_usage_combinations(ca):
    """Test different key usage combinations"""
    request = CertificateRequest(
        common_name="usage.example.com",
        country="US",
        organization="Test Org",
        key_usage={
            "digital_signature": True,
            "content_commitment": True,
            "key_encipherment": True,
            "data_encipherment": True,
            "key_agreement": True,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
    )

    cert = await ca.issue_certificate(request, cert_type="server")

    # Check key usage
    key_usage = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.KEY_USAGE)
    assert key_usage.value.digital_signature is True
    assert key_usage.value.content_commitment is True
    assert key_usage.value.key_encipherment is True
    assert key_usage.value.data_encipherment is True
    assert key_usage.value.key_agreement is True
    assert key_usage.value.key_cert_sign is False
    assert key_usage.value.crl_sign is False


@pytest.mark.asyncio
async def test_error_cases(ca):
    """Test error cases and invalid inputs"""
    # Test invalid common name
    with pytest.raises(ValueError, match="Common name is required"):
        request = CertificateRequest(common_name="")
        await ca.issue_certificate(request, cert_type="server")

    # Test invalid certificate type
    with pytest.raises(ValueError, match="Invalid certificate type"):
        request = CertificateRequest(
            common_name="test.example.com",
            country="US",
            organization="Test Org")
        await ca.issue_certificate(request, cert_type="invalid")

    # Test invalid key size
    with pytest.raises(ValueError, match="Key size must be at least 2048 bits"):
        request = CertificateRequest(
            common_name="test.example.com",
            country="US",
            organization="Test Org",
            key_size=1024,  # Too small
        )
        await ca.issue_certificate(request, cert_type="server")

    # Test invalid path length
    with pytest.raises(ValueError, match="Path length must be non-negative"):
        request = CertificateRequest(
            common_name="test.example.com",
            country="US",
            organization="Test Org",
            is_ca=True,
            path_length=-1,  # Invalid
        )
        await ca.issue_certificate(request, cert_type="sub-ca")


@pytest.mark.asyncio
async def test_crl_generation(ca):
    """Test CRL generation and validation"""
    # Issue a certificate
    request = CertificateRequest(
        common_name="test.example.com", country="US", organization="Test Org"
    )
    cert = await ca.issue_certificate(request, cert_type="server")

    # Generate initial CRL
    crl = await ca.generate_crl()
    assert len(list(crl)) == 0

    # Revoke the certificate
    await ca.revoke_certificate(cert.serial_number)

    # Generate new CRL
    crl = await ca.generate_crl()
    revoked_certs = list(crl)
    assert len(revoked_certs) == 1
    assert revoked_certs[0].serial_number == cert.serial_number


@pytest.mark.asyncio
async def test_certificate_renewal(ca):
    """Test certificate renewal"""
    # Issue initial certificate
    request = CertificateRequest(
        common_name="test.example.com",
        country="US",
        organization="Test Org",
        valid_days=1)
    original_cert = await ca.issue_certificate(request, cert_type="server")
    original_serial = original_cert.serial_number

    # Renew the certificate
    renewed_cert = await ca.renew_certificate(original_serial)
    assert renewed_cert.serial_number != original_serial
    assert renewed_cert.common_name == original_cert.common_name
    assert (renewed_cert.certificate.not_valid_after_utc >
            original_cert.certificate.not_valid_after_utc)

    # Verify both certificates are in the store
    certs = await ca.store.list_certificates(cert_type="server")
    assert any(c["serial"] == original_serial for c in certs)
    assert any(c["serial"] == renewed_cert.serial_number for c in certs)


@pytest.mark.asyncio
async def test_multiple_san_types(ca):
    """Test certificate with multiple types of Subject Alternative Names"""
    request = CertificateRequest(
        common_name="multi-san.example.com",
        country="US",
        organization="Test Org",
        san_dns_names=["multi-san.example.com", "*.multi-san.example.com"],
        san_ip_addresses=["192.168.1.1", "2001:db8::1"],
        email="admin@multi-san.example.com",
    )

    cert = await ca.issue_certificate(request, cert_type="server")

    # Check SAN extension
    san = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )

    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "multi-san.example.com" in dns_names
    assert "*.multi-san.example.com" in dns_names

    ip_addresses = san.value.get_values_for_type(x509.IPAddress)
    assert any(str(ip) == "192.168.1.1" for ip in ip_addresses)
    assert any(str(ip) == "2001:db8::1" for ip in ip_addresses)

    emails = san.value.get_values_for_type(x509.RFC822Name)
    assert "admin@multi-san.example.com" in emails


@pytest.mark.asyncio
async def test_extended_key_usage_combinations(ca):
    """Test different extended key usage combinations"""
    request = CertificateRequest(
        common_name="extended-usage.example.com",
        country="US",
        organization="Test Org",
        extended_key_usage=[
            "1.3.6.1.5.5.7.3.1",  # serverAuth
            "1.3.6.1.5.5.7.3.2",  # clientAuth
            "1.3.6.1.5.5.7.3.3",  # codeSigning
            "1.3.6.1.5.5.7.3.4",  # emailProtection
        ],
    )

    cert = await ca.issue_certificate(request, cert_type="server")

    # Check extended key usage
    ext_key_usage = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
    )

    assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in ext_key_usage.value
    assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in ext_key_usage.value
    assert x509.oid.ExtendedKeyUsageOID.CODE_SIGNING in ext_key_usage.value
    assert x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION in ext_key_usage.value


@pytest.mark.asyncio
async def test_sub_ca_chain_length(ca):
    """Test sub-CA chain length constraints"""
    # Create first level sub-CA
    sub_ca_req1 = CertificateRequest(
        common_name="Sub CA Level 1",
        country="US",
        organization="Test Org",
        is_ca=True,
        path_length=1,  # Can issue one more sub-CA
    )

    sub_ca_cert1 = await ca.issue_certificate(sub_ca_req1, cert_type="sub-ca")

    # Create sub-CA instance
    sub_ca1_dir = os.path.join(ca.base_dir, "sub-ca-level1")
    sub_ca1 = CertificateAuthority(
        sub_ca1_dir,
        ca_key=sub_ca_cert1.private_key_to_pem(),
        ca_cert=sub_ca_cert1.to_pem())
    await sub_ca1.initialize()

    # Create second level sub-CA
    sub_ca_req2 = CertificateRequest(
        common_name="Sub CA Level 2",
        country="US",
        organization="Test Org",
        is_ca=True,
        path_length=0,  # Cannot issue more sub-CAs
    )

    sub_ca_cert2 = await sub_ca1.issue_certificate(sub_ca_req2, cert_type="sub-ca")

    # Create second level sub-CA instance
    sub_ca2_dir = os.path.join(ca.base_dir, "sub-ca-level2")
    sub_ca2 = CertificateAuthority(
        sub_ca2_dir,
        ca_key=sub_ca_cert2.private_key_to_pem(),
        ca_cert=sub_ca_cert2.to_pem())
    await sub_ca2.initialize()

    # Attempt to create third level sub-CA (should fail)
    sub_ca_req3 = CertificateRequest(
        common_name="Sub CA Level 3",
        country="US",
        organization="Test Org",
        is_ca=True,
        path_length=0,
    )

    with pytest.raises(
        ValueError, match="Cannot issue CA certificate: path length constraint violated"
    ):
        await sub_ca2.issue_certificate(sub_ca_req3, cert_type="sub-ca")


@pytest.mark.asyncio
async def test_certificate_key_sizes(ca):
    """Test certificates with different key sizes"""
    key_sizes = [2048, 3072, 4096]

    for key_size in key_sizes:
        request = CertificateRequest(
            common_name=f"key-size-{key_size}.example.com",
            country="US",
            organization="Test Org",
            key_size=key_size,
        )

        cert = await ca.issue_certificate(request, cert_type="server")

        # Verify key size
        public_key = cert.certificate.public_key()
        assert public_key.key_size == key_size


@pytest.mark.asyncio
async def test_certificate_subject_attributes(ca):
    """Test all possible subject name attributes"""
    request = CertificateRequest(
        common_name="full-subject.example.com",
        country="US",
        state="California",
        locality="San Francisco",
        organization="Test Organization",
        organizational_unit="IT Department",
        email="admin@example.com",
    )

    cert = await ca.issue_certificate(request, cert_type="server")
    subject = cert.certificate.subject

    # Verify all subject attributes
    assert (subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            [0].value == "full-subject.example.com")
    assert subject.get_attributes_for_oid(
        NameOID.COUNTRY_NAME)[0].value == "US"
    assert subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[
        0].value == "California"
    assert subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[
        0].value == "San Francisco"
    assert subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[
        0].value == "Test Organization"
    assert (subject.get_attributes_for_oid(
        NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "IT Department")


@pytest.mark.asyncio
async def test_pkcs12_password_validation(ca):
    """Test PKCS12 export with different password scenarios"""
    request = CertificateRequest(
        common_name="pkcs12-test.example.com",
        country="US",
        organization="Test Org")

    cert = await ca.issue_certificate(request, cert_type="server")

    # Test with valid password
    pfx_data = await ca.export_pkcs12(cert, password="test123")
    key, cert, chain = PKCS12Helper.load_pfx(pfx_data, "test123")
    assert key is not None
    assert cert is not None
    assert len(chain) == 1

    # Test with wrong password
    with pytest.raises(ValueError):
        PKCS12Helper.load_pfx(pfx_data, "wrong-password")

    # Test with empty password
    with pytest.raises(ValueError):
        await ca.export_pkcs12(cert, password="")


@pytest.mark.asyncio
async def test_concurrent_certificate_issuance(ca):
    """Test issuing multiple certificates"""

    async def issue_cert(name: str):
        request = CertificateRequest(
            common_name=f"{name}.example.com",
            country="US",
            organization="Test Org")
        return await ca.issue_certificate(request, cert_type="server")

    # Issue 5 certificates sequentially
    names = [f"concurrent-{i}" for i in range(5)]
    certs = []
    for name in names:
        certs.append(await issue_cert(name))

    # Verify all certificates were issued successfully
    assert len(certs) == 5
    # All serial numbers should be unique
    assert len({cert.serial_number for cert in certs}) == 5

    # Verify all certificates are in the store
    stored_certs = await ca.store.list_certificates(cert_type="server")
    stored_serials = {cert["serial"] for cert in stored_certs}
    assert all(cert.serial_number in stored_serials for cert in certs)


@pytest.mark.asyncio
async def test_initialize_with_rsa():
    """Test CA initialization with RSA"""
    with tempfile.TemporaryDirectory() as base_dir:
        ca = CertificateAuthority(base_dir)
        await ca.initialize(common_name="Test CA", key_type="rsa", key_size=2048)
        assert ca.initialized
        assert isinstance(ca.ca_key, rsa.RSAPrivateKey)
        assert ca.ca_cert is not None


@pytest.mark.asyncio
async def test_initialize_with_ed25519():
    """Test CA initialization with Ed25519"""
    with tempfile.TemporaryDirectory() as base_dir:
        ca = CertificateAuthority(base_dir)
        await ca.initialize(common_name="Test CA", key_type="ed25519")
        assert ca.initialized
        assert isinstance(ca.ca_key, ed25519.Ed25519PrivateKey)
        assert ca.ca_cert is not None


@pytest.mark.asyncio
async def test_initialize_with_ed448():
    """Test CA initialization with Ed448"""
    with tempfile.TemporaryDirectory() as base_dir:
        ca = CertificateAuthority(base_dir)
        await ca.initialize(common_name="Test CA", key_type="ed448")
        assert ca.initialized
        assert isinstance(ca.ca_key, ed448.Ed448PrivateKey)
        assert ca.ca_cert is not None


@pytest.mark.asyncio
async def test_initialize_with_secp521r1():
    """Test CA initialization with SECP521R1"""
    with tempfile.TemporaryDirectory() as base_dir:
        ca = CertificateAuthority(base_dir)
        await ca.initialize(common_name="Test CA", key_type="ec", curve="e521")
        assert ca.initialized
        assert isinstance(ca.ca_key, ec.EllipticCurvePrivateKey)
        assert ca.ca_cert is not None


@pytest.mark.asyncio
async def test_initialize_with_invalid_curve():
    """Test CA initialization with invalid curve"""
    with tempfile.TemporaryDirectory() as base_dir:
        ca = CertificateAuthority(base_dir)
        with pytest.raises(ValueError, match="Unsupported or unsafe curve"):
            await ca.initialize(common_name="Test CA", key_type="ec", curve="invalid")


@pytest.mark.asyncio
async def test_issue_ed25519_certificate():
    """Test issuing certificate with Ed25519"""
    with tempfile.TemporaryDirectory() as base_dir:
        ca = CertificateAuthority(base_dir)
        await ca.initialize(common_name="Test CA", key_type="rsa", key_size=2048)

        request = CertificateRequest(
            common_name="test.example.com",
            key_type="ed25519")
        cert = await ca.issue_certificate(request, cert_type="server")
        assert isinstance(cert.private_key, ed25519.Ed25519PrivateKey)
        assert cert.certificate is not None


@pytest.mark.asyncio
async def test_issue_ed448_certificate():
    """Test issuing certificate with Ed448"""
    with tempfile.TemporaryDirectory() as base_dir:
        ca = CertificateAuthority(base_dir)
        await ca.initialize(common_name="Test CA", key_type="rsa", key_size=2048)

        request = CertificateRequest(
            common_name="test.example.com",
            key_type="ed448")
        cert = await ca.issue_certificate(request, cert_type="server")
        assert isinstance(cert.private_key, ed448.Ed448PrivateKey)
        assert cert.certificate is not None


@pytest.mark.asyncio
async def test_issue_secp521r1_certificate():
    """Test issuing certificate with SECP521R1"""
    with tempfile.TemporaryDirectory() as base_dir:
        ca = CertificateAuthority(base_dir)
        await ca.initialize(common_name="Test CA", key_type="rsa", key_size=2048)

        request = CertificateRequest(
            common_name="test.example.com",
            key_type="ec",
            curve="e521")
        cert = await ca.issue_certificate(request, cert_type="server")
        assert isinstance(cert.private_key, ec.EllipticCurvePrivateKey)
        assert cert.certificate is not None


@pytest.mark.asyncio
async def test_hash_algorithms(ca):
    """Test certificates with different hash algorithms"""
    hash_algs = [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]

    for hash_alg in hash_algs:
        request = CertificateRequest(
            common_name=f"hash-{hash_alg.name}.example.com",
            country="US",
            organization="Test Org",
            hash_algorithm=hash_alg,
        )

        cert = await ca.issue_certificate(request, cert_type="server")
        assert cert.certificate is not None
        # Verify signature algorithm matches the hash algorithm
        assert cert.certificate.signature_hash_algorithm.name == hash_alg.name


@pytest.mark.asyncio
async def test_certificate_policies(ca):
    """Test certificate policies extension"""
    policy_oid = x509.ObjectIdentifier(
        "2.23.140.1.2.1")  # Domain validated SSL
    request = CertificateRequest(
        common_name="policy.example.com",
        country="US",
        organization="Test Org",
        policy_oids=[policy_oid],
    )

    cert = await ca.issue_certificate(request, cert_type="server")

    # Verify certificate policies extension
    policies_ext = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.CERTIFICATE_POLICIES
    )
    assert any(policy.policy_identifier ==
               policy_oid for policy in policies_ext.value)


@pytest.mark.asyncio
async def test_name_constraints(ca):
    """Test name constraints for CA certificates"""
    permitted_dns = ["example.com", "sub.example.com"]
    excluded_dns = ["forbidden.example.com"]

    request = CertificateRequest(
        common_name="constrained-ca.example.com",
        country="US",
        organization="Test Org",
        is_ca=True,
        path_length=0,
        permitted_dns_domains=permitted_dns,
        excluded_dns_domains=excluded_dns,
    )

    cert = await ca.issue_certificate(request, cert_type="sub-ca")

    # Verify name constraints extension
    nc_ext = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.NAME_CONSTRAINTS
    )
    assert nc_ext.critical is True

    # Check permitted names
    permitted = nc_ext.value.permitted_subtrees
    if permitted:
        dns_names = [
            name.value for name in permitted if isinstance(
                name, x509.DNSName)]
        assert all(name in dns_names for name in permitted_dns)

    # Check excluded names
    excluded = nc_ext.value.excluded_subtrees
    if excluded:
        dns_names = [
            name.value for name in excluded if isinstance(
                name, x509.DNSName)]
        assert all(name in dns_names for name in excluded_dns)


@pytest.mark.asyncio
async def test_ocsp_and_aia_extensions(ca):
    """Test OCSP responder URL and Authority Information Access"""
    ocsp_url = "http://ocsp.example.com"
    ca_issuers_url = "http://ca.example.com/ca.crt"

    request = CertificateRequest(
        common_name="ocsp.example.com",
        country="US",
        organization="Test Org",
        ocsp_responder_url=ocsp_url,
        ca_issuers_url=ca_issuers_url,
    )

    cert = await ca.issue_certificate(request, cert_type="server")

    # Verify AIA extension
    aia_ext = cert.certificate.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
    )

    has_ocsp = False
    has_ca_issuers = False

    for desc in aia_ext.value:
        if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
            assert desc.access_location.value == ocsp_url
            has_ocsp = True
        elif desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
            assert desc.access_location.value == ca_issuers_url
            has_ca_issuers = True

    assert has_ocsp and has_ca_issuers


@pytest.mark.asyncio
async def test_negative_path_length(ca):
    """Test that negative path length is rejected"""
    request = CertificateRequest(
        common_name="negative-path.example.com",
        country="US",
        organization="Test Org",
        is_ca=True,
        path_length=-1,
    )

    with pytest.raises(ValueError, match="Path length must be non-negative"):
        await ca.issue_certificate(request, cert_type="sub-ca")
