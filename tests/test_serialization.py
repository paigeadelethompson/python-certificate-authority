"""
Tests for the serialization utilities.

This module tests the functionality for:
- Certificate serialization/deserialization (PEM/DER)
- Private key serialization/deserialization (PEM/DER)
- Certificate list serialization/deserialization
- Error handling
"""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

from CA.utils.serialization import (
    certificate_to_pem,
    certificate_to_der,
    private_key_to_pem,
    private_key_to_der,
    public_key_to_pem,
    public_key_to_der,
    load_certificate,
    load_private_key,
    load_public_key,
    cert_to_json,
    json_to_name,
    json_to_cert,
)


@pytest.fixture
def rsa_private_key():
    """Generate a test RSA private key"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


@pytest.fixture
def ec_private_key():
    """Generate a test EC private key"""
    return ec.generate_private_key(ec.SECP256K1())


@pytest.fixture
def ed25519_private_key():
    """Generate a test Ed25519 private key"""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def ed448_private_key():
    """Generate a test Ed448 private key"""
    return ed448.Ed448PrivateKey.generate()


@pytest.fixture
def certificate(rsa_private_key):
    """Generate a test certificate"""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Test Unit"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "test@example.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        rsa_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(tz=None)
    ).not_valid_after(
        datetime.now(tz=None) + timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(rsa_private_key, hashes.SHA256())
    
    return cert


def test_certificate_serialization_pem(certificate):
    """Test certificate PEM serialization/deserialization"""
    pem_data = certificate_to_pem(certificate)
    assert isinstance(pem_data, bytes)
    loaded_cert = load_certificate(pem_data)
    assert isinstance(loaded_cert, x509.Certificate)
    assert loaded_cert.subject == certificate.subject


def test_certificate_serialization_der(certificate):
    """Test certificate DER serialization/deserialization"""
    der_data = certificate_to_der(certificate)
    assert isinstance(der_data, bytes)
    loaded_cert = load_certificate(der_data)
    assert isinstance(loaded_cert, x509.Certificate)
    assert loaded_cert.subject == certificate.subject


def test_rsa_key_serialization_pem(rsa_private_key):
    """Test RSA private key PEM serialization/deserialization"""
    # Test without password
    pem_data = private_key_to_pem(rsa_private_key)
    assert isinstance(pem_data, bytes)
    loaded_key = load_private_key(pem_data)
    assert isinstance(loaded_key, rsa.RSAPrivateKey)
    
    # Test with password
    pem_data = private_key_to_pem(rsa_private_key, b"testpass")
    assert isinstance(pem_data, bytes)
    loaded_key = load_private_key(pem_data, b"testpass")
    assert isinstance(loaded_key, rsa.RSAPrivateKey)


def test_rsa_key_serialization_der(rsa_private_key):
    """Test RSA private key DER serialization/deserialization"""
    der_data = private_key_to_der(rsa_private_key)
    assert isinstance(der_data, bytes)
    loaded_key = load_private_key(der_data)
    assert isinstance(loaded_key, rsa.RSAPrivateKey)


def test_ec_key_serialization(ec_private_key):
    """Test EC private key serialization/deserialization"""
    # Test PEM format
    pem_data = private_key_to_pem(ec_private_key)
    assert isinstance(pem_data, bytes)
    loaded_key = load_private_key(pem_data)
    assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
    
    # Test DER format
    der_data = private_key_to_der(ec_private_key)
    assert isinstance(der_data, bytes)
    loaded_key = load_private_key(der_data)
    assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)


def test_ed25519_key_serialization(ed25519_private_key):
    """Test Ed25519 private key serialization/deserialization"""
    # Test PEM format
    pem_data = private_key_to_pem(ed25519_private_key)
    assert isinstance(pem_data, bytes)
    loaded_key = load_private_key(pem_data)
    assert isinstance(loaded_key, ed25519.Ed25519PrivateKey)
    
    # Test DER format
    der_data = private_key_to_der(ed25519_private_key)
    assert isinstance(der_data, bytes)
    loaded_key = load_private_key(der_data)
    assert isinstance(loaded_key, ed25519.Ed25519PrivateKey)


def test_ed448_key_serialization(ed448_private_key):
    """Test Ed448 private key serialization/deserialization"""
    # Test PEM format
    pem_data = private_key_to_pem(ed448_private_key)
    assert isinstance(pem_data, bytes)
    loaded_key = load_private_key(pem_data)
    assert isinstance(loaded_key, ed448.Ed448PrivateKey)
    
    # Test DER format
    der_data = private_key_to_der(ed448_private_key)
    assert isinstance(der_data, bytes)
    loaded_key = load_private_key(der_data)
    assert isinstance(loaded_key, ed448.Ed448PrivateKey)


def test_public_key_serialization(rsa_private_key):
    public_key = rsa_private_key.public_key()

    # Test PEM format
    pem_data = public_key_to_pem(public_key)
    assert isinstance(pem_data, bytes)
    loaded_key = load_public_key(pem_data)
    assert isinstance(loaded_key, rsa.RSAPublicKey)

    # Test DER format
    der_data = public_key_to_der(public_key)
    assert isinstance(der_data, bytes)
    loaded_key = load_public_key(der_data)
    assert isinstance(loaded_key, rsa.RSAPublicKey)


def test_cert_to_json(certificate):
    cert_json = cert_to_json(certificate)
    assert isinstance(cert_json, dict)
    assert cert_json["subject"]["common_name"] == "test.example.com"
    assert cert_json["subject"]["country"] == "US"
    assert cert_json["is_ca"] is True


def test_json_to_name():
    name_dict = {
        "common_name": "test.example.com",
        "country": "US",
        "state": "California",
        "locality": "San Francisco",
        "organization": "Test Organization",
        "organizational_unit": "Test Unit",
        "email": "test@example.com"
    }
    name = json_to_name(name_dict)
    assert isinstance(name, x509.Name)
    assert name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "test.example.com"


def test_invalid_certificate_data():
    with pytest.raises(ValueError):
        load_certificate(b"invalid data")


def test_invalid_private_key_data():
    with pytest.raises(ValueError):
        load_private_key(b"invalid data")


def test_invalid_public_key_data():
    with pytest.raises(ValueError):
        load_public_key(b"invalid data")


def test_invalid_private_key_password():
    pem_data = private_key_to_pem(rsa.generate_private_key(65537, 2048), b"correct")
    with pytest.raises(ValueError):
        load_private_key(pem_data, b"wrong")


def test_certificate_list_serialization_pem(certificate, rsa_private_key):
    """Test certificate list PEM serialization/deserialization"""
    # Create a list of certificates
    certs = [
        certificate,
        x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test2.example.com")])
        ).issuer_name(
            certificate.subject
        ).public_key(
            rsa_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(tz=None)
        ).not_valid_after(
            datetime.now(tz=None) + timedelta(days=10)
        ).sign(rsa_private_key, hashes.SHA256())
    ]
    
    # Test PEM serialization
    pem_data = certificate_to_pem(certs[0])
    assert isinstance(pem_data, bytes)
    assert pem_data.startswith(b"-----BEGIN CERTIFICATE-----")
    assert pem_data.endswith(b"-----END CERTIFICATE-----\n")
    
    # Test PEM deserialization
    loaded_cert = load_certificate(pem_data)
    assert isinstance(loaded_cert, x509.Certificate)
    assert loaded_cert.subject == certs[0].subject


def test_certificate_list_serialization_der(certificate, rsa_private_key):
    """Test certificate list DER serialization/deserialization"""
    # Create a list of certificates
    certs = [
        certificate,
        x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test2.example.com")])
        ).issuer_name(
            certificate.subject
        ).public_key(
            rsa_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(tz=None)
        ).not_valid_after(
            datetime.now(tz=None) + timedelta(days=10)
        ).sign(rsa_private_key, hashes.SHA256())
    ]
    
    # Test DER serialization
    der_data = certificate_to_der(certs[0])
    assert isinstance(der_data, bytes)
    
    # Test DER deserialization
    loaded_cert = load_certificate(der_data)
    assert isinstance(loaded_cert, x509.Certificate)
    assert loaded_cert.subject == certs[0].subject


def test_invalid_format():
    """Test handling of invalid format specification"""
    key = rsa.generate_private_key(65537, 2048)
    with pytest.raises(ValueError):
        private_key_to_pem(key, "invalid") 