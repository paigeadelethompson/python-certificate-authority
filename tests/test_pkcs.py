"""
Tests for PKCS utilities.

This module tests the functionality for:
- PKCS#7 certificate bundles
- PKCS#12 keystore creation and loading
- Password protection
- Certificate chain handling
- Error handling
"""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

from CA.utils.pkcs import PKCS7Helper, PKCS12Helper, create_pkcs12, load_pkcs12

@pytest.fixture
def private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

@pytest.fixture
def certificate(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(tz=None)
    ).not_valid_after(
        datetime.now(tz=None) + timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256())

    return cert

@pytest.fixture
def ca_certificate(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA Organization"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(tz=None)
    ).not_valid_after(
        datetime.now(tz=None) + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256())

    return cert

def test_pkcs7_create_and_load(certificate, ca_certificate):
    certs = [certificate, ca_certificate]
    pkcs7_data = PKCS7Helper.create_pkcs7(certs)
    assert isinstance(pkcs7_data, bytes)
    
    loaded_certs = PKCS7Helper.load_pkcs7(pkcs7_data)
    assert len(loaded_certs) == 2
    assert all(isinstance(cert, x509.Certificate) for cert in loaded_certs)
    
    # Check that both certificates are present, regardless of order
    loaded_subjects = {cert.subject for cert in loaded_certs}
    expected_subjects = {certificate.subject, ca_certificate.subject}
    assert loaded_subjects == expected_subjects

def test_pkcs12_create_and_load(private_key, certificate, ca_certificate):
    helper = PKCS12Helper()
    password = "testpass"
    
    # Create PKCS#12 with chain
    pkcs12_data = helper.create_pfx(
        private_key=private_key,
        certificate=certificate,
        ca_certs=[ca_certificate],
        password=password
    )
    assert isinstance(pkcs12_data, bytes)
    
    # Load and verify
    loaded_key, loaded_cert, loaded_chain = helper.load_pfx(pkcs12_data, password)
    assert isinstance(loaded_key, rsa.RSAPrivateKey)
    assert isinstance(loaded_cert, x509.Certificate)
    assert len(loaded_chain) == 1
    assert loaded_cert.subject == certificate.subject
    assert loaded_chain[0].subject == ca_certificate.subject

def test_pkcs12_without_chain(private_key, certificate):
    helper = PKCS12Helper()
    password = "testpass"
    
    # Create PKCS#12 without chain
    pkcs12_data = helper.create_pfx(
        private_key=private_key,
        certificate=certificate,
        password=password
    )
    assert isinstance(pkcs12_data, bytes)
    
    # Load and verify
    loaded_key, loaded_cert, loaded_chain = helper.load_pfx(pkcs12_data, password)
    assert isinstance(loaded_key, rsa.RSAPrivateKey)
    assert isinstance(loaded_cert, x509.Certificate)
    assert len(loaded_chain) == 0
    assert loaded_cert.subject == certificate.subject

def test_pkcs12_without_password(private_key, certificate):
    helper = PKCS12Helper()
    
    # Create PKCS#12 without password
    pkcs12_data = helper.create_pfx(
        private_key=private_key,
        certificate=certificate,
        password=None
    )
    assert isinstance(pkcs12_data, bytes)
    
    # Load and verify
    loaded_key, loaded_cert, loaded_chain = helper.load_pfx(pkcs12_data, "")
    assert isinstance(loaded_key, rsa.RSAPrivateKey)
    assert isinstance(loaded_cert, x509.Certificate)
    assert loaded_cert.subject == certificate.subject

def test_pkcs12_wrong_password(private_key, certificate):
    helper = PKCS12Helper()
    
    # Create PKCS#12 with password
    pkcs12_data = helper.create_pfx(
        private_key=private_key,
        certificate=certificate,
        password="correct"
    )
    assert isinstance(pkcs12_data, bytes)
    
    # Try to load with wrong password
    with pytest.raises(ValueError):
        helper.load_pfx(pkcs12_data, "wrong")

def test_pkcs12_invalid_data():
    helper = PKCS12Helper()
    with pytest.raises(ValueError):
        helper.load_pfx(b"invalid data", "password")

def test_create_pkcs12_function(certificate, private_key, ca_certificate):
    # Test the standalone create_pkcs12 function
    pkcs12_data = create_pkcs12(
        cert=certificate,
        key=private_key,
        ca_certs=[ca_certificate],
        password=b"testpass",
        friendly_name=b"test-cert"
    )
    assert isinstance(pkcs12_data, bytes)
    
    # Load and verify
    loaded_key, loaded_cert, loaded_chain = load_pkcs12(pkcs12_data, b"testpass")
    assert isinstance(loaded_key, rsa.RSAPrivateKey)
    assert isinstance(loaded_cert, x509.Certificate)
    assert len(loaded_chain) == 1
    assert loaded_cert.subject == certificate.subject
    assert loaded_chain[0].subject == ca_certificate.subject 