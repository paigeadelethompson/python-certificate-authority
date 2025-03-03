"""Tests for JKS (Java KeyStore) utilities

This module contains tests for the JKS utility functions and classes.
Tests cover:
- Creating JKS keystores
- Loading JKS keystores
- Extracting keys and certificates
- Error handling
"""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization

from CA.utils.jks import JKSHelper, create_jks, load_jks


@pytest.fixture
def private_key():
    """Generate a test RSA private key"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


@pytest.fixture
def certificate(private_key):
    """Generate a test certificate"""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
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
    ).sign(private_key, hashes.SHA256())
    
    return cert


@pytest.fixture
def ca_certificate(private_key):
    """Generate a test CA certificate"""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
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


def test_jks_helper_create_keystore(private_key, certificate, ca_certificate):
    """Test creating a JKS keystore using JKSHelper"""
    helper = JKSHelper()
    cert_chain = [certificate, ca_certificate]
    
    # Create keystore
    keystore_data = helper.create_keystore(
        private_key=private_key,
        cert_chain=cert_chain,
        alias="test",
        password="changeit"
    )
    
    assert keystore_data is not None
    assert isinstance(keystore_data, bytes)
    assert len(keystore_data) > 0


def test_jks_helper_load_keystore(private_key, certificate, ca_certificate):
    """Test loading a JKS keystore using JKSHelper"""
    helper = JKSHelper()
    cert_chain = [certificate, ca_certificate]
    
    # Create and load keystore
    keystore_data = helper.create_keystore(
        private_key=private_key,
        cert_chain=cert_chain,
        alias="test",
        password="changeit"
    )
    
    keystore = helper.load_keystore(keystore_data, "changeit")
    assert keystore is not None
    assert len(keystore.private_keys) == 1
    assert "test" in keystore.private_keys


def test_jks_helper_extract_key_and_certs(private_key, certificate, ca_certificate):
    """Test extracting keys and certificates from a JKS keystore using JKSHelper"""
    helper = JKSHelper()
    cert_chain = [certificate, ca_certificate]
    
    # Create keystore
    keystore_data = helper.create_keystore(
        private_key=private_key,
        cert_chain=cert_chain,
        alias="test",
        password="changeit"
    )
    
    # Load keystore
    keystore = helper.load_keystore(keystore_data, "changeit")
    
    # Extract key and certs
    extracted_key, extracted_certs = helper.extract_key_and_certs(
        keystore, "test", "changeit"
    )
    
    assert isinstance(extracted_key, rsa.RSAPrivateKey)
    assert len(extracted_certs) == 2
    assert all(isinstance(cert, x509.Certificate) for cert in extracted_certs)


def test_create_jks_with_key(private_key, certificate, ca_certificate):
    """Test creating a JKS keystore with a private key using create_jks function"""
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    keystore_data = create_jks(
        cert=certificate,
        key=key_bytes,
        ca_certs=[ca_certificate],
        password="changeit",
        alias="test"
    )
    
    assert keystore_data is not None
    assert isinstance(keystore_data, bytes)
    assert len(keystore_data) > 0


def test_create_jks_cert_only(certificate):
    """Test creating a JKS keystore with only a certificate using create_jks function"""
    keystore_data = create_jks(
        cert=certificate,
        password="changeit",
        alias="test"
    )
    
    assert keystore_data is not None
    assert isinstance(keystore_data, bytes)
    assert len(keystore_data) > 0


def test_load_jks_function(private_key, certificate, ca_certificate):
    """Test loading a JKS keystore using load_jks function"""
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Create keystore
    keystore_data = create_jks(
        cert=certificate,
        key=key_bytes,
        ca_certs=[ca_certificate],
        password="changeit",
        alias="test"
    )
    
    # Load keystore
    keystore = load_jks(keystore_data, "changeit")
    assert keystore is not None
    assert len(keystore.private_keys) == 1
    assert len(keystore.certs) == 1


def test_jks_helper_invalid_password(private_key, certificate, ca_certificate):
    """Test handling invalid password when loading JKS keystore"""
    helper = JKSHelper()
    cert_chain = [certificate, ca_certificate]
    
    # Create keystore
    keystore_data = helper.create_keystore(
        private_key=private_key,
        cert_chain=cert_chain,
        alias="test",
        password="changeit"
    )
    
    # Try to load with wrong password
    with pytest.raises(Exception):
        helper.load_keystore(keystore_data, "wrongpass")


def test_jks_helper_invalid_alias(private_key, certificate, ca_certificate):
    """Test handling invalid alias when extracting keys and certificates"""
    helper = JKSHelper()
    cert_chain = [certificate, ca_certificate]
    
    # Create keystore
    keystore_data = helper.create_keystore(
        private_key=private_key,
        cert_chain=cert_chain,
        alias="test",
        password="changeit"
    )
    
    # Load keystore
    keystore = helper.load_keystore(keystore_data, "changeit")
    
    # Try to extract with wrong alias
    with pytest.raises(ValueError):
        helper.extract_key_and_certs(keystore, "wrongalias", "changeit") 