"""
PKCS#12 File Format Utilities

This module provides utilities for working with PKCS#12 (.p12/.pfx) files.
It supports:
- Creating PKCS#12 archives
- Adding certificates and private keys
- Setting friendly names and passwords
- Managing certificate chains

The PKCS#12 format is widely used for bundling private keys with their
corresponding certificates and certificate chains. This module provides
a Python interface for creating PKCS#12 files compatible with various
systems and applications.
"""

import logging
from typing import List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    rsa,
)
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

logger = logging.getLogger(__name__)


class PKCS7Helper:
    @staticmethod
    def create_pkcs7(certificates: List[x509.Certificate]) -> bytes:
        """
        Create a PKCS7 certificate bundle

        Args:
            certificates: List of certificates to include

        Returns:
            PKCS7 bundle in PEM format
        """
        return pkcs7.serialize_certificates(certificates, encoding=serialization.Encoding.PEM)

    @staticmethod
    def load_pkcs7(data: bytes) -> List[x509.Certificate]:
        """
        Load certificates from a PKCS7 bundle

        Args:
            data: PKCS7 bundle data

        Returns:
            List of certificates
        """
        return pkcs7.load_pem_pkcs7_certificates(data)


class PKCS12Helper:
    """
    Helper class for creating PKCS#12 files.

    This class provides methods for creating PKCS#12 archives and adding
    certificates and private keys to them. It handles the complexities
    of key format conversion and certificate chain management.

    PKCS#12 is more flexible than JKS and supports:
    - All key types (RSA, EC, Ed25519, Ed448)
    - Multiple certificates and keys
    - Separate passwords for the archive and private keys
    - Friendly names for certificates

    Example:
        >>> helper = PKCS12Helper()
        >>> p12_data = helper.create_pkcs12(
        ...     cert=server_cert,
        ...     key=server_key,
        ...     ca_cert=ca_cert,
        ...     password="changeit"
        ... )
    """

    @staticmethod
    def create_pfx(
        private_key: rsa.RSAPrivateKey,
        certificate: x509.Certificate,
        ca_certs: Optional[List[x509.Certificate]] = None,
        password: Optional[str] = None,
    ) -> bytes:
        """
        Create a PKCS12 file from a certificate and private key

        Args:
            private_key: Private key
            certificate: Certificate
            ca_certs: List of CA certificates for the chain
            password: Password to protect the PKCS12 file

        Returns:
            PKCS12 formatted bytes

        Raises:
            ValueError: If password is empty or parameters are invalid
        """
        if password == "":
            raise ValueError("Password cannot be empty")

        if not private_key:
            raise ValueError("Private key is required")

        if not certificate:
            raise ValueError("Certificate is required")

        name = certificate.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME)[0].value.encode()

        return pkcs12.serialize_key_and_certificates(
            name=name,
            key=private_key,
            cert=certificate,
            cas=ca_certs,
            encryption_algorithm=(
                serialization.BestAvailableEncryption(password.encode())
                if password
                else serialization.NoEncryption()
            ),
        )

    @staticmethod
    def load_pfx(
        pfx_data: bytes, password: str
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, List[x509.Certificate]]:
        """
        Load a PKCS12 file

        Args:
            pfx_data: PKCS12 formatted bytes
            password: Password to decrypt the PKCS12 file (can be empty for unencrypted files)

        Returns:
            Tuple of (private key, certificate, CA certificates)

        Raises:
            ValueError: If PKCS12 file is invalid
        """
        if not pfx_data:
            raise ValueError("PKCS12 data is required")

        private_key, certificate, ca_certs = pkcs12.load_key_and_certificates(
            pfx_data, password.encode() if password else b""
        )

        if not private_key or not certificate:
            raise ValueError("Invalid PKCS12 file or wrong password")

        return private_key, certificate, ca_certs or []

    def create_pkcs12(
        self,
        cert: x509.Certificate,
        key: Union[
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
        ],
        ca_cert: Optional[x509.Certificate] = None,
        password: str = "changeit",
        friendly_name: bytes = b"certificate",
    ) -> bytes:
        """
        Create a PKCS#12 archive containing a certificate and private key.

        This method creates a new PKCS#12 archive and adds the provided certificate
        and private key to it. Optionally includes a CA certificate to form a
        certificate chain.

        Args:
            cert: The certificate to include
            key: The private key for the certificate
            ca_cert: Optional CA certificate to include in the chain
            password: Password to protect the archive
            friendly_name: Name to identify the certificate in the archive

        Returns:
            bytes: The PKCS#12 archive data

        Raises:
            ValueError: If the certificate or key format is invalid
            TypeError: If the password encoding fails
        """
        logger.debug(
            "Creating PKCS#12 file for certificate (has key: %s, CA certs: %d)",
            "yes" if key else "no",
            len(ca_cert) if ca_cert else 0,
        )

        try:
            pkcs12_data = pkcs12.serialize_key_and_certificates(
                name=friendly_name,
                key=key,
                cert=cert,
                cas=ca_cert,
                encryption_algorithm=(
                    serialization.BestAvailableEncryption(password.encode())
                    if password
                    else serialization.NoEncryption()
                ),
            )
            logger.debug("PKCS#12 file created successfully")
            return pkcs12_data
        except Exception as e:
            logger.error("Failed to create PKCS#12 file: %s", str(e))
            raise


def create_pkcs12(
    cert: x509.Certificate,
    key: Optional[bytes] = None,
    ca_certs: Optional[list[x509.Certificate]] = None,
    password: Optional[bytes] = None,
    friendly_name: Optional[bytes] = None,
) -> bytes:
    """Create a PKCS#12 file containing a certificate and optionally its private key and CA certificates"""
    logger.debug(
        "Creating PKCS#12 file for certificate (has key: %s, CA certs: %d)",
        "yes" if key else "no",
        len(ca_certs) if ca_certs else 0,
    )

    try:
        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=key,
            cert=cert,
            cas=ca_certs,
            encryption_algorithm=(
                serialization.BestAvailableEncryption(password)
                if password
                else serialization.NoEncryption()
            ),
        )
        logger.debug("PKCS#12 file created successfully")
        return pkcs12_data
    except Exception as e:
        logger.error("Failed to create PKCS#12 file: %s", str(e))
        raise


def load_pkcs12(
    data: bytes, password: Optional[bytes] = None
) -> Tuple[Optional[bytes], x509.Certificate, list[x509.Certificate]]:
    """Load a PKCS#12 file and extract its contents"""
    logger.debug(
        "Loading PKCS#12 file (password protected: %s)",
        "yes" if password else "no")

    try:
        key, cert, ca_certs = pkcs12.load_key_and_certificates(data, password)
        logger.debug(
            "PKCS#12 file loaded successfully (has key: %s, CA certs: %d)",
            "yes" if key else "no",
            len(ca_certs) if ca_certs else 0,
        )
        return key, cert, ca_certs or []
    except Exception as e:
        logger.error("Failed to load PKCS#12 file: %s", str(e))
        raise
