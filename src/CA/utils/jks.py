"""
Java KeyStore (JKS) File Format Utilities

This module provides utilities for working with Java KeyStore (JKS) files.
It supports:
- Creating JKS keystores
- Adding certificates and private keys
- Setting aliases and passwords
- Managing certificate chains

The JKS format is commonly used in Java applications for storing cryptographic
keys and certificates. This module provides a Python interface for creating and
manipulating JKS files compatible with Java applications.
"""

import logging
from typing import List, Optional, Union, Tuple, Any

import jks
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    rsa,
)

from .serialization import certificate_to_der, private_key_to_der

logger = logging.getLogger(__name__)


class JKSHelper:
    """
    Helper class for creating Java KeyStore (JKS) files.

    This class provides methods for creating JKS keystores and adding
    certificates and private keys to them. It handles the complexities
    of key format conversion and certificate chain management.

    The JKS format has some limitations:
    - Only supports RSA and EC keys (no Ed25519/Ed448)
    - Requires PKCS8 encoding for private keys
    - Has specific requirements for certificate chain order

    Example:
        >>> helper = JKSHelper()
        >>> jks_data = helper.create_keystore(
        ...     cert=server_cert,
        ...     key=server_key,
        ...     ca_cert=ca_cert,
        ...     password="changeit"
        ... )
    """

    @staticmethod
    def create_keystore(
        private_key: rsa.RSAPrivateKey,
        cert_chain: list[x509.Certificate],
        alias: str,
        password: str,
    ) -> bytes:
        """
        Create a Java KeyStore (JKS) with the given private key and certificate chain

        Args:
            private_key: The RSA private key
            cert_chain: List of certificates (leaf cert first, then intermediates)
            alias: Alias for the key entry
            password: Password to protect the keystore

        Returns:
            JKS file contents as bytes
        """
        logger.debug(
            "Creating JKS keystore for private key (has CA certs: %d)",
            len(cert_chain) - 1)

        try:
            # Convert private key to DER format
            key_der = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Convert certificates to DER format
            cert_chain_der = [
                cert.public_bytes(
                    serialization.Encoding.DER) for cert in cert_chain]

            # Create new keystore
            ks = jks.KeyStore.new("jks", [])

            # Add private key entry
            pke = jks.PrivateKeyEntry.new(
                alias=alias,
                certs=cert_chain_der,
                key=key_der
            )
            ks.entries[alias] = pke

            # Get keystore data
            keystore_data = ks.saves(password)
            return keystore_data

        except Exception as e:
            logger.error("Failed to create JKS keystore: %s", str(e))
            raise

    @staticmethod
    def load_keystore(keystore_data: bytes, password: str) -> jks.KeyStore:
        """
        Load a Java KeyStore from bytes

        Args:
            keystore_data: JKS file contents
            password: Password to unlock the keystore

        Returns:
            Loaded KeyStore object
        """
        logger.debug("Loading JKS keystore")

        try:
            ks = jks.KeyStore.loads(keystore_data, password)
            logger.debug(
                "JKS keystore loaded successfully (private keys: %d, certs: %d)", len(
                    ks.private_keys), len(
                    ks.certs), )
            return ks
        except Exception as e:
            logger.error("Failed to load JKS keystore: %s", str(e))
            raise

    def extract_key_and_certs(self, keystore: jks.KeyStore, alias: str, password: str) -> Tuple[Any, List[x509.Certificate]]:
        """Extract private key and certificate chain from a JKS keystore"""
        if alias not in keystore.private_keys:
            raise ValueError(f"No private key entry found with alias: {alias}")

        pk_entry = keystore.private_keys[alias]
        if not pk_entry.is_decrypted():
            pk_entry.decrypt(password)

        # Load the private key
        key = serialization.load_der_private_key(
            pk_entry.pkey,
            password=None
        )

        # Load the certificate chain
        cert_chain = [x509.load_der_x509_certificate(cert[1]) for cert in pk_entry.cert_chain]

        return key, cert_chain


def create_jks(
    cert: x509.Certificate,
    key: Optional[bytes] = None,
    ca_certs: Optional[List[x509.Certificate]] = None,
    password: str = "",
    alias: str = "certificate",
) -> bytes:
    """Create a Java KeyStore containing a certificate and optionally its private key and CA certificates"""
    logger.debug(
        "Creating JKS keystore for certificate (has key: %s, CA certs: %d)",
        "yes" if key else "no",
        len(ca_certs) if ca_certs else 0,
    )

    try:
        # Create new keystore
        ks = jks.KeyStore.new("jks", [])

        # Add private key entry if provided
        if key:
            logger.debug("Adding private key entry with alias: %s", alias)
            cert_chain = [certificate_to_der(cert)]
            if ca_certs:
                cert_chain.extend(certificate_to_der(ca_cert)
                                  for ca_cert in ca_certs)
            pke = jks.PrivateKeyEntry.new(
                alias=alias,
                key=key,
                certs=cert_chain
            )
            ks.entries[alias] = pke

            # Add CA certificates as trusted certificate entries
            if ca_certs:
                for i, ca_cert in enumerate(ca_certs):
                    ca_alias = f"ca-{i+1}"
                    logger.debug("Adding CA certificate entry with alias: %s", ca_alias)
                    tce = jks.TrustedCertEntry.new(
                        alias=ca_alias,
                        cert=certificate_to_der(ca_cert)
                    )
                    ks.entries[ca_alias] = tce
        else:
            # Add certificate entry
            logger.debug("Adding certificate entry with alias: %s", alias)
            tce = jks.TrustedCertEntry.new(
                alias=alias,
                cert=certificate_to_der(cert)
            )
            ks.entries[alias] = tce

        # Save keystore
        logger.debug("Saving JKS keystore")
        return ks.saves(password)

    except Exception as e:
        logger.error("Failed to create JKS keystore: %s", str(e))
        raise


def load_jks(data: bytes, password: str = "") -> jks.KeyStore:
    """Load a Java KeyStore from bytes"""
    logger.debug("Loading JKS keystore")

    try:
        ks = jks.KeyStore.loads(data, password)
        logger.debug(
            "JKS keystore loaded successfully (private keys: %d, certs: %d)",
            len(ks.private_keys),
            len(ks.certs),
        )
        return ks
    except Exception as e:
        logger.error("Failed to load JKS keystore: %s", str(e))
        raise
