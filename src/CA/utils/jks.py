"""
Java KeyStore (JKS) helper utilities
"""

import logging
from typing import List, Optional, Tuple

import jks
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .serialization import certificate_to_der, private_key_to_der

logger = logging.getLogger(__name__)


class JKSHelper:
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
                key=key_der,
                key_format="pkcs8",  # Use pkcs8 format instead of password
            )
            ks.entries[alias] = pke

            # Get keystore as bytes
            logger.debug("Saving JKS keystore")
            return ks.saves(password)

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

    @staticmethod
    def extract_key_and_certs(
        keystore: jks.KeyStore, alias: str, password: str
    ) -> Tuple[rsa.RSAPrivateKey, list[x509.Certificate]]:
        """
        Extract private key and certificate chain from a keystore entry

        Args:
            keystore: The KeyStore object
            alias: Alias of the entry to extract
            password: Password to decrypt the private key

        Returns:
            Tuple of (private_key, certificate_chain)
        """
        # Get private key entry
        pk_entry = keystore.private_keys[alias]
        if not pk_entry:
            raise ValueError(f"No private key entry found with alias {alias}")

        # Decrypt private key if needed
        pk_entry.decrypt(password)

        # Load private key
        private_key = serialization.load_der_private_key(
            pk_entry.pkey, password=None)

        # Load certificates
        cert_chain = [x509.load_der_x509_certificate(
            cert) for cert in pk_entry.cert_chain]

        return private_key, cert_chain


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
            ks.add_private_key(
                alias=alias,
                key=private_key_to_der(key),
                cert_chain=cert_chain,
                password=password)
        else:
            # Add certificate entry
            logger.debug("Adding certificate entry with alias: %s", alias)
            ks.add_cert(alias=alias, cert=certificate_to_der(cert))

        # Add CA certificates if provided
        if ca_certs:
            for i, ca_cert in enumerate(ca_certs):
                ca_alias = f"ca{i + 1}"
                logger.debug("Adding CA certificate with alias: %s", ca_alias)
                ks.add_cert(alias=ca_alias, cert=certificate_to_der(ca_cert))

        # Save keystore to bytes
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
