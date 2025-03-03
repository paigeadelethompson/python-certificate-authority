"""
Abstract base class for certificate stores
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


class CertificateStoreBase(ABC):
    """Abstract base class for certificate storage implementations"""

    def __init__(self, base_path: Path):
        """
        Initialize the store

        Args:
            base_path: Base path for certificate storage
        """
        self.base_path = Path(base_path)

    @abstractmethod
    async def save_ca_key(self, key_data: bytes) -> None:
        """
        Save the CA private key

        Args:
            key_data: PEM-encoded private key data
        """

    @abstractmethod
    async def save_ca_cert(self, cert_data: bytes) -> None:
        """
        Save the CA certificate

        Args:
            cert_data: PEM-encoded certificate data
        """

    @abstractmethod
    async def load_ca_key(self) -> Optional[rsa.RSAPrivateKey]:
        """
        Load the CA private key

        Returns:
            The CA private key or None if not found
        """

    @abstractmethod
    async def load_ca_cert(self) -> Optional[x509.Certificate]:
        """
        Load the CA certificate

        Returns:
            The CA certificate or None if not found
        """

    @abstractmethod
    async def save_certificate(
            self,
            cert_type: str,
            serial: int,
            cert_data: bytes,
            key_data: Optional[bytes] = None) -> None:
        """
        Save a certificate and optionally its private key

        Args:
            cert_type: Type of certificate ("sub-ca", "server", or "client")
            serial: Certificate serial number
            cert_data: PEM-encoded certificate data
            key_data: Optional PEM-encoded private key data
        """
        logger.debug("Abstract save_certificate called")

    @abstractmethod
    async def revoke_certificate(
        self, serial: int, reason: Optional[x509.ReasonFlags] = None
    ) -> None:
        """
        Revoke a certificate

        Args:
            serial: Serial number of certificate to revoke
            reason: Optional revocation reason

        Raises:
            ValueError: If certificate not found
        """
        logger.debug("Abstract revoke_certificate called")

    @abstractmethod
    async def get_certificate(self, serial: int) -> Optional[Dict[str, Any]]:
        """
        Get certificate information by serial number

        Args:
            serial: Certificate serial number

        Returns:
            Dictionary containing certificate information or None if not found
        """
        logger.debug("Abstract get_certificate called")

    @abstractmethod
    async def list_certificates(
            self, cert_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all certificates, optionally filtered by type

        Args:
            cert_type: Optional certificate type to filter by

        Returns:
            List of certificate information dictionaries
        """
        logger.debug("Abstract list_certificates called")

    @abstractmethod
    async def list_revoked(self) -> List[Dict[str, Any]]:
        """
        List all revoked certificates

        Returns:
            List of revoked certificate information dictionaries
        """
        logger.debug("Abstract list_revoked called")
