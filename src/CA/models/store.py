"""
File-based certificate store implementation
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..utils.serialization import cert_to_json
from .certificate import Certificate
from .store_base import CertificateStoreBase

logger = logging.getLogger(__name__)


class FileCertificateStore(CertificateStoreBase):
    """File-based implementation of certificate storage"""

    def __init__(self, base_dir: str):
        """
        Initialize the certificate store

        Args:
            base_dir: Base directory for certificate storage
        """
        logger.debug(
            "Initializing certificate store in directory: %s",
            base_dir)
        self.base_dir = Path(base_dir)
        self.db_path = self.base_dir / "cert-db.json"

        # Create required directories
        for subdir in ["ca", "sub-ca", "server-certs", "client-certs", "crl"]:
            dir_path = self.base_dir / subdir
            if not dir_path.exists():
                logger.debug("Creating directory: %s", dir_path)
                dir_path.mkdir(parents=True, exist_ok=True)

        # Initialize database if it doesn't exist
        if not self.db_path.exists():
            self._init_db()

    def _init_db(self):
        """Initialize an empty certificate database"""
        db = {"certificates": [], "revoked": []}
        with open(self.db_path, "w") as f:
            json.dump(db, f, indent=2)

    async def _load_db(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load the certificate database"""
        if not self.db_path.exists():
            self._init_db()

        try:
            async with aiofiles.open(self.db_path, "r") as f:
                data = await f.read()
                if not data:
                    return {"certificates": [], "revoked": []}
                return json.loads(data)
        except json.JSONDecodeError:
            # If the file is corrupted, initialize a new database
            self._init_db()
            return {"certificates": [], "revoked": []}

    async def _save_db(self, db: Dict[str, List[Dict[str, Any]]]):
        """Save the certificate database"""
        async with aiofiles.open(self.db_path, "w") as f:
            await f.write(json.dumps(db, indent=2))

    async def save_ca_key(self, key_data: bytes) -> None:
        """Save the CA private key"""
        async with aiofiles.open(self.base_dir / "ca.key", "wb") as f:
            await f.write(key_data)

    async def save_ca_cert(self, cert_data: bytes) -> None:
        """Save the CA certificate"""
        async with aiofiles.open(self.base_dir / "ca.crt", "wb") as f:
            await f.write(cert_data)

    async def load_ca_key(self) -> Optional[rsa.RSAPrivateKey]:
        """Load the CA private key"""
        try:
            async with aiofiles.open(self.base_dir / "ca.key", "rb") as f:
                key_data = await f.read()
                return serialization.load_pem_private_key(
                    key_data, password=None)
        except FileNotFoundError:
            return None

    async def load_ca_cert(self) -> Optional[x509.Certificate]:
        """Load the CA certificate"""
        try:
            async with aiofiles.open(self.base_dir / "ca.crt", "rb") as f:
                cert_data = await f.read()
                return x509.load_pem_x509_certificate(cert_data)
        except FileNotFoundError:
            return None

    async def save_certificate(self, cert: Certificate) -> None:
        """Save a certificate and optionally its private key"""
        logger.debug(
            "Saving certificate: type=%s, serial=%d",
            cert.cert_type,
            cert.serial_number)

        # Use common name as filename base
        filename_base = cert.common_name.replace(
            "*", "wildcard").replace(".", "_")

        # Save certificate
        cert_path = self.base_dir / f"{filename_base}.crt"
        logger.debug("Writing certificate to: %s", cert_path)
        cert_path.write_bytes(cert.to_pem())

        # Save private key if provided
        if cert.private_key:
            key_path = self.base_dir / f"{filename_base}.key"
            logger.debug("Writing private key to: %s", key_path)
            key_path.write_bytes(
                cert.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Update database atomically
        try:
            async with aiofiles.open(self.db_path, "r+") as f:
                data = await f.read()
                db = json.loads(data) if data else {
                    "certificates": [], "revoked": []}

                # Check if serial number already exists
                for existing in db["certificates"]:
                    if existing["serial"] == cert.serial_number:
                        raise ValueError(
                            f"Certificate with serial {cert.serial_number} already exists")

                # Update database
                cert_info = cert_to_json(cert.certificate)
                cert_info["type"] = cert.cert_type
                cert_info["serial"] = cert.serial_number
                cert_info["filename"] = filename_base
                db["certificates"].append(cert_info)

                # Seek to beginning and write updated data
                await f.seek(0)
                await f.write(json.dumps(db, indent=2))
                await f.truncate()
        except FileNotFoundError:
            # If file doesn't exist, create it with initial data
            async with aiofiles.open(self.db_path, "w") as f:
                db = {"certificates": [], "revoked": []}
                cert_info = cert_to_json(cert.certificate)
                cert_info["type"] = cert.cert_type
                cert_info["serial"] = cert.serial_number
                cert_info["filename"] = filename_base
                db["certificates"].append(cert_info)
                await f.write(json.dumps(db, indent=2))

    async def revoke_certificate(
        self, serial: int, reason: Optional[x509.ReasonFlags] = None
    ) -> None:
        """
        Revoke a certificate

        Args:
            serial: Serial number of certificate to revoke
            reason: Optional revocation reason
        """
        db = await self._load_db()

        # Find certificate in database
        cert_info = None
        for cert in db["certificates"]:
            if cert["serial"] == serial:
                cert_info = cert
                break

        if not cert_info:
            raise ValueError(f"Certificate with serial {serial} not found")

        # Add revocation reason if provided
        if reason is not None:
            cert_info["reason"] = reason

        # Move to revoked list
        db["certificates"].remove(cert_info)
        db["revoked"].append(cert_info)
        await self._save_db(db)

    async def get_certificate(self, serial: int) -> Optional[Dict[str, Any]]:
        """Get certificate information by serial number"""
        logger.debug("Looking up certificate with serial: %d", serial)
        db = await self._load_db()

        # Search in active certificates
        for cert in db["certificates"]:
            if cert["serial"] == serial:
                logger.debug("Found certificate: type=%s", cert["type"])
                return cert

        # Search in revoked certificates
        for cert in db["revoked"]:
            if cert["serial"] == serial:
                logger.debug(
                    "Found revoked certificate: type=%s",
                    cert["type"])
                return cert

        logger.debug("Certificate not found")
        return None

    async def list_certificates(
            self, cert_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all certificates, optionally filtered by type"""
        logger.debug("Listing certificates (type=%s)", cert_type or "all")
        db = await self._load_db()

        if cert_type:
            return [cert for cert in db["certificates"]
                    if cert["type"] == cert_type]
        return db["certificates"]

    async def list_revoked(self) -> List[Dict[str, Any]]:
        """List all revoked certificates"""
        logger.debug("Listing revoked certificates")
        db = await self._load_db()
        return db["revoked"]

    async def load_certificate(self,
                               serial: int) -> Optional[x509.Certificate]:
        """Load a certificate by serial number"""
        logger.debug("Loading certificate with serial number: %d", serial)
        cert_info = await self.get_certificate(serial)
        if not cert_info:
            logger.debug("Certificate not found")
            return None

        # Load certificate from file
        cert_path = self.base_dir / f"{cert_info['filename']}.crt"
        try:
            async with aiofiles.open(cert_path, "rb") as f:
                cert_data = await f.read()
                return x509.load_pem_x509_certificate(cert_data)
        except FileNotFoundError:
            logger.debug("Certificate file not found")
            return None


# For backward compatibility
CertificateStore = FileCertificateStore
