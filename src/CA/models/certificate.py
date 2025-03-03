"""
Certificate Models for X.509 Certificate Management

This module provides the core data models for working with X.509 certificates:
- CertificateRequestBase: Abstract base class for certificate requests
- CertificateBase: Abstract base class for certificates
- CertificateRequest: Concrete implementation of certificate request
- Certificate: Concrete implementation of certificate with optional private key

These models handle all aspects of certificate data, including:
- Subject information (common name, country, etc.)
- Key parameters (type, size, curve)
- Extensions (key usage, extended key usage, SANs)
- Validity periods
- Import/export functionality

The models are designed to be flexible and extensible, allowing for different
storage backends and certificate formats while maintaining a consistent interface.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

logger = logging.getLogger(__name__)


class CertificateRequestBase(ABC):
    """
    Abstract base class defining the interface for certificate requests.

    This class defines the required properties that any certificate request
    implementation must provide. It includes all the basic fields needed
    for X.509 certificate generation:
    - Subject information (common name, country, etc.)
    - Key parameters
    - Extensions
    - Validity period

    All properties are defined as abstract, allowing different implementations
    to store and manage the data in different ways while maintaining a
    consistent interface.
    """

    @property
    @abstractmethod
    def common_name(self) -> str:
        """
        Get the certificate's common name.

        Returns:
            str: The common name (CN) for the certificate subject
        """

    @property
    @abstractmethod
    def country(self) -> str:
        """
        Get the certificate's country.

        Returns:
            str: The two-letter country code for the certificate subject
        """

    @property
    @abstractmethod
    def state(self) -> str:
        """
        Get the certificate's state or province.

        Returns:
            str: The state or province name for the certificate subject
        """

    @property
    @abstractmethod
    def locality(self) -> str:
        """
        Get the certificate's locality.

        Returns:
            str: The locality (city) name for the certificate subject
        """

    @property
    @abstractmethod
    def organization(self) -> str:
        """
        Get the certificate's organization.

        Returns:
            str: The organization name for the certificate subject
        """

    @property
    @abstractmethod
    def organizational_unit(self) -> str:
        """
        Get the certificate's organizational unit.

        Returns:
            str: The organizational unit name for the certificate subject
        """

    @property
    @abstractmethod
    def email(self) -> str:
        """
        Get the certificate's email address.

        Returns:
            str: The email address for the certificate subject
        """

    @property
    @abstractmethod
    def key_size(self) -> int:
        """
        Get the certificate's key size.

        Returns:
            int: The key size in bits (e.g., 2048 for RSA)
        """

    @property
    @abstractmethod
    def valid_days(self) -> int:
        """
        Get the certificate's validity period in days.

        Returns:
            int: The number of days the certificate should be valid
        """

    @property
    @abstractmethod
    def san_dns_names(self) -> List[str]:
        """
        Get the certificate's Subject Alternative Name DNS entries.

        Returns:
            List[str]: List of DNS names to include in the SAN extension
        """

    @property
    @abstractmethod
    def san_ip_addresses(self) -> List[str]:
        """
        Get the certificate's Subject Alternative Name IP addresses.

        Returns:
            List[str]: List of IP addresses to include in the SAN extension
        """

    @property
    @abstractmethod
    def is_ca(self) -> bool:
        """
        Get whether this is a CA certificate.

        Returns:
            bool: True if this is a CA certificate, False otherwise
        """

    @property
    @abstractmethod
    def path_length(self) -> Optional[int]:
        """
        Get the certificate's path length constraint.

        Returns:
            Optional[int]: Maximum number of intermediate CAs allowed, or None for no limit
        """

    @property
    @abstractmethod
    def custom_extensions(self) -> List[x509.Extension]:
        """
        Get the certificate's custom extensions.

        Returns:
            List[x509.Extension]: List of custom X.509 extensions to add
        """

    @property
    @abstractmethod
    def key_usage(self) -> Dict[str, bool]:
        """
        Get the certificate's key usage flags.

        Returns:
            Dict[str, bool]: Dictionary of key usage flags and their values
        """

    @property
    @abstractmethod
    def extended_key_usage(self) -> List[str]:
        """
        Get the certificate's extended key usage OIDs.

        Returns:
            List[str]: List of extended key usage OID strings
        """

    @property
    @abstractmethod
    def public_key(
        self,
    ) -> Optional[
        Union[
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
        ]
    ]:
        """
        Get the certificate's public key if provided.

        Returns:
            Optional[Union[...]]: The public key object if provided, None otherwise
        """

    @property
    @abstractmethod
    def crl_distribution_points(self) -> Optional[List[str]]:
        """
        Get the certificate's CRL distribution points.

        Returns:
            Optional[List[str]]: List of CRL distribution point URLs
        """


class CertificateBase(ABC):
    """
    Abstract base class defining the interface for certificates.

    This class defines the required properties and methods that any certificate
    implementation must provide. It includes all the basic fields needed for
    working with X.509 certificates:
    - Certificate data
    - Private key (optional)
    - Subject/issuer information
    - Validity period
    - Import/export functionality

    All properties and methods are defined as abstract, allowing different
    implementations to store and manage the data in different ways while
    maintaining a consistent interface.
    """

    @property
    @abstractmethod
    def cert_type(self) -> str:
        """
        Get the certificate type.

        Returns:
            str: The type of certificate ('client', 'server', 'ca')
        """

    @property
    @abstractmethod
    def certificate(self) -> x509.Certificate:
        """
        Get the X.509 certificate object.

        Returns:
            x509.Certificate: The cryptography library certificate object
        """

    @property
    @abstractmethod
    def private_key(
        self,
    ) -> Optional[
        Union[
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
        ]
    ]:
        """
        Get the certificate's private key if available.

        Returns:
            Optional[Union[...]]: The private key object if available, None otherwise
        """

    @property
    @abstractmethod
    def serial_number(self) -> int:
        """
        Get the certificate's serial number.

        Returns:
            int: The certificate serial number
        """

    @property
    @abstractmethod
    def subject(self) -> x509.Name:
        """
        Get the certificate's subject.

        Returns:
            x509.Name: The certificate subject name
        """

    @property
    @abstractmethod
    def issuer(self) -> x509.Name:
        """
        Get the certificate's issuer.

        Returns:
            x509.Name: The certificate issuer name
        """

    @property
    @abstractmethod
    def not_valid_before(self) -> datetime:
        """
        Get the certificate's not valid before date.

        Returns:
            datetime: The date from which the certificate is valid
        """

    @property
    @abstractmethod
    def not_valid_after(self) -> datetime:
        """
        Get the certificate's not valid after date.

        Returns:
            datetime: The date after which the certificate is no longer valid
        """

    @property
    @abstractmethod
    def public_key(self) -> Any:
        """
        Get the certificate's public key.

        Returns:
            Any: The public key object
        """

    @property
    @abstractmethod
    def is_ca(self) -> bool:
        """
        Check if this is a CA certificate.

        Returns:
            bool: True if this is a CA certificate, False otherwise
        """

    @property
    @abstractmethod
    def path_length(self) -> Optional[int]:
        """
        Get the certificate's path length constraint.

        Returns:
            Optional[int]: Maximum number of intermediate CAs allowed, or None for no limit
        """

    @property
    @abstractmethod
    def common_name(self) -> str:
        """
        Get the certificate's common name.

        Returns:
            str: The common name from the certificate subject
        """

    @abstractmethod
    def to_pem(self) -> bytes:
        """
        Convert certificate to PEM format.

        Returns:
            bytes: The certificate in PEM format
        """

    @abstractmethod
    def private_key_to_pem(self, password: Optional[bytes] = None) -> bytes:
        """
        Convert private key to PEM format.

        Args:
            password: Optional password to encrypt the private key

        Returns:
            bytes: The private key in PEM format

        Raises:
            ValueError: If no private key is available
        """


class CertificateRequest(CertificateRequestBase):
    """Certificate signing request parameters"""

    def __init__(
        self,
        common_name: str,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        email: Optional[str] = None,
        valid_days: int = 365,
        not_valid_before: Optional[datetime] = None,
        not_valid_after: Optional[datetime] = None,
        is_ca: bool = False,
        path_length: Optional[int] = None,
        key_type: str = "rsa",
        key_size: int = 2048,
        curve: Optional[str] = None,
        san_dns_names: Optional[List[str]] = None,
        san_ip_addresses: Optional[List[str]] = None,
        key_usage: Optional[Dict[str, bool]] = None,
        extended_key_usage: Optional[List[str]] = None,
        crl_distribution_points: Optional[List[str]] = None,
        custom_extensions: Optional[List[x509.Extension]] = None,
        public_key: Optional[
            Union[
                rsa.RSAPublicKey,
                ec.EllipticCurvePublicKey,
                ed25519.Ed25519PublicKey,
                ed448.Ed448PublicKey,
            ]
        ] = None,
        hash_algorithm: Optional[hashes.HashAlgorithm] = None,
        policy_oids: Optional[List[x509.ObjectIdentifier]] = None,
        permitted_dns_domains: Optional[List[str]] = None,
        excluded_dns_domains: Optional[List[str]] = None,
        ocsp_responder_url: Optional[str] = None,
        ca_issuers_url: Optional[str] = None,
        ms_template_name: Optional[str] = None,
        ms_template_version: Optional[Tuple[int, int]] = None,
    ):
        """Initialize certificate request parameters"""
        logger.debug("Creating new certificate request for CN=%s", common_name)
        self._common_name = common_name
        self._country = country
        self._state = state
        self._locality = locality
        self._organization = organization
        self._organizational_unit = organizational_unit
        self._email = email
        self._valid_days = valid_days
        self._not_valid_before = not_valid_before
        self._not_valid_after = not_valid_after
        self._is_ca = is_ca
        self._path_length = path_length
        self._key_type = key_type
        self._key_size = key_size
        self._curve = curve
        self._san_dns_names = san_dns_names or []
        self._san_ip_addresses = san_ip_addresses or []
        self._key_usage = key_usage
        self._extended_key_usage = extended_key_usage
        self._crl_distribution_points = crl_distribution_points or []
        self._custom_extensions = custom_extensions or []
        self._public_key = public_key
        self._hash_algorithm = hash_algorithm
        self._policy_oids = policy_oids or []
        self._permitted_dns_domains = permitted_dns_domains or []
        self._excluded_dns_domains = excluded_dns_domains or []
        self._ocsp_responder_url = ocsp_responder_url
        self._ca_issuers_url = ca_issuers_url
        self._ms_template_name = ms_template_name
        self._ms_template_version = ms_template_version
        logger.debug(
            "Certificate request initialized with: key_type=%s, key_size=%s, curve=%s, is_ca=%s",
            self._key_type,
            self._key_size,
            self._curve,
            self._is_ca,
        )

    @property
    def common_name(self) -> str:
        return self._common_name

    @common_name.setter
    def common_name(self, value: str) -> None:
        logger.debug("Setting common_name to: %s", value)
        self._common_name = value

    @property
    def country(self) -> Optional[str]:
        return self._country

    @country.setter
    def country(self, value: Optional[str]) -> None:
        self._country = value

    @property
    def state(self) -> Optional[str]:
        return self._state

    @state.setter
    def state(self, value: Optional[str]) -> None:
        self._state = value

    @property
    def locality(self) -> Optional[str]:
        return self._locality

    @locality.setter
    def locality(self, value: Optional[str]) -> None:
        self._locality = value

    @property
    def organization(self) -> Optional[str]:
        return self._organization

    @organization.setter
    def organization(self, value: Optional[str]) -> None:
        self._organization = value

    @property
    def organizational_unit(self) -> Optional[str]:
        return self._organizational_unit

    @organizational_unit.setter
    def organizational_unit(self, value: Optional[str]) -> None:
        self._organizational_unit = value

    @property
    def email(self) -> Optional[str]:
        return self._email

    @email.setter
    def email(self, value: Optional[str]) -> None:
        self._email = value

    @property
    def valid_days(self) -> int:
        return self._valid_days

    @valid_days.setter
    def valid_days(self, value: int) -> None:
        self._valid_days = value

    @property
    def not_valid_before(self) -> Optional[datetime]:
        """Get the certificate's not valid before date"""
        return self._not_valid_before

    @not_valid_before.setter
    def not_valid_before(self, value: Optional[datetime]) -> None:
        self._not_valid_before = value

    @property
    def not_valid_after(self) -> Optional[datetime]:
        """Get the certificate's not valid after date"""
        return self._not_valid_after

    @not_valid_after.setter
    def not_valid_after(self, value: Optional[datetime]) -> None:
        self._not_valid_after = value

    @property
    def is_ca(self) -> bool:
        return self._is_ca

    @is_ca.setter
    def is_ca(self, value: bool) -> None:
        self._is_ca = value

    @property
    def path_length(self) -> Optional[int]:
        return self._path_length

    @path_length.setter
    def path_length(self, value: Optional[int]) -> None:
        self._path_length = value

    @property
    def key_type(self) -> str:
        return self._key_type

    @key_type.setter
    def key_type(self, value: str) -> None:
        self._key_type = value

    @property
    def key_size(self) -> int:
        return self._key_size

    @key_size.setter
    def key_size(self, value: int) -> None:
        self._key_size = value

    @property
    def curve(self) -> Optional[str]:
        return self._curve

    @curve.setter
    def curve(self, value: Optional[str]) -> None:
        self._curve = value

    @property
    def san_dns_names(self) -> List[str]:
        return self._san_dns_names

    @san_dns_names.setter
    def san_dns_names(self, value: List[str]) -> None:
        self._san_dns_names = value

    @property
    def san_ip_addresses(self) -> List[str]:
        return self._san_ip_addresses

    @san_ip_addresses.setter
    def san_ip_addresses(self, value: List[str]) -> None:
        self._san_ip_addresses = value

    @property
    def key_usage(self) -> Optional[Dict[str, bool]]:
        return self._key_usage

    @key_usage.setter
    def key_usage(self, value: Optional[Dict[str, bool]]) -> None:
        self._key_usage = value

    @property
    def extended_key_usage(self) -> Optional[List[str]]:
        return self._extended_key_usage

    @extended_key_usage.setter
    def extended_key_usage(self, value: Optional[List[str]]) -> None:
        self._extended_key_usage = value

    @property
    def crl_distribution_points(self) -> List[str]:
        return self._crl_distribution_points

    @crl_distribution_points.setter
    def crl_distribution_points(self, value: List[str]) -> None:
        self._crl_distribution_points = value

    @property
    def custom_extensions(self) -> List[x509.Extension]:
        return self._custom_extensions

    @custom_extensions.setter
    def custom_extensions(self, value: List[x509.Extension]) -> None:
        self._custom_extensions = value

    @property
    def public_key(
        self,
    ) -> Optional[
        Union[
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
        ]
    ]:
        return self._public_key

    @public_key.setter
    def public_key(
        self,
        value: Optional[
            Union[
                rsa.RSAPublicKey,
                ec.EllipticCurvePublicKey,
                ed25519.Ed25519PublicKey,
                ed448.Ed448PublicKey,
            ]
        ],
    ) -> None:
        self._public_key = value

    @property
    def hash_algorithm(self) -> Optional[hashes.HashAlgorithm]:
        """Get the hash algorithm to use for signing"""
        return self._hash_algorithm

    @hash_algorithm.setter
    def hash_algorithm(self, value: Optional[hashes.HashAlgorithm]) -> None:
        self._hash_algorithm = value

    @property
    def policy_oids(self) -> List[x509.ObjectIdentifier]:
        """Get the certificate policy OIDs"""
        return self._policy_oids

    @policy_oids.setter
    def policy_oids(self, value: List[x509.ObjectIdentifier]) -> None:
        self._policy_oids = value

    @property
    def permitted_dns_domains(self) -> List[str]:
        """Get the permitted DNS domains for name constraints"""
        return self._permitted_dns_domains

    @permitted_dns_domains.setter
    def permitted_dns_domains(self, value: List[str]) -> None:
        self._permitted_dns_domains = value

    @property
    def excluded_dns_domains(self) -> List[str]:
        """Get the excluded DNS domains for name constraints"""
        return self._excluded_dns_domains

    @excluded_dns_domains.setter
    def excluded_dns_domains(self, value: List[str]) -> None:
        self._excluded_dns_domains = value

    @property
    def ocsp_responder_url(self) -> Optional[str]:
        """Get the OCSP responder URL"""
        return self._ocsp_responder_url

    @ocsp_responder_url.setter
    def ocsp_responder_url(self, value: Optional[str]) -> None:
        self._ocsp_responder_url = value

    @property
    def ca_issuers_url(self) -> Optional[str]:
        """Get the CA issuers URL"""
        return self._ca_issuers_url

    @ca_issuers_url.setter
    def ca_issuers_url(self, value: Optional[str]) -> None:
        self._ca_issuers_url = value

    @property
    def ms_template_name(self) -> Optional[str]:
        """Get the Microsoft certificate template name"""
        return self._ms_template_name

    @ms_template_name.setter
    def ms_template_name(self, value: Optional[str]) -> None:
        self._ms_template_name = value

    @property
    def ms_template_version(self) -> Optional[Tuple[int, int]]:
        """Get the Microsoft certificate template version"""
        return self._ms_template_version

    @ms_template_version.setter
    def ms_template_version(self, value: Optional[Tuple[int, int]]) -> None:
        self._ms_template_version = value


@dataclass
class Certificate(CertificateBase):
    """
    A concrete implementation of a certificate with optional private key.

    This class represents an X.509 certificate and optionally its private key.
    It provides access to all certificate attributes and supports conversion
    to various formats.

    Attributes:
        _cert_type: The type of certificate ('client', 'server', 'ca')
        _certificate: The cryptography library certificate object
        _private_key: The private key if available
    """

    _cert_type: str = field(init=False)
    _certificate: x509.Certificate = field(init=False)
    _private_key: Optional[
        Union[
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
        ]
    ] = field(init=False, default=None)

    def __init__(
        self,
        cert_type: str,
        certificate: x509.Certificate,
        private_key: Optional[
            Union[
                rsa.RSAPrivateKey,
                ec.EllipticCurvePrivateKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
            ]
        ] = None,
    ):
        logger.debug("Creating new Certificate object of type: %s", cert_type)
        self._cert_type = cert_type
        self._certificate = certificate
        self._private_key = private_key
        logger.debug(
            "Certificate initialized with serial number: %d",
            certificate.serial_number)

    @property
    def cert_type(self) -> str:
        """Get the certificate type"""
        return self._cert_type

    @cert_type.setter
    def cert_type(self, value: str) -> None:
        self._cert_type = value

    @property
    def certificate(self) -> x509.Certificate:
        """Get the X.509 certificate"""
        return self._certificate

    @certificate.setter
    def certificate(self, value: x509.Certificate) -> None:
        self._certificate = value

    @property
    def private_key(
        self,
    ) -> Optional[
        Union[
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
        ]
    ]:
        """Get the private key if available"""
        return self._private_key

    @private_key.setter
    def private_key(
        self,
        value: Optional[
            Union[
                rsa.RSAPrivateKey,
                ec.EllipticCurvePrivateKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
            ]
        ],
    ) -> None:
        self._private_key = value

    @property
    def serial_number(self) -> int:
        """Get the certificate's serial number"""
        return self._certificate.serial_number

    @property
    def subject(self) -> x509.Name:
        """Get the certificate's subject"""
        return self._certificate.subject

    @property
    def issuer(self) -> x509.Name:
        """Get the certificate's issuer"""
        return self._certificate.issuer

    @property
    def not_valid_before(self) -> datetime:
        """Get the certificate's not valid before date"""
        return self._certificate.not_valid_before

    @property
    def not_valid_after(self) -> datetime:
        """Get the certificate's not valid after date"""
        return self._certificate.not_valid_after

    @property
    def public_key(self) -> Any:
        """Get the certificate's public key"""
        return self._certificate.public_key()

    @property
    def is_ca(self) -> bool:
        """Check if this is a CA certificate"""
        try:
            ext = self._certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            return ext.value.ca
        except x509.ExtensionNotFound:
            return False

    @property
    def path_length(self) -> Optional[int]:
        """Get the certificate's path length constraint"""
        try:
            ext = self._certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            return ext.value.path_length
        except x509.ExtensionNotFound:
            return None

    @property
    def common_name(self) -> str:
        """Get the certificate's common name"""
        return self.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME)[0].value

    def to_pem(self) -> bytes:
        """Convert certificate to PEM format"""
        logger.debug("Converting certificate to PEM format")
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    def private_key_to_pem(self, password: Optional[bytes] = None) -> bytes:
        """Convert private key to PEM format"""
        if not self._private_key:
            logger.debug("No private key available for PEM conversion")
            raise ValueError("No private key available")

        logger.debug(
            "Converting private key to PEM format (password protected: %s)",
            "yes" if password else "no",
        )
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
