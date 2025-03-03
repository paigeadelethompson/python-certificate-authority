"""
Certificate Authority implementation
"""

import datetime
import ipaddress
import logging
import os
from typing import Optional, Type

import aiofiles
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .constants import SAFE_CURVES
from .models.certificate import Certificate, CertificateRequest
from .models.store import FileCertificateStore
from .models.store_base import CertificateStoreBase
from .utils.jks import JKSHelper
from .utils.pkcs import PKCS12Helper

# Configure logging
logger = logging.getLogger(__name__)


class CertificateAuthority:
    def __init__(
        self,
        base_dir: str,
        store_class: Type[CertificateStoreBase] = FileCertificateStore,
        ca_key: Optional[bytes] = None,
        ca_cert: Optional[bytes] = None,
    ):
        """
        Initialize the Certificate Authority

        Args:
            base_dir: Base directory for CA files
            store_class: Class to use for certificate storage
            ca_key: Optional PEM-encoded CA private key
            ca_cert: Optional PEM-encoded CA certificate
        """
        if not base_dir:
            raise ValueError("base_dir is required")

        logger.debug("Initializing CertificateAuthority")
        self.base_dir = base_dir
        logger.debug("Using base directory: %s", self.base_dir)
        self.store = store_class(self.base_dir)
        self.ca_key = (
            None if ca_key is None else serialization.load_pem_private_key(
                ca_key, password=None))
        self.ca_cert = None if ca_cert is None else x509.load_pem_x509_certificate(
            ca_cert)
        self.initialized = self.ca_key is not None and self.ca_cert is not None
        self.serial_file = os.path.join(self.base_dir, "serial.txt")
        logger.debug(
            "CA initialization complete. Initialized: %s",
            self.initialized)

    async def _get_next_serial(self) -> int:
        """Get the next serial number and increment it"""
        logger.debug("Getting next serial number")
        try:
            if os.path.exists(self.serial_file):
                async with aiofiles.open(self.serial_file, "r") as f:
                    content = await f.read()
                    serial = int(content.strip())
                    logger.debug("Current serial number: %d", serial)
            else:
                logger.debug(
                    "Serial file not found, starting with serial number 1")
                serial = 1
        except (ValueError, FileNotFoundError):
            logger.debug(
                "Error reading serial file, starting with serial number 1")
            serial = 1

        # Write the next serial number
        async with aiofiles.open(self.serial_file, "w") as f:
            await f.write(str(serial + 1))
            logger.debug("Next serial number will be: %d", serial + 1)

        return serial

    async def initialize(
        self,
        common_name: Optional[str] = None,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        org: Optional[str] = None,
        org_unit: Optional[str] = None,
        key_type: str = "rsa",
        key_size: int = 2048,
        curve: Optional[str] = None,
    ) -> None:
        """Initialize the CA with a new key pair and self-signed certificate."""
        logger.debug(
            "Initializing CA with key_type=%s, key_size=%d, curve=%s",
            key_type,
            key_size,
            curve)

        if self.initialized and not (self.ca_key and self.ca_cert):
            logger.error("CA is already initialized")
            raise RuntimeError("CA is already initialized")

        if not os.path.exists(self.base_dir):
            logger.debug("Creating base directory: %s", self.base_dir)
            os.makedirs(self.base_dir)

        if self.ca_key is not None and self.ca_cert is not None:
            logger.debug("Using existing CA key and certificate")
            # Save existing CA certificate and key
            key_pem = self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            cert_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM)
            await self.store.save_ca_key(key_pem)
            await self.store.save_ca_cert(cert_pem)
            self.initialized = True
            logger.debug("Existing CA key and certificate saved")
            return

        if not common_name:
            logger.error("Common name is required")
            raise ValueError("Common name is required")

        # Generate or load CA key pair
        if not self.ca_key:
            logger.debug("Generating new CA key pair")
            if key_type.lower() == "rsa":
                if key_size < 2048:
                    logger.error("Key size must be at least 2048 bits")
                    raise ValueError("Key size must be at least 2048 bits")
                logger.debug("Generating RSA key pair with size %d", key_size)
                self.ca_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                )
            elif key_type.lower() == "ec":
                if not curve:
                    logger.error("Curve name is required for EC keys")
                    raise ValueError("Curve name is required for EC keys")
                if curve.lower() not in SAFE_CURVES:
                    logger.error("Unsupported or unsafe curve: %s", curve)
                    raise ValueError(
                        f"Unsupported or unsafe curve: {curve}. Please use one of: {
                            ', '.join(
                                SAFE_CURVES.keys())}")
                if SAFE_CURVES[curve.lower()] is None:
                    logger.error(
                        "Curve %s is not available in the cryptography library", curve)
                    raise ValueError(
                        f"Curve {curve} is not available in the cryptography library")

                curve_impl = SAFE_CURVES[curve.lower()]
                if isinstance(curve_impl, ec.EllipticCurve):
                    logger.debug("Generating EC key pair with curve %s", curve)
                    self.ca_key = ec.generate_private_key(curve_impl)
                else:
                    logger.error("Invalid curve implementation")
                    raise ValueError("Invalid curve implementation")
            elif key_type.lower() == "ed25519":
                logger.debug("Generating Ed25519 key pair")
                self.ca_key = ed25519.Ed25519PrivateKey.generate()
            elif key_type.lower() == "ed448":
                logger.debug("Generating Ed448 key pair")
                self.ca_key = ed448.Ed448PrivateKey.generate()
            else:
                logger.error("Invalid key_type: %s", key_type)
                raise ValueError(
                    "key_type must be 'rsa', 'ec', 'ed25519', or 'ed448'")

        # Create self-signed CA certificate
        builder = x509.CertificateBuilder()
        subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        if country:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME,
                    country))
        if state:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME,
                    state))
        if locality:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME,
                    locality))
        if org:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, org))
        if org_unit:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME,
                    org_unit))

        subject = x509.Name(subject_attrs)
        builder = builder.subject_name(subject)
        # Self-signed, so subject = issuer
        builder = builder.issuer_name(subject)
        builder = builder.not_valid_before(
            datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(
            datetime.datetime.now(
                datetime.timezone.utc) +
            datetime.timedelta(
                days=3650))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(self.ca_key.public_key())

        # Add CA extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Add Authority Key Identifier and Subject Key Identifier
        public_key = self.ca_key.public_key()
        ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(ski, critical=False)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False)

        # Sign the certificate
        signing_algorithm = (
            None if isinstance(
                self.ca_key,
                (ed25519.Ed25519PrivateKey,
                 ed448.Ed448PrivateKey)) else hashes.SHA256())
        self.ca_cert = builder.sign(
            private_key=self.ca_key,
            algorithm=signing_algorithm)

        # Save CA certificate and key
        key_pem = self.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM)
        await self.store.save_ca_key(key_pem)
        await self.store.save_ca_cert(cert_pem)
        self.initialized = True

    async def issue_certificate(
        self, request: CertificateRequest, cert_type: str = "client"
    ) -> Certificate:
        """Issue a new certificate based on the request."""
        logger.debug(
            "Issuing certificate of type '%s' for common name '%s'",
            cert_type,
            request.common_name)

        if not self.initialized:
            logger.error("CA must be initialized first")
            raise RuntimeError("CA must be initialized first")

        if not request.common_name:
            logger.error("Common name is required")
            raise ValueError("Common name is required")

        # Validate certificate type
        valid_types = ["ca", "sub-ca", "server", "client"]
        if cert_type not in valid_types:
            logger.error("Invalid certificate type: %s", cert_type)
            raise ValueError("Invalid certificate type")

        # Validate key parameters
        logger.debug(
            "Validating key parameters: type=%s, size=%d, curve=%s",
            request.key_type,
            request.key_size,
            request.curve,
        )
        if request.key_type.lower() == "rsa":
            if request.key_size < 2048:
                logger.error("Key size must be at least 2048 bits")
                raise ValueError("Key size must be at least 2048 bits")
        elif request.key_type.lower() == "ec":
            if not request.curve:
                logger.error("Curve name is required for EC keys")
                raise ValueError("Curve name is required for EC keys")
            if request.curve.lower() not in SAFE_CURVES:
                logger.error("Unsupported or unsafe curve: %s", request.curve)
                raise ValueError(
                    f"Unsupported or unsafe curve: {
                        request.curve}. Please use one of: {
                        ', '.join(
                            SAFE_CURVES.keys())}")
            if SAFE_CURVES[request.curve.lower()] is None:
                logger.error(
                    "Curve %s is not available in the cryptography library",
                    request.curve)
                raise ValueError(
                    f"Curve {
                        request.curve} is not available in the cryptography library")

        # Validate path length constraint for sub-CA certificates
        if request.is_ca or cert_type == "sub-ca":
            logger.debug("Validating CA certificate constraints")
            if request.path_length is not None and request.path_length < 0:
                logger.error("Path length must be non-negative")
                raise ValueError("Path length must be non-negative")
            ca_basic_constraints = self.ca_cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
            if not ca_basic_constraints.value.ca:
                logger.error("Cannot issue CA certificate: issuer is not a CA")
                raise ValueError(
                    "Cannot issue CA certificate: issuer is not a CA")
            if ca_basic_constraints.value.path_length is not None:
                if ca_basic_constraints.value.path_length == 0:
                    logger.error(
                        "Cannot issue CA certificate: path length constraint violated")
                    raise ValueError(
                        "Cannot issue CA certificate: path length constraint violated")
                # Ensure the path length is decremented for the new CA
                if (request.path_length is None or request.path_length >=
                        ca_basic_constraints.value.path_length):
                    logger.debug(
                        "Adjusting path length constraint from %s to %d",
                        request.path_length,
                        ca_basic_constraints.value.path_length - 1,
                    )
                    request.path_length = ca_basic_constraints.value.path_length - 1

        # Create certificate builder
        logger.debug("Building certificate with subject attributes")
        subject_attrs = [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                request.common_name)]
        if request.country:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME,
                    request.country))
        if request.state:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME,
                    request.state))
        if request.locality:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME,
                    request.locality))
        if request.organization:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME,
                    request.organization))
        if request.organizational_unit:
            subject_attrs.append(
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME,
                    request.organizational_unit))

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name(subject_attrs))
        builder = builder.issuer_name(self.ca_cert.subject)

        # Set validity period
        logger.debug("Setting certificate validity period")
        if request.not_valid_before and request.not_valid_after:
            logger.debug(
                "Using explicit validity dates: %s to %s",
                request.not_valid_before,
                request.not_valid_after,
            )
            builder = builder.not_valid_before(request.not_valid_before)
            builder = builder.not_valid_after(request.not_valid_after)
        else:
            logger.debug(
                "Using validity period of %d days",
                request.valid_days)
            builder = builder.not_valid_before(
                datetime.datetime.now(datetime.timezone.utc))
            builder = builder.not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=request.valid_days)
            )

        serial = await self._get_next_serial()
        logger.debug("Using serial number: %d", serial)
        builder = builder.serial_number(serial)

        # Generate key pair if not provided
        if request.public_key is None:
            logger.debug("Generating new key pair")
            if request.key_type.lower() == "rsa":
                logger.debug(
                    "Generating RSA key pair with size %d",
                    request.key_size)
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=request.key_size,
                )
            elif request.key_type.lower() in ["ed25519", "ed448"]:
                logger.debug("Generating %s key pair", request.key_type)
                if request.key_type.lower() == "ed25519":
                    private_key = ed25519.Ed25519PrivateKey.generate()
                else:
                    private_key = ed448.Ed448PrivateKey.generate()
            else:  # EC
                if not request.curve:
                    logger.error("Curve name is required for EC keys")
                    raise ValueError("Curve name is required for EC keys")
                curve_impl = SAFE_CURVES[request.curve.lower()]
                if isinstance(
                    curve_impl,
                    type) and issubclass(
                    curve_impl,
                    (ed25519.Ed25519PrivateKey,
                     ed448.Ed448PrivateKey)):
                    logger.debug("Generating %s key pair", request.curve)
                    private_key = curve_impl.generate()
                else:
                    logger.debug(
                        "Generating EC key pair with curve %s",
                        request.curve)
                    private_key = ec.generate_private_key(curve_impl)
            public_key = private_key.public_key()
        else:
            logger.debug("Using provided public key")
            public_key = request.public_key
            private_key = None

        builder = builder.public_key(public_key)

        # Add extensions
        logger.debug("Adding certificate extensions")

        # Basic Constraints
        logger.debug(
            "Adding Basic Constraints extension (CA: %s, path_length: %s)",
            request.is_ca or cert_type == "sub-ca",
            request.path_length,
        )
        builder = builder.add_extension(
            x509.BasicConstraints(
                ca=request.is_ca or cert_type == "sub-ca",
                path_length=request.path_length),
            critical=True,
        )

        # Key Usage
        is_ca = request.is_ca or cert_type == "sub-ca"
        key_usage_flags = {
            "digital_signature": True,
            "content_commitment": False,
            "key_encipherment": cert_type == "server",
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": is_ca,
            "crl_sign": is_ca,
            "encipher_only": False,
            "decipher_only": False,
        }

        # Override defaults with request values
        if request.key_usage:
            logger.debug(
                "Overriding default key usage flags with request values")
            key_usage_flags.update(request.key_usage)

        # Ensure CA certificates have required key usage flags
        if is_ca:
            logger.debug(
                "Ensuring CA certificates have required key usage flags")
            key_usage_flags["key_cert_sign"] = True
            key_usage_flags["crl_sign"] = True

        logger.debug("Adding Key Usage extension: %s", key_usage_flags)
        builder = builder.add_extension(
            x509.KeyUsage(**key_usage_flags),
            critical=True,
        )

        # Add Extended Key Usage extension
        if request.extended_key_usage:
            logger.debug(
                "Adding custom Extended Key Usage: %s",
                request.extended_key_usage)
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(
                    [x509.ObjectIdentifier(oid) for oid in request.extended_key_usage]
                ),
                critical=False,
            )
        else:
            # Add default extended key usage based on certificate type
            if cert_type == "server":
                logger.debug("Adding server authentication Extended Key Usage")
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False,
                )
            elif cert_type == "client":
                logger.debug("Adding client authentication Extended Key Usage")
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                    critical=False,
                )

        # Add Subject Alternative Name extension if specified
        san_list = []
        if request.san_dns_names:
            logger.debug("Adding DNS SANs: %s", request.san_dns_names)
            san_list.extend([x509.DNSName(name)
                            for name in request.san_dns_names])
        if request.san_ip_addresses:
            logger.debug("Adding IP SANs: %s", request.san_ip_addresses)
            san_list.extend([x509.IPAddress(ipaddress.ip_address(ip))
                             for ip in request.san_ip_addresses])
        if request.email:
            logger.debug("Adding email SAN: %s", request.email)
            san_list.append(x509.RFC822Name(request.email))
        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        # Add Authority Key Identifier and Subject Key Identifier
        logger.debug("Adding Key Identifiers")
        ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(ski, critical=False)

        # Get the Authority Key Identifier from the CA certificate
        ca_ski = self.ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=ca_ski.value.digest,
                authority_cert_issuer=[
                    x509.DirectoryName(
                        self.ca_cert.subject)],
                authority_cert_serial_number=self.ca_cert.serial_number,
            ),
            critical=False,
        )

        # Add CRL Distribution Points if specified
        if request.crl_distribution_points:
            logger.debug(
                "Adding CRL Distribution Points: %s",
                request.crl_distribution_points)
            builder = builder.add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(uri)],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                        for uri in request.crl_distribution_points
                    ]
                ),
                critical=False,
            )

        # Add custom extensions
        if request.custom_extensions:
            logger.debug("Adding custom extensions")
            for extension in request.custom_extensions:
                builder = builder.add_extension(
                    extension.value, critical=extension.critical)

        # Add certificate policies if specified
        if request.policy_oids:
            logger.debug(
                "Adding certificate policies: %s",
                request.policy_oids)
            builder = builder.add_extension(
                x509.CertificatePolicies(
                    [x509.PolicyInformation(policy_oid, None) for policy_oid in request.policy_oids]
                ),
                critical=False,
            )

        # Add name constraints if specified
        if request.permitted_dns_domains or request.excluded_dns_domains:
            logger.debug("Adding name constraints")
            permitted = None
            excluded = None

            if request.permitted_dns_domains:
                permitted = [x509.DNSName(name)
                             for name in request.permitted_dns_domains]

            if request.excluded_dns_domains:
                excluded = [x509.DNSName(name)
                            for name in request.excluded_dns_domains]

            builder = builder.add_extension(
                x509.NameConstraints(
                    permitted_subtrees=permitted,
                    excluded_subtrees=excluded),
                critical=True,
            )

        # Add Authority Information Access if OCSP or CA issuers URL is
        # specified
        if request.ocsp_responder_url or request.ca_issuers_url:
            logger.debug("Adding Authority Information Access")
            aia_entries = []

            if request.ocsp_responder_url:
                aia_entries.append(
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(
                            request.ocsp_responder_url),
                    ))

            if request.ca_issuers_url:
                aia_entries.append(
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(request.ca_issuers_url),
                    )
                )

            builder = builder.add_extension(
                x509.AuthorityInformationAccess(aia_entries), critical=False
            )

        # Sign the certificate with specified hash algorithm or default
        logger.debug("Signing certificate")
        signing_algorithm = (
            None if isinstance(
                self.ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)) else (
                request.hash_algorithm or hashes.SHA256()))
        cert = builder.sign(
            private_key=self.ca_key,
            algorithm=signing_algorithm)

        # Create and save the certificate
        logger.debug("Creating certificate object")
        certificate = Certificate(
            cert_type=cert_type,
            certificate=cert,
            private_key=private_key)
        logger.debug("Saving certificate to store")
        await self.store.save_certificate(certificate)

        logger.debug("Certificate issuance completed successfully")
        return certificate

    async def revoke_certificate(
        self, serial_number: int, reason: Optional[x509.ReasonFlags] = None
    ) -> None:
        """Revoke a certificate and update CRL"""
        logger.debug(
            "Revoking certificate with serial number %d",
            serial_number)
        await self.store.revoke_certificate(serial_number, reason)
        logger.debug("Certificate revocation completed")

    async def generate_crl(self) -> x509.CertificateRevocationList:
        """Generate a Certificate Revocation List"""
        logger.debug("Generating CRL")
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.last_update(datetime.datetime.now(datetime.UTC))
        builder = builder.next_update(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        )

        # Add revoked certificates
        logger.debug("Retrieving list of revoked certificates")
        revoked = await self.store.list_revoked()
        for cert_info in revoked:
            logger.debug(
                "Adding revoked certificate with serial %d to CRL",
                cert_info["serial"])
            revoked_cert = x509.RevokedCertificateBuilder()
            revoked_cert = revoked_cert.serial_number(cert_info["serial"])
            revoked_cert = revoked_cert.revocation_date(
                datetime.datetime.now(datetime.UTC))
            if "reason" in cert_info:
                revoked_cert = revoked_cert.add_extension(
                    x509.CRLReason(cert_info["reason"]), critical=False
                )
            builder = builder.add_revoked_certificate(revoked_cert.build())

        logger.debug("Signing CRL")
        return builder.sign(private_key=self.ca_key, algorithm=hashes.SHA256())

    async def renew_certificate(self, serial_number: int) -> Certificate:
        """Renew a certificate with the same parameters"""
        logger.debug(
            "Renewing certificate with serial number %d",
            serial_number)

        # Get the original certificate
        cert_info = await self.store.get_certificate(serial_number)
        if not cert_info:
            logger.error("Certificate with serial %d not found", serial_number)
            raise ValueError(
                f"Certificate with serial {serial_number} not found")

        logger.debug(
            "Creating new request with original certificate parameters")
        # Create a new request with the same parameters
        request = CertificateRequest(
            common_name=cert_info["subject"]["common_name"],
            country=cert_info["subject"].get("country", "US"),
            state=cert_info["subject"].get("state", ""),
            locality=cert_info["subject"].get("locality", ""),
            organization=cert_info["subject"].get("organization", ""),
            organizational_unit=cert_info["subject"].get("organizational_unit", ""),
            valid_days=cert_info.get("valid_days", 365),
            is_ca=cert_info.get("is_ca", False),
            path_length=cert_info.get("path_length"),
        )

        # Issue new certificate
        logger.debug("Issuing new certificate")
        return await self.issue_certificate(request, cert_type=cert_info["type"])

    async def export_pkcs12(self, cert: Certificate, password: str) -> bytes:
        """Export certificate and private key as PKCS12"""
        logger.debug("Exporting certificate as PKCS12")

        if not password:
            logger.error("Password cannot be empty")
            raise ValueError("Password cannot be empty")

        ca_cert = await self.store.load_ca_cert()
        if not ca_cert:
            logger.error("CA certificate not found")
            raise ValueError("CA certificate not found")

        logger.debug("Creating PKCS12 file")
        return PKCS12Helper.create_pfx(
            private_key=cert.private_key,
            certificate=cert.certificate,
            ca_certs=[ca_cert],
            password=password,
        )

    async def export_jks(self, cert: Certificate, password: str) -> bytes:
        """Export certificate and private key as JKS"""
        logger.debug("Exporting certificate as JKS")

        ca_cert = await self.store.load_ca_cert()
        if not ca_cert:
            logger.error("CA certificate not found")
            raise ValueError("CA certificate not found")

        logger.debug("Creating JKS keystore with alias %s", cert.common_name)
        return JKSHelper.create_keystore(
            private_key=cert.private_key,
            cert_chain=[cert.certificate, ca_cert],
            alias=cert.common_name,
            password=password,
        )
