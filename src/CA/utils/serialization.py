"""
Utilities for certificate serialization and deserialization
"""

import logging
from typing import Any, Dict, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


def cert_to_json(cert: x509.Certificate) -> Dict[str, Any]:
    """
    Convert a certificate to a JSON-serializable dictionary

    Args:
        cert: The certificate to convert

    Returns:
        Dictionary containing certificate details
    """

    def _get_name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except IndexError:
            return ""

    subject = cert.subject
    issuer = cert.issuer

    result = {
        "subject": {
            "common_name": _get_name_attr(subject, NameOID.COMMON_NAME),
            "country": _get_name_attr(subject, NameOID.COUNTRY_NAME),
            "state": _get_name_attr(subject, NameOID.STATE_OR_PROVINCE_NAME),
            "locality": _get_name_attr(subject, NameOID.LOCALITY_NAME),
            "organization": _get_name_attr(subject, NameOID.ORGANIZATION_NAME),
            "organizational_unit": _get_name_attr(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "email": _get_name_attr(subject, NameOID.EMAIL_ADDRESS),
        },
        "issuer": {
            "common_name": _get_name_attr(issuer, NameOID.COMMON_NAME),
            "country": _get_name_attr(issuer, NameOID.COUNTRY_NAME),
            "state": _get_name_attr(issuer, NameOID.STATE_OR_PROVINCE_NAME),
            "locality": _get_name_attr(issuer, NameOID.LOCALITY_NAME),
            "organization": _get_name_attr(issuer, NameOID.ORGANIZATION_NAME),
            "organizational_unit": _get_name_attr(issuer, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "email": _get_name_attr(issuer, NameOID.EMAIL_ADDRESS),
        },
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
    }

    # Add extensions
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        result["is_ca"] = basic_constraints.value.ca
        result["path_length"] = basic_constraints.value.path_length
    except x509.ExtensionNotFound:
        result["is_ca"] = False
        result["path_length"] = None

    try:
        key_usage = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE)
        result["key_usage"] = {
            "digital_signature": key_usage.value.digital_signature,
            "content_commitment": key_usage.value.content_commitment,
            "key_encipherment": key_usage.value.key_encipherment,
            "data_encipherment": key_usage.value.data_encipherment,
            "key_agreement": key_usage.value.key_agreement,
            "key_cert_sign": key_usage.value.key_cert_sign,
            "crl_sign": key_usage.value.crl_sign,
        }

        # Only include encipher_only and decipher_only if key_agreement is True
        if key_usage.value.key_agreement:
            result["key_usage"]["encipher_only"] = key_usage.value.encipher_only
            result["key_usage"]["decipher_only"] = key_usage.value.decipher_only
    except x509.ExtensionNotFound:
        result["key_usage"] = None

    try:
        ext_key_usage = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        )
        result["extended_key_usage"] = [
            oid._name for oid in ext_key_usage.value]
    except x509.ExtensionNotFound:
        result["extended_key_usage"] = None

    try:
        san = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        result["san"] = {
            "dns_names": san.value.get_values_for_type(
                x509.DNSName), "ip_addresses": [
                str(ip) for ip in san.value.get_values_for_type(
                    x509.IPAddress)], }
    except x509.ExtensionNotFound:
        result["san"] = None

    return result


def json_to_name(name_dict: Dict[str, str]) -> x509.Name:
    """
    Convert a dictionary of name attributes to an X.509 name

    Args:
        name_dict: Dictionary containing name attributes

    Returns:
        X.509 name object
    """
    attrs = []

    if name_dict.get("common_name"):
        attrs.append(
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                name_dict["common_name"]))
    if name_dict.get("country"):
        attrs.append(
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                name_dict["country"]))
    if name_dict.get("state"):
        attrs.append(
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME,
                name_dict["state"]))
    if name_dict.get("locality"):
        attrs.append(
            x509.NameAttribute(
                NameOID.LOCALITY_NAME,
                name_dict["locality"]))
    if name_dict.get("organization"):
        attrs.append(
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                name_dict["organization"]))
    if name_dict.get("organizational_unit"):
        attrs.append(
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                name_dict["organizational_unit"]))
    if name_dict.get("email"):
        attrs.append(
            x509.NameAttribute(
                NameOID.EMAIL_ADDRESS,
                name_dict["email"]))

    return x509.Name(attrs)


def json_to_cert(cert_json: Dict[str, Any],
                 cert_data: bytes) -> x509.Certificate:
    """
    Convert JSON data and certificate bytes back to a certificate object

    Args:
        cert_json: Dictionary containing certificate details
        cert_data: PEM-encoded certificate data

    Returns:
        X.509 certificate object
    """
    return x509.load_pem_x509_certificate(cert_data)


def load_certificate(cert_data: bytes) -> x509.Certificate:
    """Load a certificate from PEM or DER data"""
    logger.debug("Loading certificate from %d bytes", len(cert_data))
    try:
        return x509.load_pem_x509_certificate(cert_data)
    except ValueError:
        logger.debug("PEM load failed, trying DER format")
        return x509.load_der_x509_certificate(cert_data)


def load_private_key(key_data: bytes,
                     password: Optional[bytes] = None) -> Union[rsa.RSAPrivateKey,
                                                                ec.EllipticCurvePrivateKey,
                                                                ed25519.Ed25519PrivateKey,
                                                                ed448.Ed448PrivateKey]:
    """Load a private key from PEM or DER data"""
    logger.debug(
        "Loading private key from %d bytes (password protected: %s)",
        len(key_data),
        "yes" if password else "no",
    )
    try:
        return serialization.load_pem_private_key(key_data, password=password)
    except ValueError:
        logger.debug("PEM load failed, trying DER format")
        return serialization.load_der_private_key(key_data, password=password)


def load_public_key(key_data: bytes,
                    ) -> Union[rsa.RSAPublicKey,
                               ec.EllipticCurvePublicKey,
                               ed25519.Ed25519PublicKey,
                               ed448.Ed448PublicKey]:
    """Load a public key from PEM or DER data"""
    logger.debug("Loading public key from %d bytes", len(key_data))
    try:
        return serialization.load_pem_public_key(key_data)
    except ValueError:
        logger.debug("PEM load failed, trying DER format")
        return serialization.load_der_public_key(key_data)


def certificate_to_pem(cert: x509.Certificate) -> bytes:
    """Convert a certificate to PEM format"""
    logger.debug("Converting certificate to PEM format")
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def certificate_to_der(cert: x509.Certificate) -> bytes:
    """Convert a certificate to DER format"""
    logger.debug("Converting certificate to DER format")
    return cert.public_bytes(encoding=serialization.Encoding.DER)


def private_key_to_pem(
    key: Union[
        rsa.RSAPrivateKey,
        ec.EllipticCurvePrivateKey,
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
    ],
    password: Optional[bytes] = None,
) -> bytes:
    """Convert a private key to PEM format"""
    logger.debug(
        "Converting private key to PEM format (password protected: %s)",
        "yes" if password else "no")
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def private_key_to_der(
    key: Union[
        rsa.RSAPrivateKey,
        ec.EllipticCurvePrivateKey,
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
    ],
    password: Optional[bytes] = None,
) -> bytes:
    """Convert a private key to DER format"""
    logger.debug(
        "Converting private key to DER format (password protected: %s)",
        "yes" if password else "no")
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def public_key_to_pem(key: Union[rsa.RSAPublicKey,
                                 ec.EllipticCurvePublicKey,
                                 ed25519.Ed25519PublicKey,
                                 ed448.Ed448PublicKey],
                      ) -> bytes:
    """Convert a public key to PEM format"""
    logger.debug("Converting public key to PEM format")
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)


def public_key_to_der(key: Union[rsa.RSAPublicKey,
                                 ec.EllipticCurvePublicKey,
                                 ed25519.Ed25519PublicKey,
                                 ed448.Ed448PublicKey],
                      ) -> bytes:
    """Convert a public key to DER format"""
    logger.debug("Converting public key to DER format")
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
