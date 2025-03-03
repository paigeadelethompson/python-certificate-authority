"""
Python Certificate Authority (PyCertAuth)

A comprehensive Python library for creating and managing a Certificate Authority (CA),
issuing certificates, and handling certificate lifecycle management.

This library provides functionality for:
- Creating and managing a Certificate Authority (CA)
- Issuing server, client, and sub-CA certificates
- Supporting Subject Alternative Names (DNS, IP, Email)
- Certificate revocation and CRL generation
- PKCS12 and JKS export support
- Customizable key usage and extended key usage
- Path length constraints for CA certificates
- Certificate renewal
- Comprehensive certificate store with persistence

Example:
    >>> from pycertauth import CertificateAuthority
    >>> from pycertauth.models.certificate import CertificateRequest
    >>>
    >>> # Create and initialize a CA
    >>> ca = CertificateAuthority("ca_files")
    >>> await ca.initialize(
    ...     common_name="My Root CA",
    ...     country="US",
    ...     organization="My Company"
    ... )
    >>>
    >>> # Issue a server certificate
    >>> request = CertificateRequest(
    ...     common_name="server.example.com",
    ...     country="US",
    ...     organization="My Company",
    ...     san_dns_names=["server.example.com", "*.server.example.com"]
    ... )
    >>>
    >>> cert = await ca.issue_certificate(request, cert_type="server")
"""

from .ca import CertificateAuthority
from .constants import ExtendedKeyUsage
from .models.certificate import Certificate, CertificateRequest
from .models.store import CertificateStore

__version__ = "0.1.0"
__all__ = [
    "CertificateAuthority",
    "Certificate",
    "CertificateRequest",
    "CertificateStore",
    "ExtendedKeyUsage",
]
