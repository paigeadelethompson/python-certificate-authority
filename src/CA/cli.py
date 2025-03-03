"""
Command Line Interface for Certificate Authority Operations

This module provides a command line interface for managing a Certificate Authority.
It uses Click to create a user-friendly CLI with commands for:
- Initializing a new CA
- Issuing certificates
- Revoking certificates
- Generating CRLs
- Managing certificate lifecycle

The CLI is designed to be intuitive and follows common patterns for command
line tools, including:
- Consistent command structure
- Helpful error messages
- Command completion
- Rich help text

Example:
    Initialize a new CA:
    $ ca init --common-name "My Root CA" --country US --org "My Company"

    Issue a server certificate:
    $ ca issue server --common-name example.com --san-dns example.com,*.example.com

    Revoke a certificate:
    $ ca revoke 1234 --reason key_compromise

    Generate a CRL:
    $ ca crl generate
"""

import argparse
import asyncio
import logging
import os
import sys
from typing import List, Optional

import click

from .ca import CertificateAuthority
from .constants import ExtendedKeyUsage, KeyUsage
from .models.certificate import CertificateRequest


def configure_logging(log_level: str) -> None:
    """Configure logging with appropriate levels based on debug flag"""
    # Set up basic logging format
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    # Get the root logger
    root_logger = logging.getLogger()

    # Set the level for all loggers based on debug flag
    if log_level == "DEBUG":
        # In debug mode, allow all levels for all loggers
        root_logger.setLevel(logging.DEBUG)
    else:
        # In non-debug mode, only allow INFO and above for pycertauth loggers
        # and WARNING and above for all other loggers
        root_logger.setLevel(logging.WARNING)

        # Set INFO level specifically for pycertauth loggers
        pycertauth_logger = logging.getLogger("pycertauth")
        pycertauth_logger.setLevel(logging.INFO)


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="Python Certificate Authority CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--dir",
        default="./ca",
        help="Base directory for CA files (default: ./ca)")
    parser.add_argument(
        "--log-level",
        choices=[
            "DEBUG",
            "INFO"],
        default="INFO",
        help="Set the logging level (default: INFO for pycertauth, WARNING for others; DEBUG enables all logging)",
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute")

    # Initialize CA
    init_parser = subparsers.add_parser("init", help="Initialize a new CA")
    init_parser.add_argument(
        "--common-name",
        required=True,
        help="CA common name")
    init_parser.add_argument("--country", default="US", help="Country name")
    init_parser.add_argument(
        "--state",
        default="",
        help="State or province name")
    init_parser.add_argument("--locality", default="", help="Locality name")
    init_parser.add_argument("--org", default="", help="Organization name")
    init_parser.add_argument(
        "--org-unit",
        default="",
        help="Organizational unit name")

    # Issue certificate
    issue_parser = subparsers.add_parser(
        "issue", help="Issue a new certificate")
    issue_parser.add_argument(
        "--type",
        choices=[
            "server",
            "client",
            "sub-ca"],
        default="server",
        help="Certificate type")
    issue_parser.add_argument(
        "--common-name",
        required=True,
        help="Certificate common name")
    issue_parser.add_argument("--country", default="US", help="Country name")
    issue_parser.add_argument(
        "--state",
        default="",
        help="State or province name")
    issue_parser.add_argument("--locality", default="", help="Locality name")
    issue_parser.add_argument("--org", default="", help="Organization name")
    issue_parser.add_argument(
        "--org-unit",
        default="",
        help="Organizational unit name")
    issue_parser.add_argument("--email", default="", help="Email address")
    issue_parser.add_argument("--dns", nargs="*", help="DNS names for SAN")
    issue_parser.add_argument("--ip", nargs="*", help="IP addresses for SAN")
    issue_parser.add_argument(
        "--valid-days",
        type=int,
        default=365,
        help="Validity period in days")
    issue_parser.add_argument(
        "--path-length",
        type=int,
        help="Path length for sub-CA certificates")

    # Revoke certificate
    revoke_parser = subparsers.add_parser(
        "revoke", help="Revoke a certificate")
    revoke_parser.add_argument(
        "serial",
        type=int,
        help="Certificate serial number")

    # List certificates
    list_parser = subparsers.add_parser("list", help="List certificates")
    list_parser.add_argument(
        "--type",
        choices=[
            "server",
            "client",
            "sub-ca"],
        help="Filter by certificate type")
    list_parser.add_argument(
        "--revoked",
        action="store_true",
        help="List revoked certificates")

    # Export certificate
    export_parser = subparsers.add_parser("export", help="Export certificate")
    export_parser.add_argument(
        "serial",
        type=int,
        help="Certificate serial number")
    export_parser.add_argument(
        "--format",
        choices=[
            "pem",
            "pkcs12",
            "jks"],
        default="pem",
        help="Export format")
    export_parser.add_argument("--password",
                               help="Password for PKCS12/JKS export")
    export_parser.add_argument(
        "--out", help="Output file (default: <serial>.<format>)")

    return parser


async def init_ca(args: argparse.Namespace) -> None:
    """Initialize a new CA"""
    logger = logging.getLogger(__name__)
    logger.info("Initializing new Certificate Authority")
    logger.debug("CA directory: %s", args.dir)

    ca = CertificateAuthority(args.dir)
    await ca.initialize(
        common_name=args.common_name,
        country=args.country,
        state=args.state,
        locality=args.locality,
        org=args.org,
        org_unit=args.org_unit,
    )
    logger.info("CA initialized successfully in %s", args.dir)


async def issue_cert(args: argparse.Namespace) -> None:
    """Issue a new certificate"""
    logger = logging.getLogger(__name__)
    logger.info("Issuing new %s certificate", args.type)
    logger.debug("Certificate details - Common Name: %s", args.common_name)

    ca = CertificateAuthority(args.dir)

    request = CertificateRequest(
        common_name=args.common_name,
        country=args.country,
        state=args.state,
        locality=args.locality,
        organization=args.org,
        organizational_unit=args.org_unit,
        email=args.email,
        valid_days=args.valid_days,
        san_dns_names=args.dns or [],
        san_ip_addresses=args.ip or [],
        is_ca=args.type == "sub-ca",
        path_length=args.path_length if args.type == "sub-ca" else None,
    )

    cert = await ca.issue_certificate(request, cert_type=args.type)
    logger.info(
        "Certificate issued successfully with serial number %d",
        cert.serial_number)


async def revoke_cert(args: argparse.Namespace) -> None:
    """Revoke a certificate"""
    logger = logging.getLogger(__name__)
    logger.info("Revoking certificate with serial number %d", args.serial)

    ca = CertificateAuthority(args.dir)
    await ca.revoke_certificate(args.serial)
    logger.info("Certificate %d revoked successfully", args.serial)


async def list_certs(args: argparse.Namespace) -> None:
    """List certificates"""
    logger = logging.getLogger(__name__)
    ca = CertificateAuthority(args.dir)

    if args.revoked:
        logger.info("Listing revoked certificates")
        certs = await ca.store.list_revoked()
    else:
        cert_type = args.type or "all"
        logger.info("Listing %s certificates", cert_type)
        certs = await ca.store.list_certificates(cert_type=args.type)

    for cert in certs:
        logger.info("Certificate:")
        logger.info("  Serial: %s", cert["serial"])
        logger.info("  Type: %s", cert["type"])
        logger.info("  Subject: %s", cert["subject"]["common_name"])
        logger.info("  Not valid after: %s", cert["not_valid_after"])


async def export_cert(args: argparse.Namespace) -> None:
    """Export a certificate"""
    logger = logging.getLogger(__name__)
    logger.info(
        "Exporting certificate %d in %s format",
        args.serial,
        args.format)

    ca = CertificateAuthority(args.dir)
    cert_info = await ca.store.get_certificate(args.serial)

    if not cert_info:
        logger.error("Certificate %d not found", args.serial)
        return

    cert_dir = {"sub-ca": "sub-ca", "server": "server-certs",
                "client": "client-certs"}[cert_info["type"]]

    cert_path = os.path.join(args.dir, cert_dir, f"{args.serial}.crt")
    key_path = os.path.join(args.dir, cert_dir, f"{args.serial}.key")

    if not os.path.exists(cert_path):
        logger.error("Certificate file not found: %s", cert_path)
        return

    out_file = args.out or f"{args.serial}.{args.format}"
    logger.debug("Output file: %s", out_file)

    if args.format == "pem":
        # Copy certificate and key to output
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        if os.path.exists(key_path):
            logger.debug("Including private key in export")
            with open(key_path, "rb") as f:
                key_data = f.read()
            data = key_data + cert_data
        else:
            data = cert_data
    else:
        # Load certificate and key
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        with open(key_path, "rb") as f:
            key_data = f.read()

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate(cert_data)
        key = serialization.load_pem_private_key(key_data, password=None)

        if args.format == "pkcs12":
            if not args.password:
                logger.error("Password required for PKCS12 export")
                return
            logger.debug("Exporting as PKCS12")
            data = await ca.export_pkcs12(cert, args.password)
        else:  # jks
            if not args.password:
                logger.error("Password required for JKS export")
                return
            logger.debug("Exporting as JKS")
            data = await ca.export_jks(cert, args.password)

    with open(out_file, "wb") as f:
        f.write(data)
    logger.info("Certificate exported successfully to %s", out_file)


async def main() -> None:
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Configure logging with appropriate levels
    configure_logging(args.log_level)

    logger = logging.getLogger(__name__)

    if not args.command:
        parser.print_help()
        return

    # Create base directory if it doesn't exist
    os.makedirs(args.dir, exist_ok=True)
    logger.debug("Ensuring base directory exists: %s", args.dir)

    commands = {
        "init": init_ca,
        "issue": issue_cert,
        "revoke": revoke_cert,
        "list": list_certs,
        "export": export_cert,
    }

    try:
        logger.debug("Executing command: %s", args.command)
        await commands[args.command](args)
    except Exception as e:
        logger.error("Command failed: %s", str(e), exc_info=True)
        sys.exit(1)


def async_command(f):
    """Decorator to run async commands"""

    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@click.group()
@click.option(
    "--ca-dir",
    default="ca",
    help="Directory for CA files",
    show_default=True,
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.pass_context
def cli(ctx: click.Context, ca_dir: str, verbose: bool) -> None:
    """
    Certificate Authority Management Tool

    This tool provides commands for managing a Certificate Authority,
    including initializing the CA, issuing certificates, and handling
    certificate lifecycle operations.

    The CA files are stored in the specified directory (default: 'ca').
    Use --verbose for detailed logging output.
    """
    # ... existing code ...


@cli.command()
@click.option(
    "--common-name",
    required=True,
    help="CA certificate common name",
)
@click.option(
    "--country",
    help="Two-letter country code",
)
@click.option(
    "--state",
    help="State or province name",
)
@click.option(
    "--locality",
    help="Locality name",
)
@click.option(
    "--org",
    help="Organization name",
)
@click.option(
    "--org-unit",
    help="Organizational unit name",
)
@click.option(
    "--key-type",
    type=click.Choice(["rsa", "ec", "ed25519", "ed448"]),
    default="rsa",
    help="Key type to use",
    show_default=True,
)
@click.option(
    "--key-size",
    type=int,
    default=2048,
    help="Key size (for RSA)",
    show_default=True,
)
@click.option(
    "--curve",
    help="Curve name (for EC)",
)
@click.pass_context
def init(
    ctx: click.Context,
    common_name: str,
    country: Optional[str],
    state: Optional[str],
    locality: Optional[str],
    org: Optional[str],
    org_unit: Optional[str],
    key_type: str,
    key_size: int,
    curve: Optional[str],
) -> None:
    """
    Initialize a new Certificate Authority.

    Creates a new CA with the specified parameters. This includes generating
    a new key pair and self-signed certificate for the CA.

    The CA certificate will be configured with appropriate extensions for
    a root CA, including:
    - Basic Constraints (CA: TRUE)
    - Key Usage (Certificate Sign, CRL Sign)
    - Subject Key Identifier
    - Authority Key Identifier

    Example:
        $ ca init --common-name "My Root CA" --country US --org "My Company"
        $ ca init --common-name "My EC CA" --key-type ec --curve secp384r1
    """
    # ... existing code ...


@cli.command()
@click.argument(
    "type",
    type=click.Choice(["client", "server", "ca"]),
)
@click.option(
    "--common-name",
    required=True,
    help="Certificate common name",
)
@click.option(
    "--country",
    help="Two-letter country code",
)
@click.option(
    "--state",
    help="State or province name",
)
@click.option(
    "--locality",
    help="Locality name",
)
@click.option(
    "--org",
    help="Organization name",
)
@click.option(
    "--org-unit",
    help="Organizational unit name",
)
@click.option(
    "--email",
    help="Email address",
)
@click.option(
    "--key-type",
    type=click.Choice(["rsa", "ec", "ed25519", "ed448"]),
    default="rsa",
    help="Key type to use",
    show_default=True,
)
@click.option(
    "--key-size",
    type=int,
    default=2048,
    help="Key size (for RSA)",
    show_default=True,
)
@click.option(
    "--curve",
    help="Curve name (for EC)",
)
@click.option(
    "--days",
    type=int,
    default=365,
    help="Validity period in days",
    show_default=True,
)
@click.option(
    "--san-dns",
    help="Subject Alternative Name DNS entries (comma-separated)",
)
@click.option(
    "--san-ip",
    help="Subject Alternative Name IP addresses (comma-separated)",
)
@click.option(
    "--path-length",
    type=int,
    help="CA path length constraint (CA certificates only)",
)
@click.pass_context
def issue(
    ctx: click.Context,
    type: str,
    common_name: str,
    country: Optional[str],
    state: Optional[str],
    locality: Optional[str],
    org: Optional[str],
    org_unit: Optional[str],
    email: Optional[str],
    key_type: str,
    key_size: int,
    curve: Optional[str],
    days: int,
    san_dns: Optional[str],
    san_ip: Optional[str],
    path_length: Optional[int],
) -> None:
    """
    Issue a new certificate.

    Creates a new certificate of the specified type (client, server, or CA)
    signed by the CA. The certificate will be configured with appropriate
    extensions based on its type.

    Server certificates include:
    - Server Authentication EKU
    - DNS/IP SANs
    - Digital Signature and Key Encipherment KU

    Client certificates include:
    - Client Authentication EKU
    - Digital Signature, Key Encipherment, and Non-Repudiation KU

    CA certificates include:
    - Basic Constraints (CA: TRUE)
    - Certificate Sign and CRL Sign KU
    - Optional path length constraint

    Example:
        $ ca issue server --common-name example.com --san-dns example.com,*.example.com
        $ ca issue client --common-name "John Doe" --email john@example.com
        $ ca issue ca --common-name "Sub CA" --path-length 0
    """
    # ... existing code ...


@cli.command()
@click.argument("serial", type=int)
@click.option(
    "--reason",
    type=click.Choice([
        "unspecified",
        "key_compromise",
        "ca_compromise",
        "affiliation_changed",
        "superseded",
        "cessation_of_operation",
        "certificate_hold",
        "remove_from_crl",
        "privilege_withdrawn",
        "aa_compromise",
    ]),
    help="Revocation reason",
)
@click.pass_context
def revoke(
    ctx: click.Context,
    serial: int,
    reason: Optional[str],
) -> None:
    """
    Revoke a certificate.

    Marks a certificate as revoked in the CA database. The certificate is
    identified by its serial number. An optional reason for revocation
    can be specified.

    The revocation will be included in future CRLs generated by the CA.

    Example:
        $ ca revoke 1234 --reason key_compromise
        $ ca revoke 5678 --reason cessation_of_operation
    """
    # ... existing code ...


@cli.command()
@click.argument("serial", type=int)
@click.pass_context
def renew(ctx: click.Context, serial: int) -> None:
    """
    Renew a certificate.

    Creates a new certificate with the same parameters as an existing
    certificate but with updated validity dates. The new certificate
    will have a new key pair and serial number.

    The original certificate remains valid unless explicitly revoked.

    Example:
        $ ca renew 1234
    """
    # ... existing code ...


@cli.group()
def crl() -> None:
    """
    Manage Certificate Revocation Lists (CRLs).

    Commands for generating and managing CRLs, which list all
    certificates that have been revoked by the CA.
    """
    pass


@crl.command()
@click.pass_context
def generate(ctx: click.Context) -> None:
    """
    Generate a new CRL.

    Creates a new Certificate Revocation List containing all certificates
    that have been revoked by the CA. The CRL is signed by the CA and
    includes the revocation date and reason for each revoked certificate.

    Example:
        $ ca crl generate
    """
    # ... existing code ...


def main() -> None:
    """
    Main entry point for the CLI application.

    Sets up logging and runs the Click command group in an asyncio event loop.
    Handles keyboard interrupts gracefully.
    """
    # ... existing code ...


if __name__ == "__main__":
    main()
