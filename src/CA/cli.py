"""
Command-line interface for PyCertAuth
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
def main():
    """Python Certificate Authority CLI"""


@main.command()
@click.option("--base-dir", required=True, help="Base directory for CA files")
@click.option("--common-name", required=True, help="CA common name")
@click.option("--country", required=True, help="Country code (e.g., US)")
@click.option("--state", help="State or province")
@click.option("--locality", help="City or locality")
@click.option("--org", help="Organization name")
@click.option("--org-unit", help="Organizational unit")
@async_command
async def init(
    base_dir: str,
    common_name: str,
    country: str,
    state: Optional[str] = None,
    locality: Optional[str] = None,
    org: Optional[str] = None,
    org_unit: Optional[str] = None,
):
    """Initialize a new Certificate Authority"""
    ca = CertificateAuthority(base_dir)
    await ca.initialize(
        common_name=common_name,
        country=country,
        state=state,
        locality=locality,
        org=org,
        org_unit=org_unit,
    )
    click.echo(f"CA initialized in {base_dir}")


@main.group()
def issue():
    """Issue certificates"""


@issue.command()
@click.option("--base-dir", required=True, help="Base directory for CA files")
@click.option("--common-name", required=True, help="Certificate common name")
@click.option("--country", help="Country code (e.g., US)")
@click.option("--state", help="State or province")
@click.option("--locality", help="City or locality")
@click.option("--org", help="Organization name")
@click.option("--org-unit", help="Organizational unit")
@click.option("--san-dns", multiple=True, help="DNS Subject Alternative Name")
@click.option("--san-ip", multiple=True, help="IP Subject Alternative Name")
@click.option("--valid-days", type=int, default=365,
              help="Validity period in days")
@click.option("--output", help="Output file path (without extension)")
@async_command
async def server(
    base_dir: str,
    common_name: str,
    country: Optional[str] = None,
    state: Optional[str] = None,
    locality: Optional[str] = None,
    org: Optional[str] = None,
    org_unit: Optional[str] = None,
    san_dns: Optional[List[str]] = None,
    san_ip: Optional[List[str]] = None,
    valid_days: int = 365,
    output: Optional[str] = None,
):
    """Issue a server certificate"""
    ca = CertificateAuthority(base_dir)
    request = CertificateRequest(
        common_name=common_name,
        country=country,
        state=state,
        locality=locality,
        organization=org,
        organizational_unit=org_unit,
        san_dns_names=list(san_dns) if san_dns else None,
        san_ip_addresses=list(san_ip) if san_ip else None,
        valid_days=valid_days,
        key_usage=KeyUsage.SERVER,
        extended_key_usage=[ExtendedKeyUsage.SERVER_AUTH],
    )
    cert = await ca.issue_certificate(request, cert_type="server")

    if output:
        # Save certificate and private key
        with open(f"{output}.crt", "wb") as f:
            f.write(cert.to_pem())
        with open(f"{output}.key", "wb") as f:
            f.write(cert.private_key_to_pem())
        # Export as PKCS12
        pkcs12_data = await ca.export_pkcs12(cert, "changeit")
        with open(f"{output}.p12", "wb") as f:
            f.write(pkcs12_data)
        click.echo(f"Certificate saved to {output}.crt")
        click.echo(f"Private key saved to {output}.key")
        click.echo(f"PKCS12 bundle saved to {output}.p12 (password: changeit)")
    else:
        click.echo(cert.to_pem().decode())


@issue.command()
@click.option("--base-dir", required=True, help="Base directory for CA files")
@click.option("--common-name", required=True, help="Certificate common name")
@click.option("--country", help="Country code (e.g., US)")
@click.option("--state", help="State or province")
@click.option("--locality", help="City or locality")
@click.option("--org", help="Organization name")
@click.option("--org-unit", help="Organizational unit")
@click.option("--email", help="Email address")
@click.option("--valid-days", type=int, default=365,
              help="Validity period in days")
@click.option("--output", help="Output file path (without extension)")
@async_command
async def client(
    base_dir: str,
    common_name: str,
    country: Optional[str] = None,
    state: Optional[str] = None,
    locality: Optional[str] = None,
    org: Optional[str] = None,
    org_unit: Optional[str] = None,
    email: Optional[str] = None,
    valid_days: int = 365,
    output: Optional[str] = None,
):
    """Issue a client certificate"""
    ca = CertificateAuthority(base_dir)
    request = CertificateRequest(
        common_name=common_name,
        country=country,
        state=state,
        locality=locality,
        organization=org,
        organizational_unit=org_unit,
        email=email,
        valid_days=valid_days,
        key_usage=KeyUsage.CLIENT,
        extended_key_usage=[ExtendedKeyUsage.CLIENT_AUTH],
    )
    cert = await ca.issue_certificate(request, cert_type="client")

    if output:
        # Save certificate and private key
        with open(f"{output}.crt", "wb") as f:
            f.write(cert.to_pem())
        with open(f"{output}.key", "wb") as f:
            f.write(cert.private_key_to_pem())
        # Export as PKCS12
        pkcs12_data = await ca.export_pkcs12(cert, "changeit")
        with open(f"{output}.p12", "wb") as f:
            f.write(pkcs12_data)
        click.echo(f"Certificate saved to {output}.crt")
        click.echo(f"Private key saved to {output}.key")
        click.echo(f"PKCS12 bundle saved to {output}.p12 (password: changeit)")
    else:
        click.echo(cert.to_pem().decode())


@main.command()
@click.option("--base-dir", required=True, help="Base directory for CA files")
@click.option("--serial", required=True, type=int,
              help="Certificate serial number")
@async_command
async def revoke(base_dir: str, serial: int):
    """Revoke a certificate"""
    ca = CertificateAuthority(base_dir)
    await ca.revoke_certificate(serial)
    click.echo(f"Certificate with serial {serial} revoked")


@main.group()
def crl():
    """Manage Certificate Revocation Lists"""


@crl.command()
@click.option("--base-dir", required=True, help="Base directory for CA files")
@click.option("--output", help="Output file path")
@async_command
async def generate(base_dir: str, output: Optional[str] = None):
    """Generate a Certificate Revocation List"""
    ca = CertificateAuthority(base_dir)
    crl_data = await ca.generate_crl()
    if output:
        with open(output, "wb") as f:
            f.write(crl_data.public_bytes(serialization.Encoding.PEM))
        click.echo(f"CRL saved to {output}")
    else:
        click.echo(crl_data.public_bytes(serialization.Encoding.PEM).decode())


if __name__ == "__main__":
    main()
