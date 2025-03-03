"""
Command Line Interface for Certificate Authority Operations

This module provides a command line interface for managing a Certificate Authority.
It uses Click to create a user-friendly CLI with commands for:
- Initializing a new CA
- Issuing certificates
- Revoking certificates
- Generating CRLs
- Managing certificate lifecycle
- Listing certificates
- Exporting certificates

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

    List certificates:
    $ ca list --type server

    Export certificate:
    $ ca export 1234 --format pkcs12 --password secret
"""

import asyncio
import json
import logging
import os
from typing import List, Optional

import click
from cryptography import x509
from cryptography.x509 import ReasonFlags
from cryptography.hazmat.primitives import serialization

from .ca import CertificateAuthority
from .constants import SAFE_CURVES
from .models.certificate import CertificateRequest


def async_command(f):
    """Decorator to run Click commands as async functions"""
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    wrapper.__name__ = f.__name__
    return wrapper


@click.group()
@click.option(
    "--ca-dir",
    default="ca",
    help="Directory for CA files",
    show_default=True,
    envvar="CA_DIR",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
    envvar="CA_VERBOSE",
)
@click.pass_context
def cli(ctx: click.Context, ca_dir: str, verbose: bool) -> None:
    """Certificate Authority CLI

    This tool provides commands for managing a Certificate Authority,
    including certificate issuance, revocation, and CRL generation.
    """
    # Configure logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Store CA directory in context
    ctx.ensure_object(dict)
    ctx.obj["ca_dir"] = ca_dir


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
@async_command
async def init(
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
    """Initialize a new Certificate Authority"""
    ca = CertificateAuthority(ctx.obj["ca_dir"])
    await ca.initialize(
        common_name=common_name,
        country=country,
        state=state,
        locality=locality,
        org=org,
        org_unit=org_unit,
        key_type=key_type,
        key_size=key_size,
        curve=curve,
    )
    click.echo(f"CA initialized successfully in {ctx.obj['ca_dir']}")


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
@async_command
async def issue(
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
    """Issue a new certificate"""
    ca = CertificateAuthority(ctx.obj["ca_dir"])

    # Split SAN entries
    dns_names = san_dns.split(",") if san_dns else []
    ip_addresses = san_ip.split(",") if san_ip else []

    request = CertificateRequest(
        common_name=common_name,
        country=country,
        state=state,
        locality=locality,
        organization=org,
        organizational_unit=org_unit,
        email=email,
        valid_days=days,
        san_dns_names=dns_names,
        san_ip_addresses=ip_addresses,
        is_ca=type == "ca",
        path_length=path_length if type == "ca" else None,
        key_type=key_type,
        key_size=key_size,
        curve=curve,
    )

    cert = await ca.issue_certificate(request, cert_type=type)
    click.echo(
        f"Certificate issued successfully with serial number {cert.serial_number}")


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
@async_command
async def revoke(
    ctx: click.Context,
    serial: int,
    reason: Optional[str],
) -> None:
    """Revoke a certificate"""
    ca = CertificateAuthority(ctx.obj["ca_dir"])
    await ca.revoke_certificate(
        serial,
        reason=getattr(ReasonFlags, reason) if reason else None)
    click.echo(f"Certificate {serial} revoked successfully")


@cli.command()
@click.argument("serial", type=int)
@click.pass_context
@async_command
async def renew(ctx: click.Context, serial: int) -> None:
    """Renew a certificate"""
    ca = CertificateAuthority(ctx.obj["ca_dir"])
    cert = await ca.renew_certificate(serial)
    click.echo(
        f"Certificate renewed successfully with new serial number {cert.serial_number}")


@cli.group()
def crl() -> None:
    """Manage Certificate Revocation Lists"""
    pass


@crl.command()
@click.pass_context
@async_command
async def generate(ctx: click.Context) -> None:
    """Generate a new CRL"""
    ca = CertificateAuthority(ctx.obj["ca_dir"])
    crl = await ca.generate_crl()
    with open("crl.pem", "wb") as f:
        f.write(crl.public_bytes(encoding=serialization.Encoding.PEM))
    click.echo("CRL generated successfully and saved to crl.pem")


@cli.command()
@click.option(
    "--type",
    type=click.Choice(["server", "client", "ca"]),
    help="Filter by certificate type",
)
@click.option(
    "--revoked",
    is_flag=True,
    help="List revoked certificates",
)
@click.pass_context
@async_command
async def list(
    ctx: click.Context,
    type: Optional[str],
    revoked: bool,
) -> None:
    """List certificates

    Lists all certificates or filters by type and revocation status.
    Displays certificate details including serial number, subject,
    validity period, and status.
    """
    ca = CertificateAuthority(ctx.obj["ca_dir"])

    if revoked:
        certs = await ca.store.list_revoked()
    else:
        certs = await ca.store.list_certificates(cert_type=type)

    for cert in certs:
        click.echo("Certificate:")
        click.echo(f"  Serial: {cert['serial']}")
        click.echo(f"  Type: {cert['type']}")
        click.echo(f"  Subject: {cert['subject']['common_name']}")
        click.echo(f"  Not valid after: {cert['not_valid_after']}")
        if revoked and "revocation_date" in cert:
            click.echo(f"  Revoked: {cert['revocation_date']}")
            if cert.get("revocation_reason"):
                click.echo(f"  Reason: {cert['revocation_reason']}")
        click.echo("")


@cli.command()
@click.argument("serial", type=int)
@click.option(
    "--format",
    type=click.Choice(["pem", "pkcs12", "jks"]),
    default="pem",
    help="Export format",
    show_default=True,
)
@click.option(
    "--password",
    help="Password for PKCS12/JKS export",
)
@click.option(
    "--out",
    help="Output file (default: <serial>.<format>)",
)
@click.pass_context
@async_command
async def export(
    ctx: click.Context,
    serial: int,
    format: str,
    password: Optional[str],
    out: Optional[str],
) -> None:
    """Export a certificate

    Exports a certificate and its private key in the specified format.
    For PKCS12 and JKS formats, a password is required to protect the
    private key. The certificate chain will be included if available.
    """
    ca = CertificateAuthority(ctx.obj["ca_dir"])
    cert_info = await ca.store.get_certificate(serial)

    if not cert_info:
        click.echo(f"Certificate {serial} not found", err=True)
        return

    # Get the certificate and key paths
    cert_dir = {
        "ca": "sub-ca",
        "server": "server-certs",
        "client": "client-certs"
    }[cert_info["type"]]

    cert_path = f"{ctx.obj['ca_dir']}/{cert_dir}/{serial}.crt"
    key_path = f"{ctx.obj['ca_dir']}/{cert_dir}/{serial}.key"

    # Load certificate and key
    with open(cert_path, "rb") as f:
        cert_data = f.read()

    if format == "pem":
        # For PEM, include both cert and key if available
        data = cert_data
        try:
            with open(key_path, "rb") as f:
                key_data = f.read()
                data = key_data + cert_data
        except FileNotFoundError:
            pass  # Key not available, just use cert
    else:  # pkcs12 or jks
        if not password:
            click.echo(f"Password required for {format.upper()} export", err=True)
            return

        # Load the private key
        try:
            with open(key_path, "rb") as f:
                key_data = f.read()
        except FileNotFoundError:
            click.echo("Private key not found", err=True)
            return

        # Export in requested format
        if format == "pkcs12":
            data = await ca.export_pkcs12(cert_info, password)
        else:  # jks
            data = await ca.export_jks(cert_info, password)

    # Write to output file
    out_file = out or f"{serial}.{format}"
    with open(out_file, "wb") as f:
        f.write(data)

    click.echo(f"Certificate exported successfully to {out_file}")
