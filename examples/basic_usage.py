"""Basic example of using the Certificate Authority"""
import asyncio
import os
import tempfile
from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest
from cryptography.hazmat.primitives import serialization

async def main():
    # Example 1: Using default CA directory (./ca)
    print("Example 1: Using default CA directory")
    ca = CertificateAuthority("./ca")
    await ca.initialize(
        common_name="Example CA",
        country="US",
        state="California",
        locality="San Francisco",
        org="Example Corp",
        org_unit="IT"
    )
    print("CA initialized successfully in ./ca")

    # Issue and export certificates
    await issue_and_export_certs(ca, "permanent")
    print("Certificates exported to current directory")

    # Example 2: Using a temporary directory (for testing/examples)
    print("\nExample 2: Using temporary directory")
    with tempfile.TemporaryDirectory() as temp_dir:
        ca = CertificateAuthority(temp_dir)
        await ca.initialize(
            common_name="Example Temp CA",
            country="US",
            state="California",
            locality="San Francisco",
            org="Example Corp",
            org_unit="IT"
        )
        print(f"CA initialized successfully in {temp_dir}")

        # Issue and export certificates
        await issue_and_export_certs(ca, "temp")
        print("Certificates exported to current directory")

async def issue_and_export_certs(ca, prefix):
    """Issue and export certificates using the given CA"""
    # Issue a server certificate
    server_request = CertificateRequest(
        common_name="example.com",
        organization="Example Corp",
        country="US",
        san_dns_names=["example.com", "*.example.com"],
        valid_days=365
    )
    server_cert = await ca.issue_certificate(server_request, cert_type="server")
    print(f"Server certificate issued with serial {server_cert.serial_number}")

    # Issue a client certificate
    client_request = CertificateRequest(
        common_name="client1",
        organization="Example Corp",
        country="US",
        email="client1@example.com",
        valid_days=365
    )
    client_cert = await ca.issue_certificate(client_request, cert_type="client")
    print(f"Client certificate issued with serial {client_cert.serial_number}")

    # Export certificates
    with open(f"{prefix}_server.crt", "wb") as f:
        f.write(server_cert.to_pem())
    with open(f"{prefix}_server.key", "wb") as f:
        f.write(server_cert.private_key_to_pem())

    with open(f"{prefix}_client.crt", "wb") as f:
        f.write(client_cert.to_pem())
    with open(f"{prefix}_client.key", "wb") as f:
        f.write(client_cert.private_key_to_pem())

    # Export as PKCS12
    server_p12 = await ca.export_pkcs12(server_cert, "changeit")
    with open(f"{prefix}_server.p12", "wb") as f:
        f.write(server_p12)

    client_p12 = await ca.export_pkcs12(client_cert, "changeit")
    with open(f"{prefix}_client.p12", "wb") as f:
        f.write(client_p12)

    # Revoke the client certificate
    await ca.revoke_certificate(client_cert.serial_number)
    print(f"Client certificate {client_cert.serial_number} revoked")

    # Generate CRL
    crl = await ca.generate_crl()
    with open(f"{prefix}_ca.crl", "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    print("CRL generated successfully")

if __name__ == "__main__":
    asyncio.run(main()) 