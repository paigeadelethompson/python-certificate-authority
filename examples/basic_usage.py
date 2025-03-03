"""Basic example of using the Certificate Authority"""
import asyncio
import tempfile
from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest
from cryptography.hazmat.primitives import serialization

async def main():
    # Create a temporary directory for the CA
    with tempfile.TemporaryDirectory() as base_dir:
        # Initialize the CA
        ca = CertificateAuthority(base_dir)
        await ca.initialize(
            common_name="Example CA",
            country="US",
            state="California",
            locality="San Francisco",
            org="Example Corp",
            org_unit="IT"
        )
        print("CA initialized successfully")

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
        with open("server.crt", "wb") as f:
            f.write(server_cert.to_pem())
        with open("server.key", "wb") as f:
            f.write(server_cert.private_key_to_pem())

        with open("client.crt", "wb") as f:
            f.write(client_cert.to_pem())
        with open("client.key", "wb") as f:
            f.write(client_cert.private_key_to_pem())

        # Export as PKCS12
        server_p12 = await ca.export_pkcs12(server_cert, "changeit")
        with open("server.p12", "wb") as f:
            f.write(server_p12)

        client_p12 = await ca.export_pkcs12(client_cert, "changeit")
        with open("client.p12", "wb") as f:
            f.write(client_p12)

        print("Certificates exported successfully")

        # Revoke the client certificate
        await ca.revoke_certificate(client_cert.serial_number)
        print(f"Client certificate {client_cert.serial_number} revoked")

        # Generate CRL
        crl = await ca.generate_crl()
        with open("ca.crl", "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        print("CRL generated successfully")

if __name__ == "__main__":
    asyncio.run(main()) 