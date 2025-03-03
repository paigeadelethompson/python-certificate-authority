"""Example of an HTTPS client with mutual TLS authentication"""
import asyncio
import os
import ssl
import aiohttp
from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest
from cryptography.hazmat.primitives import serialization

async def main():
    # Initialize the CA in the default directory (./ca)
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

    # Issue client certificate
    client_request = CertificateRequest(
        common_name="client1",
        organization="Example Corp",
        country="US",
        email="client1@example.com",
        valid_days=365
    )
    client_cert = await ca.issue_certificate(client_request, cert_type="client")
    print(f"Client certificate issued with serial {client_cert.serial_number}")

    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)

    # Save client certificate and key
    with open("certs/client.crt", "wb") as f:
        f.write(client_cert.to_pem())
    with open("certs/client.key", "wb") as f:
        f.write(client_cert.private_key_to_pem())

    # Save CA certificate if not already saved by server
    if not os.path.exists("certs/ca.crt"):
        with open("certs/ca.crt", "wb") as f:
            f.write(ca.ca_cert.public_bytes(serialization.Encoding.PEM))

    print("Certificates exported to ./certs directory")

    # Create SSL context for the client
    ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile="certs/ca.crt"
    )
    ssl_context.load_cert_chain(
        certfile="certs/client.crt",
        keyfile="certs/client.key"
    )
    ssl_context.check_hostname = False

    # Make request to server
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(
                'https://localhost:8443',
                ssl=ssl_context
            ) as response:
                print(f"Status: {response.status}")
                print(f"Response: {await response.text()}")
        except aiohttp.ClientError as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main()) 