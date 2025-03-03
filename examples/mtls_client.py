"""Example of an HTTPS client with mutual TLS authentication"""
import asyncio
import ssl
import tempfile
import aiohttp
from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest

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

        # Issue client certificate
        client_request = CertificateRequest(
            common_name="client1",
            organization="Example Corp",
            country="US",
            email="client1@example.com",
            valid_days=365
        )
        client_cert = await ca.issue_certificate(client_request, cert_type="client")

        # Save client certificate and key
        with open("client.crt", "wb") as f:
            f.write(client_cert.to_pem())
        with open("client.key", "wb") as f:
            f.write(client_cert.private_key_to_pem())

        # Save CA certificate
        with open("ca.crt", "wb") as f:
            f.write(ca.ca_cert.public_bytes(serialization.Encoding.PEM))

        # Create SSL context for the client
        ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile="ca.crt"
        )
        ssl_context.load_cert_chain(
            certfile="client.crt",
            keyfile="client.key"
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