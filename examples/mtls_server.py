"""Example of an HTTPS server with mutual TLS authentication"""
import asyncio
import os
import ssl
from aiohttp import web
from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest
from cryptography.hazmat.primitives import serialization

async def handle_request(request):
    """Handle incoming requests"""
    # Get client certificate info
    transport = request.transport
    ssl_object = transport.get_extra_info('ssl_object')
    client_cert = ssl_object.getpeercert()
    
    return web.Response(text=f"Hello {client_cert['subject'][0][0][1]}!")

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

    # Issue server certificate
    server_request = CertificateRequest(
        common_name="localhost",
        organization="Example Corp",
        country="US",
        san_dns_names=["localhost"],
        valid_days=365
    )
    server_cert = await ca.issue_certificate(server_request, cert_type="server")
    print(f"Server certificate issued with serial {server_cert.serial_number}")

    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)

    # Save server certificate and key
    with open("certs/server.crt", "wb") as f:
        f.write(server_cert.to_pem())
    with open("certs/server.key", "wb") as f:
        f.write(server_cert.private_key_to_pem())

    # Save CA certificate
    with open("certs/ca.crt", "wb") as f:
        f.write(ca.ca_cert.public_bytes(serialization.Encoding.PEM))

    print("Certificates exported to ./certs directory")

    # Create SSL context for the server
    ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH,
        cafile="certs/ca.crt"
    )
    ssl_context.load_cert_chain(
        certfile="certs/server.crt",
        keyfile="certs/server.key"
    )
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.check_hostname = False

    # Create web application
    app = web.Application()
    app.router.add_get("/", handle_request)

    # Start server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(
        runner,
        'localhost',
        8443,
        ssl_context=ssl_context
    )
    
    print("Starting HTTPS server on https://localhost:8443")
    print("Use mtls_client.py to connect")
    
    await site.start()
    
    try:
        # Keep the server running
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main()) 