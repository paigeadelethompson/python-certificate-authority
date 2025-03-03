# Python Certificate Authority

A comprehensive Python-based Certificate Authority (CA) for managing X.509 certificates. This library provides a complete solution for creating and managing a certificate authority, including support for certificate issuance, revocation, and various certificate formats.

## Features

- Create and manage a Certificate Authority (CA)
- Issue server and client certificates
- Support for certificate revocation (CRL)
- Multiple key types support (RSA, ECDSA, Ed25519, Ed448)
- Export certificates in various formats (PEM, PKCS12, JKS)
- Async/await support for all operations
- Command-line interface (CLI)
- Comprehensive test suite
- Type hints throughout the codebase

## Installation

```bash
pip install python-certificate-authority
```

For development:

```bash
pip install python-certificate-authority[dev]
```

## Quick Start

### Using as a Library

```python
import asyncio
from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest

async def main():
    # Initialize CA
    ca = CertificateAuthority("/path/to/ca/dir")
    await ca.initialize(
        common_name="My Root CA",
        country="US",
        state="California",
        locality="San Francisco",
        org="My Company",
        org_unit="IT"
    )

    # Issue a server certificate
    request = CertificateRequest(
        common_name="example.com",
        organization="My Company",
        country="US",
        san_dns_names=["example.com", "*.example.com"],
        valid_days=365
    )
    cert = await ca.issue_certificate(request, cert_type="server")

    # Export as PKCS12
    pkcs12_data = await ca.export_pkcs12(cert, "password123")
    with open("server.p12", "wb") as f:
        f.write(pkcs12_data)

asyncio.run(main())
```

### Using the CLI

```bash
# Initialize a new CA
ca init --common-name "My Root CA" --country US --state California --org "My Company"

# Issue a server certificate
ca issue server --common-name example.com --san-dns example.com --san-dns "*.example.com"

# Issue a client certificate
ca issue client --common-name "client1" --org "My Company"

# Revoke a certificate
ca revoke --serial 1234

# Generate CRL
ca crl generate
```

## Development

1. Clone the repository:
```bash
git clone https://github.com/yourusername/python-certificate-authority.git
cd python-certificate-authority
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
```

3. Install development dependencies:
```bash
pip install -e ".[dev,test]"
```

4. Run tests:
```bash
pytest tests/ -v
```

5. Run linters:
```bash
black .
flake8 .
pylint src/CA tests
isort .
mypy src/CA
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 