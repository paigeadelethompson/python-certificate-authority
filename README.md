# Python Certificate Authority

A comprehensive Python-based Certificate Authority (CA) for managing X.509 certificates. This library provides a complete solution for creating and managing a certificate authority, including support for certificate issuance, revocation, and various certificate formats.

## Requirements

- Python 3.9 - 3.14
- OpenSSL 3.0 or higher (required by cryptography 42.0.0)

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
git clone https://github.com/paigeadelethompson/python-certificate-authority.git
cd python-certificate-authority
```

2. Install hatch:
```bash
pip install hatch
```

3. Run tests:
```bash
hatch run test
```

4. Code Quality Tools:

Format code:
```bash
hatch run format  # Runs autoflake, autopep8, black, and isort in the correct order
```

Run all linters:
```bash
hatch run lint  # Runs all formatting and linting tools in the correct order
```

The CI pipeline will run all these checks in this order:
1. Code formatting (autoflake, autopep8, black, isort)
2. Linting (flake8, pylint)
3. Type checking (mypy)
4. Tests (pytest)

All checks must pass for a PR to be merged.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Run code quality tools and rebase formatting fixes:
   ```bash
   # First, run formatting
   hatch run format

   # If any files were modified, stage them
   git add .

   # Then rebase and squash formatting changes into your feature commits
   git rebase -i origin/main

   # In the rebase editor, mark formatting-only commits as 'fixup'
   # to merge them into their parent feature commit
   ```
   This keeps the commit history clean by avoiding separate formatting commits.

5. Ensure all checks pass:
   ```bash
   hatch run lint   # Run all linters
   hatch run test   # Run tests
   ```

6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Commit Guidelines

- Keep commits focused on single changes
- Use semantic commit messages (see Versioning section)
- Rebase formatting fixes into their related feature commits
- If you have multiple commits, consider squashing related changes

Example of good commit sequence:
```
feat: add Ed25519 key support
  - Core Ed25519 implementation
  - Tests for Ed25519
  - (Formatting fixes squashed in)

fix: correct key size validation
  - Update validation logic
  - Add test cases
  - (Formatting fixes squashed in)
```

Example of what to avoid:
```
feat: add Ed25519 key support
style: format Ed25519 files
fix: fix linting issues in Ed25519
fix: more formatting
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Versioning

This project uses [python-semantic-release](https://python-semantic-release.readthedocs.io/) for automated version management. Versions are automatically determined from commit messages:

- `fix:` prefix in commit = patch version bump (0.1.0 -> 0.1.1)
- `feat:` prefix in commit = minor version bump (0.1.0 -> 0.2.0)
- `BREAKING CHANGE:` in commit body = major version bump (0.1.0 -> 1.0.0)

Example commit messages:
```
fix: correct certificate renewal date calculation
feat: add support for Ed25519 keys
feat: replace JKS export implementation
BREAKING CHANGE: new API for certificate store
```

Versions are automatically managed when pushing to main branch. The GitHub Actions workflow will:
1. Run all tests
2. Create a new version if needed based on commits
3. Create a GitHub release
4. Publish to PyPI 