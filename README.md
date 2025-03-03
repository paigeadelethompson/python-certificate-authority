# certificate-authority

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
pip install certificate-authority
```

For development:

```bash
pip install certificate-authority[dev]
```

## Quick Start

### Using as a Library

```python
import asyncio
from CA import CertificateAuthority
from CA.models.certificate import CertificateRequest

async def main():
    # Initialize CA
    ca = CertificateAuthority("./ca")  # Uses default directory in current working directory
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

Basic usage:
```bash
python -m CA [OPTIONS] COMMAND [ARGS]...
```

Global options:
- `--ca-dir`: Directory for CA files (default: "./ca" - relative to current directory)
- `--verbose, -v`: Enable verbose output

Available commands:

#### Initialize CA
```bash
python -m CA init [OPTIONS]

Options:
  --common-name TEXT          CA certificate common name [required]
  --country TEXT             Two-letter country code
  --state TEXT              State or province name
  --locality TEXT           Locality name
  --org TEXT                Organization name
  --org-unit TEXT           Organizational unit name
  --key-type [rsa|ec|ed25519|ed448]  Key type to use [default: rsa]
  --key-size INTEGER        Key size for RSA [default: 2048]
  --curve TEXT              Curve name for EC keys
```

#### Issue Certificate
```bash
python -m CA issue [client|server|ca] [OPTIONS]

Options:
  --common-name TEXT          Certificate common name [required]
  --country TEXT             Two-letter country code
  --state TEXT              State or province name
  --locality TEXT           Locality name
  --org TEXT                Organization name
  --org-unit TEXT           Organizational unit name
  --email TEXT              Email address
  --key-type [rsa|ec|ed25519|ed448]  Key type to use [default: rsa]
  --key-size INTEGER        Key size for RSA [default: 2048]
  --curve TEXT              Curve name for EC keys
  --days INTEGER            Validity period in days [default: 365]
  --san-dns TEXT            Subject Alternative Name DNS entries (comma-separated)
  --san-ip TEXT             Subject Alternative Name IP addresses (comma-separated)
  --path-length INTEGER     CA path length constraint (CA certificates only)
```

#### Revoke Certificate
```bash
python -m CA revoke SERIAL [OPTIONS]

Options:
  --reason [unspecified|key_compromise|ca_compromise|affiliation_changed|
           superseded|cessation_of_operation|certificate_hold|
           remove_from_crl|privilege_withdrawn|aa_compromise]
```

#### Renew Certificate
```bash
python -m CA renew SERIAL
```

#### List Certificates
```bash
python -m CA list [OPTIONS]

Options:
  --type [server|client|ca]  Filter by certificate type
  --revoked                 List only revoked certificates
```

#### Export Certificate
```bash
python -m CA export SERIAL [OPTIONS]

Options:
  --format [pem|pkcs12|jks]  Export format [default: pem]
  --password TEXT           Password for PKCS12/JKS export
  --out TEXT               Output file (default: <serial>.<format>)
```

#### CRL Management
```bash
python -m CA crl generate    Generate a new CRL
```

Examples:
```bash
# Create a new CA in the default directory (./ca)
python -m CA init --common-name "My Root CA" --country US --state California --org "My Company"

# Create a CA in a custom directory
python -m CA --ca-dir /path/to/custom/ca init --common-name "My Root CA" --country US --state California --org "My Company"

# Issue a server certificate (uses ./ca by default)
python -m CA issue server --common-name example.com --san-dns "example.com,*.example.com" --san-ip "10.0.0.1"

# Use a specific CA directory for all operations
export CA_DIR=/path/to/custom/ca  # Optional: set default CA directory in environment
python -m CA --ca-dir "${CA_DIR:-./ca}" issue client --common-name "client1" --org "My Company" --key-type ed25519

# Issue an intermediate CA certificate
python -m CA issue ca --common-name "Intermediate CA" --path-length 0

# Revoke a certificate with reason
python -m CA revoke 1234 --reason key_compromise

# List all server certificates
python -m CA list --type server

# List revoked certificates
python -m CA list --revoked

# Export certificate in different formats
python -m CA export 1234 --format pem --out cert.pem
python -m CA export 1234 --format pkcs12 --password secret --out cert.p12
python -m CA export 1234 --format jks --password secret --out cert.jks

# Generate CRL
python -m CA crl generate
```

## Development

1. Clone the repository:
```bash
git clone https://github.com/paigeadelethompson/certificate-authority.git
cd certificate-authority
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

## Releases and Publishing

This project uses automated releases through GitHub Actions and PyPI's Trusted Publisher system. The process is:

1. Commits to main branch should follow semantic versioning format:
   - `fix:` prefix for bug fixes (0.1.0 -> 0.1.1)
   - `feat:` prefix for new features (0.1.0 -> 0.2.0)
   - `BREAKING CHANGE:` in commit body for breaking changes (0.1.0 -> 1.0.0)

2. To create a new release:
   ```bash
   # Create a new version tag
   git tag v0.1.0

   # Push the tag to trigger release
   git push origin v0.1.0
   ```

3. The release workflow will automatically:
   - Build the package
   - Create a GitHub release
   - Publish to PyPI using Trusted Publisher

Note: Only maintainers with proper access can publish releases. The release process requires:
- Write access to the GitHub repository
- The repository to be properly configured with PyPI's Trusted Publisher system

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