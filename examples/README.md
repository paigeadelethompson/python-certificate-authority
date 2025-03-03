# PyCertAuth Examples

This directory contains example scripts demonstrating various features of PyCertAuth.

## Running the Examples

1. Make sure you have PyCertAuth installed:
```bash
pip install pycertauth
```

2. Install additional dependencies for web server examples:
```bash
pip install aiohttp
```

3. Run any example using Python 3.8 or later:
```bash
python 01_basic_ca.py
```

## Available Examples

### 1. Basic CA (01_basic_ca.py)
Shows how to:
- Create and initialize a Certificate Authority
- Issue a server certificate with Subject Alternative Names
- Export certificates in PEM and PKCS12 formats

### 2. Certificate Chain (02_certificate_chain.py)
Demonstrates:
- Creating a complete PKI hierarchy
- Root CA → Intermediate CA → Server Certificate
- Certificate chain creation and export
- Path length constraints

### 3. Client Authentication (03_client_auth.py)
Examples of:
- Client authentication certificates
- Email signing certificates (S/MIME)
- Document signing certificates
- Different key usage and extended key usage configurations

### 4. Certificate Store (04_certificate_store.py)
Shows how to:
- Save and retrieve certificates
- List all certificates
- Search certificates by validity
- Handle certificate revocation
- Generate Certificate Revocation Lists (CRL)

### 5. Java KeyStore (05_jks_keystore.py)
Demonstrates:
- Exporting certificates to JKS format
- Creating keystores for Java applications
- Multiple certificates in one keystore
- Creating truststores
- Usage with Tomcat/Spring Boot

### 6. Custom Extensions (06_custom_extensions.py)
Shows how to:
- Create custom OIDs
- Add custom X.509 extensions
- Role-based access control with certificates
- Multiple extensions in one certificate
- Department and employee information in certificates

### 7. Web Server (07_web_server.py)
Demonstrates:
- Setting up an HTTPS server with aiohttp
- Client certificate authentication
- Certificate validation
- Public and secure endpoints
- Testing with curl

### 8. OCSP Responder (08_ocsp_responder.py)
Shows how to:
- Implement an OCSP responder
- Create OCSP signing certificates
- Handle OCSP requests
- Provide real-time certificate status
- Test with OpenSSL

### 9. CRL Distribution (09_crl_distribution.py)
Demonstrates:
- CRL distribution points
- Certificate revocation handling
- Automatic CRL updates
- RESTful API for revocation
- Status checking endpoints

## Output Files

Each example creates various output files in the current directory. These files are for demonstration purposes and should be properly secured in a production environment.

### Basic CA Example
- `server.key`: Server private key (PEM)
- `server.crt`: Server certificate (PEM)
- `server.p12`: Server certificate and key (PKCS12)

### Certificate Chain Example
- `root.crt`: Root CA certificate
- `intermediate.crt`: Intermediate CA certificate
- `intermediate.key`: Intermediate CA private key
- `server.crt`: Server certificate
- `server.key`: Server private key
- `chain.crt`: Full certificate chain

### Client Authentication Example
- `client_basic.p12`: Basic client authentication certificate
- `client_email.p12`: Email signing certificate
- `client_docsign.p12`: Document signing certificate

### Certificate Store Example
- `ca.crl`: Certificate Revocation List

### Java KeyStore Example
- `tomcat.jks`: Single certificate keystore
- `multi.jks`: Multiple certificate keystore
- `truststore.jks`: CA certificate truststore

### Custom Extensions Example
- `department.crt`: Certificate with department extension
- `rbac.crt`: Certificate with role-based access control
- `employee.crt`: Certificate with multiple custom extensions

### Web Server Example
- `server.crt`: Server certificate
- `server.key`: Server private key
- `client.p12`: Client certificate for authentication
- `ca.crt`: CA certificate for trust

### OCSP Responder Example
- `ocsp.crt`: OCSP responder certificate
- `ocsp.key`: OCSP responder private key
- `test.crt`: Test certificate
- `ca.crt`: CA certificate

### CRL Distribution Example
- `test1.crt`, `test2.crt`, `test3.crt`: Test certificates
- `crl.pem`: Certificate Revocation List
- `ca.crt`: CA certificate

## Security Notes

These examples are for demonstration purposes. In a production environment:

1. Always protect private keys with strong passwords
2. Store private keys securely
3. Use appropriate key lengths and validity periods
4. Implement proper access controls
5. Follow your organization's security policies
6. Use secure random number generation
7. Implement proper certificate revocation checking
8. Keep CA certificates offline when possible
9. Use hardware security modules (HSM) for CA keys in production
10. Implement high availability for OCSP/CRL services
11. Monitor certificate expiration and revocation status

## Testing Tools

### Using OpenSSL
```bash
# View certificate contents
openssl x509 -in server.crt -text -noout

# Verify certificate chain
openssl verify -CAfile chain.crt server.crt

# Test HTTPS server
openssl s_client -connect localhost:8443

# Test OCSP responder
openssl ocsp -issuer ca.crt -cert test.crt -url http://localhost:2560 -resp_text

# Verify against CRL
openssl verify -crl_check -CAfile ca.crt -CRLfile crl.pem test1.crt
```

### Using Java Keytool
```bash
# View keystore contents
keytool -list -v -keystore tomcat.jks

# Import certificate into truststore
keytool -import -trustcacerts -file ca.crt -alias ca -keystore truststore.jks
```

### Using Curl
```bash
# Test HTTPS server with client certificate
curl -k --cert-type P12 --cert client.p12:secret https://localhost:8443/secure

# Download CRL
curl -o crl.pem http://localhost:8080/crl.pem

# Check certificate status
curl -X POST -H "Content-Type: application/json" -d '{"serial": 1}' http://localhost:8080/check
```

## Additional Resources

- [PyCertAuth Documentation](https://github.com/yourusername/pycertauth)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [RFC 5280 - X.509 PKI Certificate](https://tools.ietf.org/html/rfc5280)
- [RFC 6960 - OCSP](https://tools.ietf.org/html/rfc6960)
- [RFC 5019 - Lightweight OCSP Profile](https://tools.ietf.org/html/rfc5019)
- [Java Keytool Documentation](https://docs.oracle.com/en/java/javase/11/tools/keytool.html)
- [AIOHTTP SSL Documentation](https://docs.aiohttp.org/en/stable/client_advanced.html#ssl-control-for-tcp-sockets) 