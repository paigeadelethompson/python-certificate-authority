"""Constants used throughout the pycertauth package"""

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519

# Safe curves from safecurves.cr.yp.to
SAFE_CURVES = {
    "curve25519": ed25519.Ed25519PrivateKey,  # Using Ed25519 directly
    "m221": None,  # Not available in cryptography library
    "e222": None,  # Not available in cryptography library
    "curve1174": None,  # Not available in cryptography library
    "e382": None,  # Not available in cryptography library
    "m383": None,  # Not available in cryptography library
    "curve383187": None,  # Not available in cryptography library
    "curve41417": None,  # Not available in cryptography library
    "ed448": ed448.Ed448PrivateKey,  # Using Ed448 directly
    "m511": None,  # Not available in cryptography library
    "e521": ec.SECP521R1(),  # Closest to E-521
}


class ExtendedKeyUsage:
    """Extended Key Usage (EKU) OIDs as defined in RFC 5280"""

    SERVER_AUTH = "1.3.6.1.5.5.7.3.1"  # TLS Web Server Authentication
    CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"  # TLS Web Client Authentication
    CODE_SIGNING = "1.3.6.1.5.5.7.3.3"  # Code Signing
    EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"  # Email Protection
    TIME_STAMPING = "1.3.6.1.5.5.7.3.8"  # Time Stamping
    OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"  # OCSP Signing


class KeyUsage:
    """Default key usage flags for different certificate types"""

    CA = {
        "digital_signature": True,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": True,
        "crl_sign": True,
        "encipher_only": False,
        "decipher_only": False,
    }

    SERVER = {
        "digital_signature": True,
        "content_commitment": False,
        "key_encipherment": True,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False,
    }

    CLIENT = {
        "digital_signature": True,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False,
    }
