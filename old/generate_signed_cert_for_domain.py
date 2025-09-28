import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_CACHE_DIR = "certs"
os.makedirs(CERT_CACHE_DIR, exist_ok=True)

def get_or_generate_cert(domain):
    cert_path = os.path.join(CERT_CACHE_DIR, f"{domain}.crt.pem")
    key_path = os.path.join(CERT_CACHE_DIR, f"{domain}.key.pem")
    if (
        not os.path.exists(cert_path)
        or not os.path.exists(key_path)
        or not is_cert_valid(cert_path)
    ):
        cert_pem, key_pem = generate_signed_cert(domain)
        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        with open(key_path, "wb") as f:
            f.write(key_pem)

    # TODO: Check if the cert is actually valid. It might have expired. If that
    # is the case, then delete the file and generate it again
    return cert_path, key_path

def is_cert_valid(cert_path: str) -> bool:
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        now = datetime.now(timezone.utc)
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    except Exception:
        # Invalid file or corrupt cert
        return False

def generate_signed_cert(domain, ca_cert_path="encripton.pem", ca_key_path="encripton.key"):
    # Load CA key and cert
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Generate new key for the fake cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem

# Example usage:
# cert_pem, key_pem = generate_signed_cert("geoapi.es")
# with open("geoapi_cert.pem", "wb") as f:
#     f.write(cert_pem)
# with open("geoapi_key.pem", "wb") as f:
#     f.write(key_pem)
