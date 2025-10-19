import logging
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger(__name__)

CERTS_PATH = "certs"
ROOT_CERT = "encripton.pem"
ROOT_KEY = "encripton.key"

CERT = "{domain}.crt.pem"
KEY = "{domain}.key.pem"

class CertManager:
    def __init__(self):
        self.cert_cache_dir = Path(CERTS_PATH)
        self.root_cert = ROOT_CERT
        self.root_key = ROOT_KEY

        os.makedirs(self.cert_cache_dir, exist_ok=True)

    def is_root_cert_valid(self) -> bool:
        return self._is_cert_valid(cert_name=ROOT_CERT)

    def is_cert_valid(self, domain: str) -> bool:
        cert_name = CERT.format(domain=domain)
        return self._is_cert_valid(cert_name=cert_name)

    def _is_cert_valid(self, cert_name) -> bool:
        try:
            with open(self.cert_cache_dir / cert_name, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            now = datetime.now(timezone.utc)
            return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        except Exception:
            # Invalid file or corrupt cert
            return False

    def create_root_cert(self) -> Tuple[bytes, bytes]:
        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create subject and issuer (self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"EncriptonMITM"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"EncriptonMITM Root CA"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=False
            )
            .sign(key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(self.cert_cache_dir / self.root_cert, "wb") as f:
            f.write(cert_pem)

        with open(self.cert_cache_dir / self.root_key, "wb") as f:
            f.write(key_pem)

        # TODO: delete previous versions
        subprocess.run([
            "sudo",
            "security",
            "add-trusted-cert",
            "-d",
            "-r"
            "trustRoot",
            "-k"
            "/Library/Keychains/System.keychain",
            (self.cert_cache_dir / self.root_cert).resolve(),
        ])

        return cert_pem, key_pem

    def get_or_generate_cert(self, domain) -> Tuple[str, str]:
        cert_path = self.cert_cache_dir / CERT.format(domain=domain)
        key_path = self.cert_cache_dir / KEY.format(domain=domain)

        if (
            not os.path.exists(cert_path)
            or not os.path.exists(key_path)
            or not self.is_cert_valid(domain)
        ):
            logger.info(f"Generating spoofed cert for {domain}")
            cert_pem, key_pem = self.generate_signed_cert(domain)

            with open(cert_path, "wb") as f:
                f.write(cert_pem)

            with open(key_path, "wb") as f:
                f.write(key_pem)

        return cert_path.absolute(), key_path.absolute()

    def generate_signed_cert(self, domain) -> Tuple[bytes, bytes]:
        # Load CA key and cert
        with open(self.cert_cache_dir / self.root_key, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(self.cert_cache_dir / self.root_cert, "rb") as f:
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