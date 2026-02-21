import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger(__name__)


class CertManager:
    def __init__(self, data_dir: Path, app_id: str):
        self._data_dir = data_dir
        self._app_id = app_id

        self._domain_locks: dict[str, Lock] = {}
        self._domain_locks_lock = Lock()

        os.makedirs(self._data_dir, exist_ok=True)

        self._db = sqlite3.connect(str(self._data_dir / "certs.db"), check_same_thread=False)
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS root_cert (
                id  INTEGER PRIMARY KEY CHECK (id = 1),
                cert_pem BLOB NOT NULL,
                key_pem  BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS leaf_certs (
                domain   TEXT PRIMARY KEY,
                cert_pem BLOB NOT NULL,
                key_pem  BLOB NOT NULL,
                expires_at REAL NOT NULL
            );
        """)

    def _root_row(self):
        return self._db.execute("SELECT cert_pem, key_pem FROM root_cert WHERE id = 1").fetchone()

    def is_root_cert_valid(self) -> bool:
        try:
            row = self._root_row()
            if row is None:
                return False
            cert = x509.load_pem_x509_certificate(bytes(row[0]))
            now = datetime.now(timezone.utc)
            return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        except Exception:
            return False

    def is_root_cert_trusted(self) -> bool:
        try:
            row = self._root_row()
            if row is None:
                return False
            cert = x509.load_pem_x509_certificate(bytes(row[0]))
            fingerprint = cert.fingerprint(hashes.SHA1()).hex().upper()
            if sys.platform == "darwin":
                return self._is_trusted_macos(fingerprint)
            return False
        except Exception:
            return False

    def _is_trusted_macos(self, fingerprint: str) -> bool:
        result = subprocess.run(
            ["security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False
        # Output lines look like: "SHA-1 hash: AB CD EF ..."
        # Strip all whitespace so we can do a plain substring match.
        normalized = result.stdout.replace(" ", "").upper()
        return fingerprint in normalized

    def is_cert_valid(self, domain: str) -> bool:
        now = datetime.now(timezone.utc).timestamp()
        row = self._db.execute(
            "SELECT expires_at FROM leaf_certs WHERE domain = ?",
            (domain,),
        ).fetchone()
        return row is not None and now <= row[0]

    def get_root_cert_pem(self) -> bytes:
        row = self._root_row()
        return bytes(row[0])

    def _clear_leaf_cert_cache(self):
        """Remove all cached leaf certs so they get re-signed by the new root CA."""
        self._db.execute("DELETE FROM leaf_certs")
        self._db.commit()

    def create_root_cert(self) -> Tuple[bytes, bytes]:
        logger.info("Creating root certificate")
        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create subject and issuer (self-signed)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._app_id),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{self._app_id} Root CA"),
            ]
        )

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
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        self._db.execute(
            "INSERT OR REPLACE INTO root_cert (id, cert_pem, key_pem) VALUES (1, ?, ?)",
            (cert_pem, key_pem),
        )
        self._db.commit()

        # Leaf certs signed by the old CA are now invalid — purge them.
        self._clear_leaf_cert_cache()

        return cert_pem, key_pem

    def install_root_cert(self):
        logger.info("Installing root cert")

        if sys.platform == "darwin":
            cert_pem = self.get_root_cert_pem()
            fd, tmp_path = tempfile.mkstemp(suffix=".pem")
            try:
                os.write(fd, cert_pem)
                os.close(fd)
                # TODO: delete previous versions
                subprocess.run(
                    [
                        "sudo",
                        "security",
                        "add-trusted-cert",
                        "-d",
                        "-rtrustRoot",
                        "-k/Library/Keychains/System.keychain",
                        tmp_path,
                    ]
                )
            finally:
                os.unlink(tmp_path)

    def _get_domain_lock(self, domain: str) -> Lock:
        with self._domain_locks_lock:
            if domain not in self._domain_locks:
                self._domain_locks[domain] = Lock()
            return self._domain_locks[domain]

    def get_or_generate_cert(self, domain: str) -> Tuple[bytes, bytes]:
        with self._get_domain_lock(domain):
            if not self.is_cert_valid(domain):
                logger.info(f"Generating spoofed cert for {domain}")
                cert_pem, key_pem = self.generate_signed_cert(domain)
                expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).timestamp()
                self._db.execute(
                    "INSERT OR REPLACE INTO leaf_certs (domain, cert_pem, key_pem, expires_at) VALUES (?, ?, ?, ?)",
                    (domain, cert_pem, key_pem, expires_at),
                )
                self._db.commit()
                return cert_pem, key_pem

            row = self._db.execute(
                "SELECT cert_pem, key_pem FROM leaf_certs WHERE domain = ?",
                (domain,),
            ).fetchone()
            return bytes(row[0]), bytes(row[1])

    def generate_signed_cert(self, domain: str) -> Tuple[bytes, bytes]:
        # Load CA cert and key from DB
        row = self._root_row()
        ca_cert = x509.load_pem_x509_certificate(bytes(row[0]))
        ca_key = serialization.load_pem_private_key(bytes(row[1]), password=None)

        # Generate new key for the fake cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ]
        )

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
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH,
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
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
