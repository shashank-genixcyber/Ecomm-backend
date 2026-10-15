"""Generate disposable local assets without importing Django or reading .env."""
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .registry import CONSUMERS, oauth_audience, oauth_scope


def private_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def public_bytes(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def certificate_fingerprint(certificate):
    return certificate.fingerprint(hashes.SHA256()).hex()


def key_fingerprint(key):
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(public).hexdigest()


def initialize(root):
    from .audit import environment_name
    environment_name()  # Reject invalid labels before creating any assets.
    root = Path(root).resolve()
    if (root / "manifest.json").exists():
        if json.loads((root / "manifest.json").read_text())["schema_version"] != 1:
            raise ValueError("Unsupported demo asset manifest.")
        from .issuance import ensure_issuances
        ensure_issuances(root)
        return root
    if root.exists() and any(root.iterdir()):
        raise ValueError("Demo directory is incomplete; refusing to overwrite its contents.")
    root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".demo-init-", dir=root.parent))
    staging.chmod(0o700)

    def write(name, value):
        data = value if isinstance(value, bytes) else value.encode()
        descriptor = os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)

    def write_json(name, value):
        write(name, json.dumps(value, indent=2))

    try:
        now = datetime.now(timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Everyday Local Demo CA")])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
              .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                          crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
              .sign(ca_key, hashes.SHA256()))
        write("ca.pem", ca.public_bytes(serialization.Encoding.PEM))
        write("ca.key.pem", private_bytes(ca_key))

        def make_certificate(name, server=False):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            builder = (x509.CertificateBuilder()
                       .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                       .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                       .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                       .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                                   data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                                   crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
            if server:
                builder = builder.add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]), critical=False)
            certificate = builder.sign(ca_key, hashes.SHA256())
            write(f"{name}.pem", certificate.public_bytes(serialization.Encoding.PEM))
            write(f"{name}.key.pem", private_bytes(key))
            return certificate

        make_certificate("server", server=True)
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        write("issuer.key.pem", private_bytes(issuer_key))
        write("issuer.public.pem", public_bytes(issuer_key))
        bootstrap = {"django_secret_key": secrets.token_urlsafe(64), "web_client_secret": secrets.token_urlsafe(32)}
        references = {}
        for consumer in CONSUMERS:
            reference = {"type": consumer.credential_type, "version": "v1"}
            if consumer.credential_type == "secret":
                value = secrets.token_urlsafe(32)
                write(f"{consumer.credential_name}.txt", value)
                reference["expected_secret"] = value
            elif consumer.credential_type == "certificate":
                reference["fingerprint"] = certificate_fingerprint(make_certificate(consumer.credential_name))
            elif consumer.credential_type == "key":
                key = ed25519.Ed25519PrivateKey.generate()
                write(f"{consumer.credential_name}.key.pem", private_bytes(key))
                reference["public_key"] = public_bytes(key).decode()
            else:
                client = {"client_id": consumer.id, "client_secret": secrets.token_urlsafe(32),
                          "audience": oauth_audience(consumer), "scope": oauth_scope(consumer)}
                write_json(f"{consumer.id}.client.json", client)
                reference.update(client)
            references[consumer.id] = reference
        write_json("bootstrap.json", bootstrap)
        write_json("provider.json", references)
        write_json("manifest.json", {"schema_version": 1, "created_at": now.isoformat(),
                                     "version": "v1", "services": [consumer.public() for consumer in CONSUMERS],
                                     "infrastructure": [
                                         {"name": name, "asset_role": "infrastructure"} for name in (
                                             "django-signing-secret", "web-oidc-client-secret", "local-demo-ca",
                                             "local-demo-server-certificate", "local-oidc-signing-key",
                                             "promotions-oauth-client-secret", "fulfillment-oauth-client-secret",
                                             "notifications-oauth-client-secret")
                                     ]})
        if root.exists():
            root.rmdir()  # Only an empty directory can reach this branch.
        staging.rename(root)
        from .issuance import ensure_issuances
        ensure_issuances(root, origin="local_generation")
        return root
    finally:
        if staging.exists():
            shutil.rmtree(staging)
