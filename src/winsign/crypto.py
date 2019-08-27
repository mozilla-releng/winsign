from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils


def sign_signer_digest(priv_key, digest_algo, signer_digest):
    crypto_digest = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256()}[  # nosec
        digest_algo
    ]
    signature = priv_key.sign(
        signer_digest, padding.PKCS1v15(), utils.Prehashed(crypto_digest)
    )
    return signature


def load_private_key(data):
    return serialization.load_pem_private_key(
        data, password=None, backend=default_backend()
    )


def load_pem_cert(pem_data):
    return x509.load_pem_x509_certificate(pem_data, default_backend())


def load_pem_certs(pem_data):
    certs = []
    for cert in pem_data.split(b"-----BEGIN CERTIFICATE-----\n"):
        if not cert:
            continue
        cert = b"-----BEGIN CERTIFICATE-----\n" + cert
        certs.append(load_pem_cert(cert))
    return certs
