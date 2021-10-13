"""key and signing functions for winsign."""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils


def sign_signer_digest(priv_key, digest_algo, signer_digest):
    """Sign a digest with a private key.

    Args:
        priv_key (private key): private key to sign with
        digest_algo (str): one of 'sha1', or 'sha256'
        signer_digest (bytes): digest to sign

    Returns:
        The signature as a byte string

    """
    crypto_digest = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256()}[  # nosec
        digest_algo
    ]
    signature = priv_key.sign(
        signer_digest, padding.PKCS1v15(), utils.Prehashed(crypto_digest)
    )
    return signature


def write_pem_cert(cert, filename):
    """Write an x509 Certificate object out to given filename.

    Args:
        cert (x509 certificate): input cert object
        filename (str): path that we will output the cert.public_bytes() to

    """
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))


def load_private_key(data):
    """Load private key from a PEM encoded string."""
    return serialization.load_pem_private_key(
        data, password=None, backend=default_backend()
    )


def load_pem_cert(pem_data):
    """Load x509 cerficiate from a PEM encoded string."""
    return x509.load_pem_x509_certificate(pem_data, default_backend())


def load_pem_certs(pem_data):
    """Load multiple x509 certificates from a PEM encoded string."""
    certs = []
    for cert in pem_data.split(b"-----BEGIN CERTIFICATE-----\n"):
        if not cert:
            continue
        cert = b"-----BEGIN CERTIFICATE-----\n" + cert
        certs.append(load_pem_cert(cert))
    return certs
