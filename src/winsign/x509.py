from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def encode_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def decode_key(data):
    return serialization.load_pem_private_key(
        data, password=None, backend=default_backend()
    )


def load_pem_cert(pem_data):
    return x509.load_pem_x509_certificate(pem_data, default_backend())
