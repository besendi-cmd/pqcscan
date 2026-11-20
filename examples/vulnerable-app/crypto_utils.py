import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def make_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    return rsa_key, ec_key


def wrap_session_key(public_key, session_key: bytes) -> bytes:
    return public_key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


def sign(ec_key, message: bytes) -> bytes:
    return ec_key.sign(message, ec.ECDSA(hashes.SHA256()))


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def legacy_checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()  # pqcscan: ignore
