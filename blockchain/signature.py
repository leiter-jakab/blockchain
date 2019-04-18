from typing import Tuple, Any
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def generate_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return priv, priv.public_key()


def sign(message: Any, private_key: rsa.RSAPrivateKey) -> bytes:
    message = bytes(str(message), 'utf-8')
    sig = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return sig


def verify(message: Any, signature: bytes, public_key) -> bool:
    message = bytes(str(message), 'utf-8')
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def serialize_private_key(key: rsa.RSAPrivateKeyWithSerialization, password: bytes = b'') -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password)
    )


def serialize_public_key(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(pem_data: bytes, password: bytes = None) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem_data, password, default_backend())


def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem_data, default_backend())


def compute_hash(data: Any) -> bytes:
    if type(data) != bytes:
        data = bytes(str(data), 'utf8')
    digest = hashes.Hash(hashes.SHA256(), default_backend())
    digest.update(data)
    return digest.finalize()
