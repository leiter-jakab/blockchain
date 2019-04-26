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


def sign_as_hex(message: Any, private_key: rsa.RSAPrivateKey) -> str:
    return sign(message, private_key).hex()


def verify(message: Any, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
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


def verify_hex(message: Any, signature: str, public_key: rsa.RSAPublicKey) -> bool:
    return verify(message, bytes.fromhex(signature), public_key)


def serialize_private_key(key: rsa.RSAPrivateKeyWithSerialization, password: bytes = b'') -> bytes:
    key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password)
    )
    return key


def serialize_private_key_as_hex(key: rsa.RSAPrivateKeyWithSerialization, password: bytes = b'') -> str:
    return serialize_private_key(key, password).hex()


def serialize_public_key(key: rsa.RSAPublicKey) -> bytes:
    key = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key


def serialize_public_key_as_hex(key: rsa.RSAPublicKey) -> str:
    return serialize_public_key(key).hex()


def load_private_key(pem_data: bytes, password: bytes = None) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem_data, password, default_backend())


def load_private_key_from_hex(pem_data: str, password: bytes = None) -> rsa.RSAPrivateKey:
    return load_private_key(bytes.fromhex(pem_data), password)


def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem_data, default_backend())


def load_public_key_from_hex(pem_data: str) -> rsa.RSAPublicKey:
    return load_public_key(bytes.fromhex(pem_data))


def compute_hash(data: Any) -> bytes:
    if type(data) != bytes:
        data = bytes(str(data), 'utf8')
    digest = hashes.Hash(hashes.SHA256(), default_backend())
    digest.update(data)
    return digest.finalize()


def compute_hash_as_hex(data: Any) -> str:
    return compute_hash(data).hex()
