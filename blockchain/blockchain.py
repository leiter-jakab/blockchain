from __future__ import annotations
import json
from typing import Optional, Tuple, List, Dict, NamedTuple, Union, TYPE_CHECKING
from . import crypt
if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import rsa

# block constants
NONCE_ACCEPTED = 'NONCE_ACCEPTED'
NONCE_REJECTED = 'NONCE_ERROR'
NONCE_OK = 'NONCE_OK'
NONCE_NOK = 'NONCE_NOK'
BLOCK_OK = 'BLOCK_OK'
BLOCK_NOK = 'BLOCK_NOK'

# generic signature constants
SIGNATURE_OK = 'SIGNATURE_OK'
SIGNATURE_NOK = 'SIGNATURE_NOK'


class Block(NamedTuple):
    data: Tuple[DataObject, ...]
    previous_block_hash: str
    nonce: str = ''

    @classmethod
    def new_block(cls, data: Tuple[DataObject, ...], previous_block: Optional[Block]) -> Block:
        if data:
            prev_block_hash = previous_block.compute_hash() if previous_block else ''
            return cls(data, prev_block_hash)
        raise ValueError('data and previous_block must not be None')

    def as_dict(self) -> Dict[str, str]:
        return {
            'data': [db.as_dict() for db in self.data],
            'previous_block_hash': self.previous_block_hash,
            'nonce': self.nonce
        }

    def as_json(self) -> str:
        return json.dumps(self.as_dict())

    def compute_hash(self) -> str:
        data_hash = ''.join([db.compute_hash() for db in self.data])
        return crypt.compute_hash_as_hex(data_hash + self.previous_block_hash)

    def add_nonce(self, address: rsa.RSAPublicKey, nonce: str) -> VerificationResult:
        if not self.verify_nonce(nonce):
            return VerificationFailure(NONCE_REJECTED, 'nonce does not produce expected hash')
        address = crypt.serialize_public_key_as_hex(address)
        block_with_nonce = self._replace(nonce=nonce)
        return VerificationResult.succeed(NONCE_ACCEPTED, 'nonce produced expected hash', block_with_nonce)

    def verify_nonce(self, nonce: str) -> VerificationResult:
        n = 2
        if crypt.compute_hash(self.compute_hash() + nonce).startswith(bytes(n)):
            return VerificationResult.succeed(NONCE_OK, 'nonce produced expected hash')
        return VerificationResult.fail(NONCE_NOK, 'nonce does not produce expected hash')

    def verify(self, block_service) -> VerificationResult:
        previous_block = block_service.get_block(self.previous_block_hash)
        if self.previous_block_hash == previous_block.compute_hash(previous_block):
            return VerificationResult.succeed(BLOCK_OK, 'previous block and hash matching')
        return VerificationResult.fail(BLOCK_NOK, 'previous block and hash not matching')


class DataObject(NamedTuple):
    topic: str
    payload: NamedTuple

    def compute_hash(self) -> str:
        return NotImplemented

    def verify(self) -> VerificationResult:
        return NotImplemented

    def as_dict(self) -> Dict[str, str]:
        return {
            'topic': self.topic,
            'payload': self.payload_as_dict()
        }

    def payload_as_dict(self) -> Dict[str, Union[str, int, float, List, Dict]]:
        return NotImplemented

    def as_json(self) -> str:
        return json.dumps(self.as_dict())

    @classmethod
    def from_dict(cls, as_dict: Dict) -> DataObject:
        block = cls(topic=as_dict['topic'], payload=cls.payload_from_dict(as_dict['payload']))
        return block

    @staticmethod
    def payload_from_dict(payload: Dict[str, Union[str, int, float, List, Dict]]) -> NamedTuple:
        return NotImplemented

    @classmethod
    def from_json(cls, as_json: str) -> DataObject:
        block = cls.from_dict(json.loads(as_json))
        return block


class VerificationResult(NamedTuple):
    result_code: str
    message: str
    payload: Optional[VerifiedObject] = None

    @staticmethod
    def succeed(result_code: str, message: str, payload: Optional[VerifiedObject] = None):
        return VerificationSuccess(result_code, message, payload)

    @staticmethod
    def fail(result_code: str, message: str, payload: Optional[VerifiedObject] = None):
        return VerificationFailure(result_code, message, payload)


class VerificationSuccess(VerificationResult):
    def __bool__(self):
        return True


class VerificationFailure(VerificationResult):
    def __bool__(self):
        return False


VerifiedObject = Union[Block, DataObject]
