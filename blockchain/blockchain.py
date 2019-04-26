from __future__ import annotations
import time
import json
from typing import Optional, Tuple, Dict, NamedTuple, TypeVar, TYPE_CHECKING
from . import signature
if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import rsa

T = TypeVar('T')

# generic signature constants
SIGNATURE_OK = 'SIGNATURE_OK'
SIGNATURE_NOK = 'SIGNATURE_NOK'

# networking constants
TOPIC_NETWORK_EVENT = 'TOPIC_NETWORK_EVENT'
NETWORK_EVENT_CONNECT = 'NETWORK_EVENT_CONNECT'
NETWORK_EVENT_DISCONNECT = 'NETWORK_EVENT_DISCONNECT'
NETWORK_EVENT_KEEP_ALIVE = 'NETWORK_EVENT_KEEP_ALIVE'


class Block(NamedTuple):
    data: Tuple[DataObject, ...]
    previous_block_hash: bytes
    nonce: bytes = None

    @classmethod
    def new_block(cls, data: Tuple[DataObject, ...], previous_block: Optional[Block]) -> Block:
        if data:
            prev_block_hash = previous_block.compute_hash() if previous_block else b''
            return cls(data, prev_block_hash)
        raise ValueError('data and previous_block must not be None')

    def as_dict(self) -> Dict[str, str]:
        return {
            'data': [db.as_dict() for db in self.data],
            'previous_block_hash': str(self.previous_block_hash, 'utf8'),
            'nonce': str(self.nonce, 'utf8')
        }

    def as_json(self) -> str:
        return json.dumps(self.as_dict())

    def compute_hash(self) -> bytes:
        data_hash = b''.join([db.compute_hash() for db in self.data])
        return signature.compute_hash(data_hash + self.previous_block_hash)

    def verify(self, block_service) -> bool:
        previous_block = block_service.get_block(self.previous_block_hash)
        return self.previous_block_hash == previous_block.compute_hash(previous_block)


class DataObject(NamedTuple):
    payload: T
    topic: str

    def compute_hash(self):
        return NotImplemented

    def verify(self):
        return NotImplemented

    def as_dict(self) -> Dict[str, str]:
        return {
            'topic': self.topic,
            'payload': self.payload_as_dict()
        }

    def payload_as_dict(self):
        return NotImplemented

    def as_json(self) -> str:
        return json.dumps(self.as_dict())

    @classmethod
    def from_dict(cls, as_dict: Dict) -> DataObject:
        block = cls(payload=cls.payload_from_dict(as_dict['payload']), topic=as_dict['topic'])
        return block

    @staticmethod
    def payload_from_dict(payload: Dict[str, str]) -> T:
        return NotImplemented

    @classmethod
    def from_json(cls, as_json: str) -> DataObject:
        block = cls.from_dict(json.loads(as_json))
        return block


class NetworkEvent(DataObject):
    payload: Dict[str, str]
    topic: str = TOPIC_NETWORK_EVENT

    @classmethod
    def new_network_event(cls,
                          public_key: str,
                          host: str,
                          port: str,
                          event_type: str,
                          private_key: rsa.RSAPrivateKey) -> NetworkEvent:
        payload = {
            'public_key': public_key,
            'host': host,
            'port': port,
            'event_type': event_type,
            'timestamp': str(time.time()),
            'signature': str(signature.sign(public_key + host + port, private_key), 'utf8')
        }
        return cls(payload)

    @classmethod
    def new_connect_event(cls,
                          public_key: str,
                          host: str,
                          port: str,
                          private_key: rsa.RSAPrivateKey) -> NetworkEvent:
        return cls.new_network_event(public_key, host, port, NETWORK_EVENT_CONNECT, private_key)

    @classmethod
    def new_disconnect_event(cls,
                             public_key: str,
                             host: str,
                             port: str,
                             private_key: rsa.RSAPrivateKey) -> NetworkEvent:
        return cls.new_network_event(public_key, host, port, NETWORK_EVENT_DISCONNECT, private_key)

    @classmethod
    def new_keep_alive_event(cls,
                             public_key,
                             host: str,
                             port: str,
                             private_key: rsa.RSAPrivateKey) -> NetworkEvent:
        return cls.new_network_event(public_key, host, port, NETWORK_EVENT_KEEP_ALIVE, private_key)

    def verify(self):
        pub_key = self.payload['public_key']
        sig = self.payload['signature']
        msg = pub_key + self.payload['host'] + self.payload['port'] + self.payload['timestamp'] + self.payload['event_type']
        if signature.verify(msg, bytes(sig, 'utf8'), pub_key):
            return VerificationSuccess(result_code=SIGNATURE_OK, message='signature matches key-pair')
        return VerificationFailed(result_code=SIGNATURE_NOK, message='signature does not match key-pair')

    def compute_hash(self):
        return signature.compute_hash(''.join(self.payload.values()))

    def payload_as_dict(self):
        return self.payload

    @staticmethod
    def payload_from_dict(payload: Dict[str, str]) -> T:
        return {
            'public_key': payload['public_key'],
            'host': payload['host'],
            'port': payload['port'],
            'event_type': payload['event_type'],
            'timestamp': payload['timestamp'],
            'signature': payload['signature']
        }


class VerificationResult(NamedTuple):
    result_code: str
    message: str


class VerificationSuccess(VerificationResult):
    def __bool__(self):
        return True


class VerificationFailed(VerificationResult):
    def __bool__(self):
        return False
