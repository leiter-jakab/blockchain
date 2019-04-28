from __future__ import annotations
import time
from typing import Dict, NamedTuple, TYPE_CHECKING
from .blockchain import VerificationResult, DataObject, SIGNATURE_OK, SIGNATURE_NOK
from . import signing
if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import rsa

# networking constants
TOPIC_NETWORK_EVENT = 'TOPIC_NETWORK_EVENT'
NETWORK_EVENT_CONNECT = 'NETWORK_EVENT_CONNECT'
NETWORK_EVENT_DISCONNECT = 'NETWORK_EVENT_DISCONNECT'
NETWORK_EVENT_KEEP_ALIVE = 'NETWORK_EVENT_KEEP_ALIVE'


class NetworkEventPayload(NamedTuple):
    public_key: str
    host: str
    port: str
    event_type: str
    timestamp: str
    signature: str


class NetworkEvent(DataObject):
    payload: Dict[str, str]

    @classmethod
    def new_network_event(cls,
                          public_key: rsa.RSAPublicKey,
                          host: str,
                          port: str,
                          event_type: str,
                          private_key: rsa.RSAPrivateKey) -> NetworkEvent:
        public_key = signing.serialize_public_key_as_hex(public_key)
        timestamp = str(time.time())
        payload = {
            'public_key': public_key,
            'host': host,
            'port': port,
            'event_type': event_type,
            'timestamp': timestamp,
            'signature': signing.sign_as_hex(public_key + host + port + event_type + timestamp, private_key)
        }
        return cls(payload, TOPIC_NETWORK_EVENT)

    @classmethod
    def new_connect_event(cls,
                          public_key: rsa.RSAPublicKey,
                          host: str,
                          port: str,
                          private_key: rsa.RSAPrivateKey) -> NetworkEvent:
        return cls.new_network_event(public_key, host, port, NETWORK_EVENT_CONNECT, private_key)

    @classmethod
    def new_disconnect_event(cls,
                             public_key: rsa.RSAPublicKey,
                             host: str,
                             port: str,
                             private_key: rsa.RSAPrivateKey) -> NetworkEvent:
        return cls.new_network_event(public_key, host, port, NETWORK_EVENT_DISCONNECT, private_key)

    @classmethod
    def new_keep_alive_event(cls,
                             public_key: rsa.RSAPublicKey,
                             host: str,
                             port: str,
                             private_key: rsa.RSAPrivateKey) -> NetworkEvent:
        return cls.new_network_event(public_key, host, port, NETWORK_EVENT_KEEP_ALIVE, private_key)

    def verify(self) -> VerificationResult:
        pub_key = self.payload['public_key']
        sig = self.payload['signature']
        msg = ''.join([pub_key, self.payload['host'],
                       self.payload['port'],
                       self.payload['event_type'],
                       self.payload['timestamp']])
        if signing.verify_hex(msg, sig, signing.load_public_key_from_hex(pub_key)):
            return VerificationResult.succeed(SIGNATURE_OK, 'signature matches key-pair', self)
        return VerificationResult.fail(SIGNATURE_NOK, 'signature does not match key-pair')

    def compute_hash(self) -> str:
        return signing.compute_hash_as_hex(''.join(self.payload.values()))

    def payload_as_dict(self) -> Dict[str, str]:
        return self.payload

    @staticmethod
    def payload_from_dict(payload: Dict[str, str]) -> Dict[str, str]:
        return {
            'public_key': payload['public_key'],
            'host': payload['host'],
            'port': payload['port'],
            'event_type': payload['event_type'],
            'timestamp': payload['timestamp'],
            'signature': payload['signature']
        }
