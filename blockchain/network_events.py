from __future__ import annotations
import time
from typing import Dict, NamedTuple, TYPE_CHECKING
from .blockchain import VerificationResult, DataObject, SIGNATURE_OK, SIGNATURE_NOK
from . import signing
if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import rsa

# networking constants
TOPIC_NETWORK_EVENTS = 'TOPIC_NETWORK_EVENTS'
NETWORK_EVENT_CONNECT = 'NETWORK_EVENT_CONNECT'
NETWORK_EVENT_DISCONNECT = 'NETWORK_EVENT_DISCONNECT'
NETWORK_EVENT_KEEP_ALIVE = 'NETWORK_EVENT_KEEP_ALIVE'


class NetworkEventPayload(NamedTuple):
    public_key: str
    host: str
    port: str
    event_type: str
    timestamp: float
    signature: str


class NetworkEvent(DataObject):
    payload: NetworkEventPayload

    @classmethod
    def new_network_event(cls,
                          public_key: rsa.RSAPublicKey,
                          host: str,
                          port: str,
                          event_type: str,
                          private_key: rsa.RSAPrivateKey) -> NetworkEvent:
        public_key = signing.serialize_public_key_as_hex(public_key)
        timestamp = time.time()
        signature = signing.sign_as_hex(public_key + host + port + event_type + str(timestamp), private_key)
        payload = NetworkEventPayload(public_key,
                                      host,
                                      port,
                                      event_type,
                                      timestamp,
                                      signature)
        return cls(payload, TOPIC_NETWORK_EVENTS)

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
        msg = self.__get_unique_signable()
        if signing.verify_hex(msg, self.payload.signature, signing.load_public_key_from_hex(self.payload.public_key)):
            return VerificationResult.succeed(SIGNATURE_OK, 'signature matches key-pair', self)
        return VerificationResult.fail(SIGNATURE_NOK, 'signature does not match key-pair')

    def compute_hash(self) -> str:
        return signing.compute_hash_as_hex(self.__get_unique_signable())

    def payload_as_dict(self) -> Dict[str, str]:
        return self.payload._asdict()

    @staticmethod
    def payload_from_dict(payload: Dict[str, str]) -> NetworkEventPayload:
        return NetworkEventPayload(**payload)
    
    def __get_unique_signable(self) -> str:
        return ''. join([self.payload.public_key,
                         self.payload.host,
                         self.payload.port,
                         self.payload.event_type,
                         str(self.payload.timestamp)])
