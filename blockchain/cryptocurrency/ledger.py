from __future__ import annotations
from dataclasses import dataclass, replace
from typing import Tuple, Optional, TYPE_CHECKING
from ..blockchain import Block
from ..blockchain import signature
from .transaction import Transaction, VERIFIED
if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

BLOCK_DATA_ERROR = 'BLOCK_DATA_ERROR'
BLOCK_HASH_ERROR = 'BLOCK_HASH_ERROR'
NONCE_ERROR = 'NONCE_ERROR'
NONCE_ACCEPTED = 'NONCE_ACCEPTED'


@dataclass(frozen=True)
class TransactionBlock(Block):
    nonce: Optional[Tuple[bytes, bytes]] = None

    @classmethod
    def new_block(
            cls,
            data: Tuple[Transaction] = (),
            previous_block: Optional[TransactionBlock] = None) -> TransactionBlock:
        previous_hash = previous_block.compute_hash() if previous_block else b''
        return cls(data, previous_block, previous_hash)

    def add_transaction(self, transaction: Transaction) -> TransactionBlock:
        return replace(self, data=self.data + (transaction,))

    def add_transactions(self, transactions: Tuple[Transaction, ...]) -> TransactionBlock:
        return replace(self, data=self.data + transactions)

    def add_nonce(self, address: RSAPublicKey, nonce: bytes) -> Tuple[Block, str, str]:
        if not self.verify_nonce(nonce):
            return self, NONCE_ERROR, 'nonce does not produce expected hash'
        address = signature.serialize_public_key(address)
        return replace(self, nonce=(address, nonce)), NONCE_ACCEPTED, 'nonce produced expected hash'

    def verify_nonce(self, nonce: bytes) -> bool:
        n = 2
        return signature.compute_hash(self.compute_hash() + nonce).startswith(bytes(n))

    def verify(self) -> Tuple[Tuple[Transaction, ...], str, str]:
        if not self.data:
            return self.data, BLOCK_DATA_ERROR, 'block contains no transactions'
        if super().verify():
            for tra in self.data:
                tr, status, msg = tra.verify()
                if status != VERIFIED:
                    return self.data, status, msg
            return self.data, VERIFIED, 'transaction block verified'
        return self.data, BLOCK_HASH_ERROR, 'previous block and hash not consistent'
