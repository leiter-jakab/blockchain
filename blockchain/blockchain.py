from __future__ import annotations
import json
# from dataclasses import dataclass
from typing import Any, Optional, Dict, NamedTuple, TypeVar
from . import signature


# @dataclass(frozen=True)
# class Block:
#     data: Optional[Any]
#     previous_block: Optional[bytes]
#     previous_hash: Optional[bytes]
#
#     @classmethod
#     def new_block(cls, data: Any, previous_block: Optional[bytes] = None) -> Block:
#         previous_hash = previous_block.compute_hash() if previous_block else b''
#         return cls(data, previous_block, previous_hash)
#
#     def verify(self) -> bool:
#         return self.previous_hash == self.previous_block.compute_hash()
#
#     def compute_hash(self) -> bytes:
#         if hasattr(self.data, 'compute_hash'):
#             data_hash = self.data.compute_hash()
#         else:
#             data_hash = signature.compute_hash(self.data)
#         return signature.compute_hash(data_hash + self.previous_hash)
#
#     def __repr__(self):
#         return f'Block.new_block({self.data}, previous_block)'

class Block(NamedTuple):
    data: BlockData
    previous_block_hash: bytes
    nonce: bytes = None

    @classmethod
    def new_block(cls, data: BlockData, previous_block: Optional[Block]) -> Block:
        if data:
            prev_block_hash = previous_block.compute_hash() if previous_block else b''
            return cls(data, prev_block_hash)
        raise ValueError('data and previous_block must not be None')

    def as_dict(self) -> Dict[str, str]:
        return {
            'data': self.data.as_dict(),
            'previous_block_hash': str(self.previous_block_hash, 'utf8'),
            'nonce': str(self.nonce, 'utf8')
        }

    def as_json(self, data_as_dict) -> str:
        return json.dumps(self.as_dict(data_as_dict))

    def compute_hash(self) -> bytes:
        return signature.compute_hash(self.data.compute_hash() + self.previous_block_hash)

    def verify(self, block_service) -> bool:
        previous_block = block_service.get_block(self.previous_block_hash)
        return self.previous_block_hash == previous_block.compute_hash(previous_block)


T = TypeVar('T')


class BlockData(NamedTuple):
    payload: T
    data_type = 'TYPE_GENERIC'

    def as_dict(self) -> Dict[str, str]:
        return {
            'type': self.data_type,
            'payload': self.payload_as_dict()
        }

    def payload_as_dict(self):
        return NotImplemented

    def as_json(self) -> str:
        return json.dumps(self.as_dict())

    @classmethod
    def from_dict(cls, as_dict: Dict) -> BlockData:
        block = cls(payload=cls.payload_from_dict(as_dict['payload']), data_type=as_dict['data_type'])
        return block

    @staticmethod
    def payload_from_dict(payload: Dict[str, str]) -> T:
        return NotImplemented

    @classmethod
    def from_json(cls, as_json: str) -> BlockData:
        pass


class ExampleData(BlockData):
    payload: Dict[int, str]
    data_type = 'TYPE_EXAMPLE'
