from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional
from . import signature


@dataclass(frozen=True)
class Block:
    data: Any
    previous_block: Block
    previous_hash: Optional[bytes]

    @classmethod
    def new_block(cls, data: Any, previous_block: Optional[Block] = None) -> Block:
        previous_hash = previous_block.compute_hash() if previous_block else b''
        return cls(data, previous_block, previous_hash)

    def verify(self) -> bool:
        return self.previous_hash == self.previous_block.compute_hash()
    
    def compute_hash(self) -> bytes:
        if hasattr(self.data, 'compute_hash'):
            data_hash = self.data.compute_hash()
        else:
            data_hash = signature.compute_hash(self.data)
        return signature.compute_hash(data_hash + self.previous_hash)

    def __repr__(self):
        return f'Block.new_block({self.data}, previous_block)'
