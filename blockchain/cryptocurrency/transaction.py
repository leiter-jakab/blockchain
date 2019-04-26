from __future__ import annotations
# from dataclasses import dataclass, replace
from typing import Tuple, Union, NamedTuple, TYPE_CHECKING
from decimal import Decimal
from ..blockchain import signature
if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

SIGNING_ERROR = 'SIGNING_ERROR'
TRANSACTION_ERROR = 'TRANSACTION_ERROR'
SIGNED = 'SIGNED'
VERIFIED = 'VERIFIED'


# @dataclass(frozen=True)
# class Transaction:
#     inputs: Tuple[Tuple[bytes, Union[int, float], bytes], ...] = ()
#     outputs: Tuple[Tuple[bytes, Union[int, float]], ...] = ()
#     required: Tuple[Tuple[bytes, bytes], ...] = ()
#
#     def add_input(self, from_address: RSAPublicKey, amount: Union[int, float]) -> Transaction:
#         new_inp = self.inputs + ((signature.serialize_public_key(from_address), amount, b''),)
#         return replace(self, inputs=new_inp)
#
#     def add_output(self, to_address: RSAPublicKey, amount: Union[int, float]) -> Transaction:
#         new_outp = self.outputs + ((signature.serialize_public_key(to_address), amount),)
#         return replace(self, outputs=new_outp)
#
#     def add_required(self, address: RSAPublicKey) -> Transaction:
#         new_reqd = self.required + ((signature.serialize_public_key(address), b''),)
#         return replace(self, required=new_reqd)
#
#     def sign(self, private_key: RSAPrivateKey) -> Tuple[Transaction, str, str]:
#         if len(self.inputs) < 1 or len(self.outputs) < 1:
#             return self, TRANSACTION_ERROR, 'transaction must have at least one input and output'
#
#         for i, v in enumerate(self.inputs):
#             addr, amount, sig = v
#             if addr == signature.serialize_public_key(private_key.public_key()):
#                 if sig:
#                     return self,  SIGNING_ERROR, 'transaction already signed by this private key'
#                 signed_input = (addr, amount, signature.sign(self.compute_hash(), private_key))
#                 new_inputs = self.inputs[:i] + (signed_input,) + self.inputs[i+1:]
#                 return replace(self, inputs=new_inputs), SIGNED, 'transaction signed'
#
#         for i, v in enumerate(self.required):
#             addr, sig = v
#             if addr == signature.serialize_public_key(private_key.public_key()):
#                 if sig:
#                     return self, SIGNING_ERROR, 'transaction already signed by this private key'
#                 required_sig = (addr, signature.sign(self.compute_hash(), private_key))
#                 new_required = self.required[:i] + (required_sig,) + self.required[i+1:]
#                 return replace(self, required=new_required), SIGNED, 'transaction signed'
#
#         return self, SIGNING_ERROR, 'not a valid signer'
#
#     def verify(self) -> Tuple[Transaction, str, str]:
#         sum_in = 0
#         sum_out = 0
#
#         for _, amount, _ in self.inputs:
#             if amount < 0:
#                 return self, TRANSACTION_ERROR, 'no negative inputs allowed'
#             sum_in += amount
#
#         for _, amount in self.outputs:
#             if amount < 0:
#                 return self, TRANSACTION_ERROR, 'no negative outputs allowed'
#             sum_out += amount
#
#         if sum_in < sum_out:
#             return self, TRANSACTION_ERROR, 'output must not exceed input'
#
#         for addr, _, sig in self.inputs:
#             if not sig:
#                 return self, SIGNING_ERROR, 'input signature missing'
#             if not signature.verify(self.compute_hash(), sig, signature.load_public_key(addr)):
#                 return self, SIGNING_ERROR, 'input signature is not valid'
#         for addr, sig in self.required:
#             if not sig:
#                 return self, SIGNING_ERROR, 'arbiter signature missing'
#             if not signature.verify(self.compute_hash(), sig, signature.load_public_key(addr)):
#                 return self, SIGNING_ERROR, 'arbiter signature is not valid'
#
#         return self, VERIFIED, 'transaction verified'
#
#     def compute_hash(self) -> bytes:
#         tra_bytes = b''
#         for addr, amount, _ in self.inputs:
#             tra_bytes += addr
#             tra_bytes += bytes(str(amount), 'utf-8')
#
#         for addr, amount in self.outputs:
#             tra_bytes += addr
#             tra_bytes += bytes(str(amount), 'utf-8')
#
#         for addr, _ in self.required:
#             tra_bytes += addr
#
#         return signature.compute_hash(tra_bytes)
#
#     def __str__(self):
#         def get_addr(addr):
#             return str(addr, 'utf-8').replace('\n', '')[-38: -30]
#
#         rep = '[inputs]:\n'
#         for addr, amount, sig in self.inputs:
#             rep += f'  - {get_addr(addr)}: {amount} {" | signed" if sig else ""}\n'
#         rep += '[outputs]:\n'
#         for addr, amount in self.outputs:
#             rep += f'  - {get_addr(addr)}: {amount}\n'
#         rep += '[required]:\n'
#         for addr, sig in self.required:
#             rep += f'  - {get_addr(addr)} {"| signed" if sig else ""}\n'
#
#         return rep
Amount = Union[int, float, Decimal]
Input = Tuple[bytes, Amount, bytes]
Output = Tuple[bytes, Amount]
ArbiterSig = Tuple[bytes, bytes]


class Transaction(NamedTuple):
    inputs: Tuple[Input, ...] = ()
    outputs: Tuple[Output, ...] = ()
    required: Tuple[ArbiterSig, ...] = ()


def add_input(tra: Transaction, from_address: RSAPublicKey, amount: Amount) -> Transaction:
    return tra._replace(inputs=tra.inputs + ((signature.serialize_public_key(from_address), amount, b''),))


def add_output(tra: Transaction, to_address: RSAPublicKey, amount: Amount) -> Transaction:
    return tra._replace(outputs=tra.outputs + ((signature.serialize_public_key(to_address), amount),))


def add_required(tra: Transaction, arbiter_address: RSAPublicKey) -> Transaction:
    return tra._replace(required=tra.required + ((signature.serialize_public_key(arbiter_address), b''),))
