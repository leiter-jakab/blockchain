from __future__ import annotations
from typing import Tuple, Dict, List, Union, NamedTuple, TYPE_CHECKING
from decimal import Decimal
from .blockchain import DataObject, VerificationResult
from . import crypt
if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import rsa



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

# transaction constants
TOPIC_TRANSACTIONS = 'TOPIC_TRANSACTIONS'
TRANSACTION_ERROR = 'TRANSACTION_ERROR'
TRANSACTION_SIGNING_ERROR = 'TRANSACTION_SIGNING_ERROR'
TRANSACTION_SIGNED = 'TRANSACTION_SIGNED'
TRANSACTION_VERIFIED = 'TRANSACTION_VERIFIED'


class Input(NamedTuple):
    from_address: str
    amount: str
    signature: str

    @classmethod
    def new_input(cls, from_address: rsa.RSAPublicKey, amount: Union[int, float, Decimal]) -> Input:
        from_address = crypt.serialize_public_key_as_hex(from_address)
        amount = str(amount)
        return cls(from_address, amount, '')

    def get_digest(self):
        return self.from_address + self.amount


class Output(NamedTuple):
    to_address: str
    amount: Union[int, float, Decimal]

    @classmethod
    def new_output(cls, to_address: rsa.RSAPublicKey, amount: Union[int, float, Decimal]) -> Output:
        to_address = crypt.serialize_public_key_as_hex(to_address)
        amount = str(amount)
        return cls(to_address, amount)

    def get_digest(self):
        return self.to_address + self.amount


class Arbiter(NamedTuple):
    address: str
    signature: str

    @classmethod
    def new_arbiter(cls, address: rsa.RSAPublicKey) -> Arbiter:
        address = crypt.serialize_public_key_as_hex(address)
        return cls(address, '')

    def get_digest(self):
        return self.address


class Transaction(NamedTuple):
    input: Input
    output: Output
    unit: str
    arbiters: Tuple[Arbiter, ...]

    @classmethod
    def new_transaction(cls,
                        from_address: rsa.RSAPublicKey,
                        to_address: rsa.RSAPublicKey,
                        amount: Union[float, int, Decimal],
                        unit: str,
                        arbiter_addresses: Tuple[rsa.RSAPublicKey, ...]) -> Transaction:
        inp = Input.new_input(from_address, amount)
        outp = Output.new_output(to_address, amount)
        arbs = tuple([Arbiter.new_arbiter(addr) for addr in arbiter_addresses])
        return cls(input=inp, output=outp, arbiters=arbs, unit=unit)

    def sign(self, private_key: rsa.RSAPrivateKey) -> VerificationResult:
        for i, v in enumerate(self.inputs):
            addr, amount, sig = v
            if addr == signature.serialize_public_key(private_key.public_key()):
                if sig:
                    return self,  SIGNING_ERROR, 'transaction already signed by this private key'
                signed_input = (addr, amount, signature.sign(self.compute_hash(), private_key))
                new_inputs = self.inputs[:i] + (signed_input,) + self.inputs[i+1:]
                return replace(self, inputs=new_inputs), SIGNED, 'transaction signed'

        for i, v in enumerate(self.required):
            addr, sig = v
            if addr == signature.serialize_public_key(private_key.public_key()):
                if sig:
                    return self, SIGNING_ERROR, 'transaction already signed by this private key'
                required_sig = (addr, signature.sign(self.compute_hash(), private_key))
                new_required = self.required[:i] + (required_sig,) + self.required[i+1:]
                return replace(self, required=new_required), SIGNED, 'transaction signed'

        return self, SIGNING_ERROR, 'not a valid signer'

    def verify(self) -> VerificationResult:
        pass

    def compute_hash(self) -> str:
        digest = ''.join([self.input.get_digest(),
                          self.output.get_digest(),
                          ''.join([arb.get_digest() for arb in self.arbiters])])
        return crypt.compute_hash_as_hex(digest)


class TransactionEvent(DataObject):
    payload: Tuple[Transaction, ...]

    @classmethod
    def new_transactions(cls, transactions: Tuple[Transaction, ...]) -> TransactionEvent:
        return cls(topic=TOPIC_TRANSACTIONS, payload=transactions)

    @classmethod
    def new_transaction(cls, transaction: Transaction) -> TransactionEvent:
        return cls.new_transactions((transaction,))

    def add_transactions(self, transactions: Tuple[Transaction, ...]) -> TransactionEvent:
        return self._replace(payload=self.payload + transactions)

    def add_transaction(self, transaction: Transaction) -> TransactionEvent:
        return  self.add_transactions((transaction,))

    def verify(self) -> VerificationResult:
        pass

    def compute_hash(self) -> str:
        pass

    def payload_as_dict(self) -> Dict[str, Union[str, int, float, List, Dict]]:
        pass

    @staticmethod
    def payload_from_dict(payload: Dict[str, Union[str, int, float, List, Dict]]) -> Transaction:
        pass
