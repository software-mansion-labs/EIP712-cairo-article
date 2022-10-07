from ast import Constant
import sha3

from eip712_structs import EIP712Struct, Address, String, Uint
from eip712_structs import make_domain
from eth_utils import big_endian_to_int
from coincurve import PrivateKey, PublicKey
from eth_keys import keys
from coincurve.utils import hex_to_bytes


# Etherum private key
PRIVATE_KEY = '4c8d872afd351d5711d1eb31299b8769e9b62c6bcd47fc6904a88b6533fc337a'

# The actual address will be set after contract is deployed, and then domain separator will be a constant
VERYFYING_CONTRACT = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'

# Message structure
class Payload(EIP712Struct):
  myStarkNetAddress = Uint(256)

class Eip712_hashing_test:
    def __init__(self):
        self.pkey = keys.PrivateKey(hex_to_bytes(PRIVATE_KEY))
        self.eth_address = self.pkey.public_key.to_checksum_address()
        self.domain = make_domain(name='TestContract',
                        version='1',
                        verifyingContract=VERYFYING_CONTRACT)

    def get_signature(self, starknet_address):
        # Filling the message structure
        msg = Payload()
        msg['myStarkNetAddress'] = starknet_address

        # Converting it to signable bytes
        signable_bytes = msg.signable_bytes(self.domain)

        # Now ... sign it :)
        signature = self.pkey.sign_msg(signable_bytes)
        
        # Array of 5 128bit integers is expected on the cairo side.
        res = []
        res.append(signature[64]) # v
        res.append(big_endian_to_int(signature[0:16]))  # higher 128 bits of r
        res.append(big_endian_to_int(signature[16:32])) # lower 128 bits of r
        res.append(big_endian_to_int(signature[32:48])) # higher 128 bits of s
        res.append(big_endian_to_int(signature[48:64])) # lower 128 bits of s

        return res

    def get_domain_sep(self):
        return int.from_bytes(self.domain.hash_struct(), "big")

    def get_struct_hash(self):
        msg = Payload()
        return int.from_bytes(msg.type_hash().hex(), "big")

    def get_eth_address(self):
        return int(self.eth_address, 16)
