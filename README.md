## `map.cairo`
Stores pairs of the form `(eth_address: felt, starknet_address)`

## `eip712.cairo`
Function `get_eip712_hash()` calculates hash of a given structure in EIP-712 standard.

## `validate.cairo`
Function `add_connection()` binds ETH adsress to Starknet address if the ETH address matches the message signature which is checked in `is_valid_signature()` function.