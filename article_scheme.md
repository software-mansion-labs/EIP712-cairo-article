# EIP712 authentication in cairo 
## Link to protostar [article](https://blog.swmansion.com/testing-starknet-contracts-made-easy-with-protostar-2ecdad3c9133) and a little explanation
## Link to EIP712 [documentation](https://eips.ethereum.org/EIPS/eip-712) with some basic background 
## Use case - creating a binding between ETH adress and Starknet Address
## Pair map code
```cairo
using Pair = (eth_address : felt, starknet_address : felt)

@storage_var
func storage(addresses: Pair) -> (exists: felt):
end

func map_adresses{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}(eth_address: felt, starknet_address: felt):

    let addresses : Pair = (eth_address = eth_address, starknet_address = starknet_address)

    storage.write(addresses, 1)
    return ()
end

func are_connected{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}(eth_address: felt, starknet_address: felt) -> (res : felt):
    let addresses : Pair = (eth_address = eth_address, starknet_address = starknet_address)
    let (res) = storage.read(addresses=addresses)
    return (res)
end
```
Quick explenation on how it works (storage vars are explained in the protostar article)

## EIP-712 hashing code with some basic eplanation
```cairo
 func get_hash{range_check_ptr,  keccak_ptr: felt*, bitwise_ptr : BitwiseBuiltin*}(starknetAddress: felt, domain_hash : Uint256) -> (
        hashed_msg : Uint256):
    alloc_locals

    let (starknetAddress_h, starknetAddress_l) = split_felt(starknetAddress)

    let (encoded_data : Uint256*) = alloc()
    assert encoded_data[0] = Uint256(TYPE_HASH_LOW, TYPE_HASH_HIGH)
    assert encoded_data[1] = Uint256(starknetAddress_l, starknetAddress_h)
    let (data_hash) = keccak_uint256s_bigend{keccak_ptr=keccak_ptr}(2, encoded_data)

    let prefix = PREFIX
    let (w1, prefix) = add_prefix(domain_hash.high, prefix)
    let (w0, prefix) = add_prefix(domain_hash.low, prefix)
    let (w3, prefix) = add_prefix(data_hash.high, prefix)
    let (w2, overflow) = add_prefix(data_hash.low, prefix)
    let (signable_bytes : Uint256*) = alloc()
    assert signable_bytes[0] = Uint256(w0, w1)
    assert signable_bytes[1] = Uint256(w2, w3)
    assert signable_bytes[2] = Uint256(overflow, 0)
    let (res) = keccak_uint256s_bigend{keccak_ptr=keccak_ptr}(2, signable_bytes)
    return (res)
end
```

## Explanation of the const variables such as TYPE_HASH and DOMAIN_SEPARATOR

## Validation of the ETH address code with some explanation

## Deploying the contract
