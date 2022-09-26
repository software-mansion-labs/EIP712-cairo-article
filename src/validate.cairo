%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.cairo.common.math import assert_in_range, assert_not_equal, assert_not_zero, assert_250_bit, assert_lt_felt, split_felt
from starkware.cairo.common.uint256 import Uint256, uint256_check
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_secp.signature import verify_eth_signature_uint256, recover_public_key, public_key_point_to_eth_address
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from starkware.cairo.common.cairo_secp.bigint import (
    BigInt3,
    uint256_to_bigint,
)
from starkware.cairo.common.serialize import serialize_word
from src.eip712 import get_hash
from src.map import save_connected_addresses, are_addresses_connected

@external
func add_connection{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(eth_address : felt, starknet_address : felt, domain_hash: Uint256, signature_len: felt, signature: felt*){
    assert_valid_eth_signature(eth_address, starknet_address, domain_hash, signature_len, signature);
    save_connected_addresses(eth_address, starknet_address);
    return ();
}

func assert_valid_eth_signature{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*
}(eth_address: felt, starknet_address: felt, domain_hash: Uint256, signature_len: felt, signature: felt*){
    alloc_locals;
    with_attr error_message(
        "Invalid signature length. Signature should have exactly 5 elements."
    ){
        assert signature_len = 5;
    }

    let v = signature[0];
    let r = Uint256(signature[2], signature[1]);
    let s = Uint256(signature[4], signature[3]);
    
    let (local keccak_ptr_start) = alloc();
    let keccak_ptr = keccak_ptr_start;

    let (hash_uint) = get_hash{keccak_ptr=keccak_ptr}(starknet_address, domain_hash);
   
    verify_eth_signature_uint256{keccak_ptr=keccak_ptr}(hash_uint, r, s, v, eth_address);

    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr);

    return ();
}


