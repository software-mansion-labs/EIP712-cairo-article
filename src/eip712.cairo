%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import split_felt, assert_not_equal, unsigned_div_rem
from starkware.cairo.common.uint256 import Uint256, word_reverse_endian
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin
from starkware.cairo.common.bitwise import bitwise_and
from starkware.cairo.common.cairo_keccak.keccak import keccak_uint256s, keccak_uint256s_bigend, keccak_bigend


const DIVISOR = 2**64;

const PREFIX = 0x1901;

// A Hash of a structure that we're signing (Payload) which is shown in ../struct.json file 
const TYPE_HASH_HIGH = 0x065712a4b704d4db141ac23cc21f8064;
const TYPE_HASH_LOW = 0x1aa16b709432aa6609751730017007d8;

// Splits 128bit big endian int to 2 64bit small endian ints
func split_to_64bit_small_endian_words{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(value: felt) -> (high: felt, low: felt){
    let (temp) = word_reverse_endian(value);
    let (high, low) = unsigned_div_rem(temp, DIVISOR);
    return (high, low);
}
// Changes input format to array of 64bit values in little endian format
func populate_array_little_end{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(w0: felt, w1: felt, w2: felt, w3: felt, overflow: felt, signable_bytes : felt*){
    
    let (high, low) = split_to_64bit_small_endian_words(w0);
    assert signable_bytes[0] = low;
    assert signable_bytes[1] = high;

    let (high, low) = split_to_64bit_small_endian_words(w1);
    assert signable_bytes[2] = low;
    assert signable_bytes[3] = high;

    let (high, low) = split_to_64bit_small_endian_words(w2);
    assert signable_bytes[4] = low;
    assert signable_bytes[5] = high;

    let (high, low) = split_to_64bit_small_endian_words(w3);
    assert signable_bytes[6] = low;
    assert signable_bytes[7] = high;

    // Overflow is only 2 bytes long
    let (temp) = word_reverse_endian(overflow);
    let (value8, trash) = unsigned_div_rem(temp, 2**112);
    assert signable_bytes[8] = value8;

    return ();
}

// value has to be a 16 byte word
// prefix length = PREFIX_BITS
func add_prefix{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(value : felt, prefix : felt) -> (
        result : felt, overflow: felt){
    let shifted_prefix = prefix * 2 ** 128;
    // with_prefix is 18 bytes long
    let with_prefix = shifted_prefix + value;
    let overflow_mask = 2 ** 16 - 1;
    let (overflow) = bitwise_and(with_prefix, overflow_mask);
    let result = (with_prefix - overflow) / 2 ** 16;
    return (result, overflow);
}

func get_eip712_hash{range_check_ptr,  keccak_ptr: felt*, bitwise_ptr : BitwiseBuiltin*}(starknet_address: felt, domain_hash : Uint256) -> (
        hashed_msg : Uint256){

    let (starknet_address_h, starknet_address_l) = split_felt(starknet_address);
    
    let (encoded_data : Uint256*) = alloc();
    assert encoded_data[0] = Uint256(TYPE_HASH_LOW, TYPE_HASH_HIGH);
    assert encoded_data[1] = Uint256(starknet_address_l, starknet_address_h);
    let (data_hash) = keccak_uint256s_bigend{keccak_ptr=keccak_ptr}(2, encoded_data);

    let prefix = PREFIX;
    let (w0, prefix) = add_prefix(domain_hash.high, prefix);
    let (w1, prefix) = add_prefix(domain_hash.low, prefix);
    let (w2, prefix) = add_prefix(data_hash.high, prefix);
    let (w3, overflow) = add_prefix(data_hash.low, prefix);
    
    let (signable_bytes : felt*) = alloc();
    
    // w0, w1, w2, w3, and overflow need to be split into 64 bit chunks in little endian format
    populate_array_little_end(w0, w1, w2, w3, overflow, signable_bytes);

    // final value is 66 bytes long 
    let (res) = keccak_bigend{keccak_ptr=keccak_ptr}(signable_bytes, 66);
    
    return (hashed_msg = res);  
}