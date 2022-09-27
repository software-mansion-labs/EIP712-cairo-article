%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256

from src.validate import add_connection
 
@external
func test_validate_add{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
    bitwise_ptr : BitwiseBuiltin*
}(){
    alloc_locals;
    local eth_address;
    local domain_hash_low;
    local domain_hash_high;
    local v;
    local r_low;
    local r_high;
    local s_low;
    local s_high;
    %{
        import sys
        sys.path.append("/usr/local/lib/python3.9/site-packages")

        import testing
        test1 = testing.Eip712_hashing_test()
        
        sig = test1.get_signature(314141244)
        
        ids.eth_address = test1.get_eth_address()

        domain_hash = test1.get_domain_sep()
        ids.domain_hash_low = domain_hash % 2**128
        ids.domain_hash_high = domain_hash // 2**128

        ids.v = sig[0]
        ids.r_high = sig[1]
        ids.r_low = sig[2]
        ids.s_high = sig[3]
        ids.s_low = sig[4]
    %}
    let domain_hash = Uint256(domain_hash_low, domain_hash_high);
    let (array: felt*) = alloc();
    assert array[0] = v;
    assert array[1] = r_high;
    assert array[2] = r_low;
    assert array[3] = s_high;
    assert array[4] = s_low;
    add_connection(eth_address, 314141244, domain_hash, 5, array);
    return();
}