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
    local array: felt*;
    local eth_address;
    local domain_hash_low;
    local domain_hash_high;
    %{
        import sys
        sys.path.append("/usr/local/lib/python3.9/site-packages")

        import testing
        test1 = testing.Eip712_hashing_test()
        
        sig = test1.get_signature(2137)
        
        ids.eth_address = test1.get_eth_address()

        domain_hash = test1.get_domain_sep()
        ids.domain_hash_low = domain_hash % 2**128
        ids.domain_hash_high = domain_hash // 2**128

        ids.array = array = segments.add()
        for i, val in enumerate(sig):
            memory[array + i] = val
    %}
    let domain_hash = Uint256(domain_hash_low, domain_hash_high);

    add_connection(eth_address, 2137, domain_hash, 5, array);
    return();
}