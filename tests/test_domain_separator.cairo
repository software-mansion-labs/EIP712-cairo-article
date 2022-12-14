%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256

from src.domain_separator import get_domain_separator, set_domain_separator

@external
func test_domain_sep{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(){

    set_domain_separator(Uint256(42,2137732142069));
    let (domain_sep) = get_domain_separator();
    assert domain_sep = Uint256(42,2137732142069);
    return ();
}