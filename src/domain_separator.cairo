%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256, uint256_eq
from starkware.cairo.common.cairo_builtins import HashBuiltin

@storage_var
func domain_sep() -> (domain_separator: Uint256) {
}

func get_domain_separator{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}()->(domain_separator: Uint256){
    alloc_locals;
    let (domain_separator: Uint256) = domain_sep.read();
    let (check) = uint256_eq(domain_separator, Uint256(0,0));
    with_attr error_message(
        "Domain separator hash must be set before use."
    ){
        assert check = 0;
    }
    return (domain_separator = domain_separator);
}

@external
func set_domain_separator{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(domain_separator: Uint256){
    alloc_locals;
    let (domain_separator_check) = domain_sep.read();
    let (check) = uint256_eq(domain_separator_check, Uint256(0,0));
    with_attr error_message(
        "Domain separator hash can only be set once."
    ){
        assert check = 1;
    }
    domain_sep.write(domain_separator);
    return();
}