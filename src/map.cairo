%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_nn


@storage_var
func storage(eth_address : felt, starknet_address : felt) -> (exists: felt):
end

func save_connected_addresses{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}(eth_address: felt, starknet_address: felt):

    storage.write(eth_address, starknet_address, 1)
    return ()
end

func are_addresses_connected{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}(eth_address: felt, starknet_address: felt) -> (res : felt):
    let (res) = storage.read(eth_address, starknet_address)
    return (res)
end