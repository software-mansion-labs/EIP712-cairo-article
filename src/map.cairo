%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_nn

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