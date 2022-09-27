%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

from src.map import save_connected_addresses, are_addresses_connected
 
@external
func test_map_add{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}(){
    alloc_locals;
    save_connected_addresses(2137, 69);
    save_connected_addresses(3231, 2532);
    save_connected_addresses(1, 2);
    
    //Check mapped addresses
    let (conection) = are_addresses_connected(2137, 69);
    assert conection = 1;
     
    let (conection) = are_addresses_connected(3231, 2532);
    assert conection = 1;
    
    let (conection) = are_addresses_connected(1, 2);
    assert conection = 1;
    
    //Check example non-mapped addresses
    let (conection) = are_addresses_connected(3, 1);
    assert conection = 0;
    return ();
}