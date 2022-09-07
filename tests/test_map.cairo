%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

from src.map import map_adresses, are_connected
 
@external
func test_map_add{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}():
    alloc_locals
    map_adresses(2137, 69)
    map_adresses(3231, 2532)
    map_adresses(1, 2)
    
    # Check mapped addresses
    let (conection) = are_connected(2137, 69)
    assert conection = 1
     
    let (conection) = are_connected(3231, 2532)
    assert conection = 1
    
    let (conection) = are_connected(1, 2)
    assert conection = 1
    
    # Check example non-mapped addresses 
    let (conection) = are_connected(3, 1)
    assert conection = 0
    return ()
end