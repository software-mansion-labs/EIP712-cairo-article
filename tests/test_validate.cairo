%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

from src.validate import add_connection
 
@external
func test_validate_add{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}():
    alloc_locals
    %{
        import os
        import sys
        print(os.environ['PYTHONPATH'])
        #print(sys.path)
        #sys.path.append("/Users/jakubszmurlo/eip712/eip712")
        import testing
    %}
    return ()
end