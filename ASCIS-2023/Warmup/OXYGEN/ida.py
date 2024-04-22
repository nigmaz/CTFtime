import ida_bytes


array_start_address = 0x14002D000
array_length = 123

for i in range(array_length):
    byte_address = array_start_address + i
    current_byte = ida_bytes.get_byte(byte_address)
    new_byte = current_byte ^ 0x69
    ida_bytes.patch_byte(byte_address, new_byte)

# - `Edit -> Segments -> Rebase Program...`.
