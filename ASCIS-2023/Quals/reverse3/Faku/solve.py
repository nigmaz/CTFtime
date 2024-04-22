from pwn import *
from z3 import *
import struct

# Your function for converting bytes to int
def convert_bytes_to_int(a):
    b = 0
    for i in a:
        b = (b << 8) + i
    return b

# Constants from bytes
constants = [
    bytes.fromhex('D9 E0 8B 0B C5 85 8E 62 EE 0B')[::-1],
    bytes.fromhex('55 9E 28 98 C4 05 FE A3 5F 65')[::-1],
    bytes.fromhex('01 B1 3D C7 06 7C C9 82 06 14')[::-1],
    bytes.fromhex('77 C8 E3 E9 8B 0F 2F D3 AB 10')[::-1],
    bytes.fromhex('F1 BD 01 43 24 1A 57 A0 FC 56')[::-1],
    bytes.fromhex('3D 18 B7 93 8A C7 31 9C E8 AF')[::-1],
    bytes.fromhex('D9 54 6C 74 31 78 70 E6 6D 06')[::-1],
    bytes.fromhex('FB DB 27 14 C5 48 F7 14 7D 5C')[::-1],
    bytes.fromhex('EF 95 37 7D 7F 73 B9 7F 38 87')[::-1]
]

operators = [
	bytes.fromhex('43 E6 0E 73 C4 FA 26 37 D7 F8 C3 2C C8 57 8A 8F AA 01 86 0D')[::-1],
	bytes.fromhex('F7 61 51 E7 0A 93 04 B8 CD 0C 78 1C 0E 20 3F D2 0A 65 05 65')[::-1],
	bytes.fromhex('83 30 E8 FE 14 CD 10 7E 43 36 86 C3 CA E1 1A 98 E8 7D B1 4D')[::-1]
]

# Convert constants to integers
constants = [convert_bytes_to_int(const) for const in constants]

# Define operators
operators = [convert_bytes_to_int(opt) for opt in operators]

# Khởi tạo các biến
input0, input1, input2 = Ints('input0 input1 input2')

# # Khởi tạo Solver
solver = Solver()

# Thêm các ràng buộc vào solver
solver.add(input0 * constants[0] + input1 * constants[1] - input2 * constants[2] == operators[0])
solver.add(input0 * constants[3] + input1 * constants[4] + input2 * constants[5] == operators[1])
solver.add(input0 * constants[6] - input1 * constants[7] - input2 * constants[8] == 0 - operators[2])

# Kiểm tra xem hệ phương trình có thể giải được không
if solver.check() == sat:
    model = solver.model()
    print("input0 =", model[input0])
    print("input1 =", model[input1])
    print("input2 =", model[input2])
    input0 = (model[input0]).as_long()
    input1 = (model[input1]).as_long()
    input2 = (model[input2]).as_long()
    input0, input1, input2 = abs(int(input0)), abs(int(input1)), abs(int(input2))

    flag = input0.to_bytes((input0.bit_length() + 7) // 8, 'big')
    flag += input1.to_bytes((input1.bit_length() + 7) // 8, 'big')
    flag += input2.to_bytes((input2.bit_length() + 7) // 8, 'big')
    print("FLAG: ", flag)
else:
    print("Fail!!!")



