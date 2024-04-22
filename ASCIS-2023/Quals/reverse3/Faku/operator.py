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
    bytes.fromhex('33 F2 32 07 96 A2 37 9B 9C 5B E0 3A 8B 96 18 D7 4D B2 F6 24')[::-1],
    bytes.fromhex('FD 4B 48 79 21 23 47 DE 48 17 BC 8D 69 42 43 D1 AF 71 3B 48')[::-1],
    bytes.fromhex('E3 0C 05 D4 B8 47 D0 FA 70 72 78 44 F6 78 EC E8 91 29 C6 3B')[::-1]
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



