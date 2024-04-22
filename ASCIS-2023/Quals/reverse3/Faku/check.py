from pwn import *

def convert_bytes_to_int(a):
	b = 0
	for i in a:
		b = (b << 8) + i
	return b

num1 = bytes.fromhex('D9 E0 8B 0B C5 85 8E 62 EE 0B')[::-1]
num1 = convert_bytes_to_int(num1)

# x = convert_bytes_to_int(b"\x61" * 10)
num2 = bytes.fromhex('61 61 61 61 61 61 61 61 61 61')[::-1]
num2 = convert_bytes_to_int(num2)
print(hex(num1 * num2))

# FAKU{N3V3R_9onn4_91v3_yOU_uP!}
# input1 = bytes.fromhex('52 33 56 33 4E 7B 55 4B 41 46')[::-1]
# input1 = convert_bytes_to_int(input1)
# print(input1)

# input2 = bytes.fromhex('76 31 39 5F 34 6E 6E 6F 39 5F')[::-1]
# input2 = convert_bytes_to_int(input2)
# print(input2)

# input3 = bytes.fromhex('7D 21 50 75 5F 55 4F 79 5F 33')[::-1]
# input3 = convert_bytes_to_int(input3)
# print(input3)

