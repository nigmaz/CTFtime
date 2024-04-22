from pwn import *

def convert_bytes_to_int(a):
	b = 0
	for i in a:
		b = (b << 8) + i
	return b

const0 = bytes.fromhex('D9 E0 8B 0B C5 85 8E 62 EE 0B')[::-1]
const0 = convert_bytes_to_int(const0)
print(f"const0: {const0}")

const1 = bytes.fromhex('55 9E 28 98 C4 05 FE A3 5F 65')[::-1]
const1 = convert_bytes_to_int(const1)
print(f"const1: {const1}")

const2 = bytes.fromhex('01 B1 3D C7 06 7C C9 82 06 14')[::-1]
const2 = convert_bytes_to_int(const2)
print(f"const2: {const2}")

const3 = bytes.fromhex('77 C8 E3 E9 8B 0F 2F D3 AB 10')[::-1]
const3 = convert_bytes_to_int(const3)
print(f"const3: {const3}")

const4 = bytes.fromhex('F1 BD 01 43 24 1A 57 A0 FC 56')[::-1]
const4 = convert_bytes_to_int(const4)
print(f"const4: {const4}")

const5 = bytes.fromhex('3D 18 B7 93 8A C7 31 9C E8 AF')[::-1]
const5 = convert_bytes_to_int(const5)
print(f"const5: {const5}")

const6 = bytes.fromhex('D9 54 6C 74 31 78 70 E6 6D 06')[::-1]
const6 = convert_bytes_to_int(const6)
print(f"const6: {const6}")

const7 = bytes.fromhex('FB DB 27 14 C5 48 F7 14 7D 5C')[::-1]
const7 = convert_bytes_to_int(const7)
print(f"const7: {const7}")

const8 = bytes.fromhex('EF 95 37 7D 7F 73 B9 7F 38 87')[::-1]
const8 = convert_bytes_to_int(const8)
print(f"const8: {const8}")

##################################################################
########## ANTI-DEBUG
operator1 = bytes.fromhex('33 F2 32 07 96 A2 37 9B 9C 5B E0 3A 8B 96 18 D7 4D B2 F6 24')[::-1]
operator1 = convert_bytes_to_int(operator1)
print(f"operator1: {operator1}")

operator2 = bytes.fromhex('FD 4B 48 79 21 23 47 DE 48 17 BC 8D 69 42 43 D1 AF 71 3B 48')[::-1]
operator2 = convert_bytes_to_int(operator2)
print(f"operator2: {operator2}")

operator3 = bytes.fromhex('E3 0C 05 D4 B8 47 D0 FA 70 72 78 44 F6 78 EC E8 91 29 C6 3B')[::-1]
operator3 = convert_bytes_to_int(operator3)
print(f"operator3: {operator3}")

##################################################################
operator1 = bytes.fromhex('')[::-1]
operator1 = convert_bytes_to_int(operator1)
print(f"operator1: {operator1}")

operator2 = bytes.fromhex('')[::-1]
operator2 = convert_bytes_to_int(operator2)
print(f"operator2: {operator2}")

operator3 = bytes.fromhex('')[::-1]
operator3 = convert_bytes_to_int(operator3)
print(f"operator3: {operator3}")
