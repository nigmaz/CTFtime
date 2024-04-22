### 'Input: '
Format = 0xAD597B65781B4B08.to_bytes(8, byteorder='little')
hex_array = [hex(byte) for byte in Format]
input = [0x41, 0x25, 0x6B, 0x0D, 0x11, 0x41, 0x79, 0xAD]

for i in range(0, 8):
	hex_array[i] = int(hex_array[i], 16) ^ input[i]

for byte in hex_array:
    print(chr(byte), end='')
print('\n')

### 'WTF!'
Format = 0xC31544B581A6.to_bytes(8, byteorder='little')
hex_array = [hex(byte) for byte in Format]
input = [0xf1, 0xd5, 0xf3, 0x65, 0x1f, 0xc3, 0x00, 0x00]

for i in range(0, 8):
	hex_array[i] = int(hex_array[i], 16) ^ input[i]

for byte in hex_array:
    print(chr(byte), end='')
print('\n')

### 'ntdll.dl'
Format = 0x4759E1D9D9B7E115.to_bytes(8, byteorder='little')
hex_array = [hex(byte) for byte in Format]
input = [0x7b, 0x95, 0xd3, 0xb5, 0xb5, 0xcf, 0x3d, 0x2b]

for i in range(0, 8):
	hex_array[i] = int(hex_array[i], 16) ^ input[i]

for byte in hex_array:
    print(chr(byte), end='')
print('\n')

###############################################################################################################
### XOR in fn_checkInput()
a = bytes.fromhex('C1B762F697A76872A7BA15F990B37E7D')
b = bytes.fromhex('D6B71BF4EDAA7671C9B912F098B3667E')
c = bytes.fromhex('93E357BDDFFF2F2793E357BDDFFF2F27')

str1 = []
str2 = []
for i, j in zip(a, c):
	str1.append(chr(i ^ j))
str1 = ''.join(str1[::-1])
print(str1)

for i, j in zip(b, c):
	str2.append(chr(i ^ j))
str2 = ''.join(str2[::-1])
print(str2)
print(str1 + str2)

a = 0x27 ^ 0x27 # 0x127 ^ 0x27
print(chr(a))

# from pwn import xor

# print(xor([0x7D, 0x7E, 0xB3, 0x90, 0xF9, 0x15, 0xBA, 0xA7, 0x72, 0x68, 
#   0xA7, 0x97, 0xF6, 0x62, 0xB7, 0xC1, 0x7E, 0x66, 0xB3, 0x98, 0xF0, 0x12, 0xB9, 0xC9, 0x71, 0x76, 
#   0xAA, 0xED, 0xF4, 0x1B, 0xB7, 0xD6], [0x27, 0x2F, 0xFF, 0xDF, 0xBD, 0x57, 0xE3, 0x93, 0x27, 0x2F, 
#   0xFF, 0xDF, 0xBD, 0x57, 0xE3, 0x93]))

##############################################################################################################



