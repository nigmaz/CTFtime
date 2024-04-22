def string_to_ascii_hex_array(input_string):
    return [ord(char) for char in input_string]

def decrypt1(input_str, key):
    result = ""
    for char in input_str:
        xor_result = char ^ key
        result += chr(xor_result)
    return result

def decrypt2(input_str, key):
    result = ""
    for i in range(0, 6):
        xor_result = ord(input_str[i]) ^ key[i]
        result += chr(xor_result)
    return result 
	
def decrypt3(ciphertext, key):
    # rc4_decrypt
    S = list(range(256))
    j = 0
    out = []

    # KSA (Key Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA (Pseudo-Random Generation Algorithm)
    i = j = 0
    for char in ciphertext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(char ^ S[(S[i] + S[j]) % 256]))

    return ''.join(out)

def decrypt4(input_str, key):
    result = ""
    for i in range(0, 6):
        xor_result = int(input_str[i]) - ord(key[i])
        result += chr(xor_result)
    return result 

def decrypt5(input_str, key):
    result = ""
    for i in range(0, 6):
        xor_result = int(input_str[i]) + ord(key[i])
        result += chr(xor_result & 0xff)
    return result 


enc_5 = [0x5A, 0x5B, 0x0B, 0x0A, 0x5E, 0x5F]
enc_4 = [0x05, 0x01, 0x06, 0x5B, 0x05, 0x02]
enc_3 = [0x60, 0xE0, 0xE4, 0x2D, 0xFF, 0x97, 0xDD, 0x13, 0xEE, 0xA0, 0x55, 0xF4]
enc_2 = [0x95, 0xC8, 0x95, 0x9D, 0x69, 0x68]
enc_1 = [0x01, 0xFA, 0x06, 0xD2, 0xFF, 0xCE]


result5 = decrypt1(enc_5, 0x69)
print("[+] Result-5: ", result5)

result4 = decrypt2(result5, enc_4)
print("[+] Result-4: ", result4)

a = result4 + result5
print("\n[!] Rc4 key:     ", a)
a = string_to_ascii_hex_array(a)

b = decrypt3(enc_3, a)
print("[!] Rc4 decrypt: ", b)

result2 = b[:6]
result3 = b[-6:]
print("\n[+] Result-2: ", result2)
print("[+] Result-3: ", result3)

result1 = decrypt4(enc_2, result2)
print("[+] Result-1: ", result1)

result0 = decrypt5(enc_1, result3)
print("[+] Result-0: ", result0)


result = "ASCIS{" + result0 + "-" + result1 + "-" + result2 + "-" + result3 + "-" + result4 + "-" + result5 + "}"
print("\nFlag: ", result)
