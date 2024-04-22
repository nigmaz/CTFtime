license = b""
part1 = b"X"
part2 = b"1"
part3 = b""
part4 = b"br0"

### part2 FLAG ###
s = b'd0j6'
for i in range(3):
    token = 0
    if i % 2 == 0:
        part2 += bytes([s[i] - part2[-1]])
    else:
        part2 += bytes([part2[-1] - s[i] + 0x30])

### part3 FLAG ###
for i in range(32, 127):
    for j in range(32, 127):
        if 0xD6A6 == ((i << 8) + j) ^ 0xBEEF:
            part3 = (chr(i) + chr(j)).encode()


license = part1 + b"-" + part2 + b"-" + part3 + b"-" + part4
print(license)
