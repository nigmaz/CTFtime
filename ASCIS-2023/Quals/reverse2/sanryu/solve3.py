def rol(a, x):
    tmp = bin(a)[2:].rjust(8, '0')
    return int(tmp[x:] + tmp[:x], 2)

data = [0xD7, 0x9E, 0xCA, 0x51, 0xA4, 0xEB, 0x8A, 0x48, 0x2B, 0xBE, 
  0x62, 0x04, 0x96, 0x2B, 0xD7, 0x11, 0xDB, 0x63, 0xFA]

rol_count = [0xf3a8d24e, 0x57286251, 0xed0bb215, 0xc54297c6, 0x1372d3d1, 0x9aebb2fd,
      0x4074858d, 0xd8f50000, 0x95e8f163, 0x325640e9, 0x6c750331, 0x86a54774,
      0xd88dda56, 0xfbd660c5, 0x77f412ae, 0x9077a73e, 0xb8817c4e, 0xb4a4110c,
      0xbc4e8a99, 0x409d7713, 0x935c8213]


for a in data:
    print(bin(a)[2:].rjust(8, '0'))

for i in range(min(len(rol_count), len(data))):
    print(end=chr(rol(data[i], 8 - (rol_count[i] % 8))))


# import idc

# def read_data(start_address, count):
#     data = []

#     for i in range(count):
#         value = idc.get_wide_dword(start_address + i * 4)
#         data.append(hex(value))

#     return data

# start_address = 0x000000E3B74FF2A0
# value_count = 628

# data = read_data(start_address, value_count)

# print(data)


