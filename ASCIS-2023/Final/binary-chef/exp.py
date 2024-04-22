#!/usr/bin/env python3
from pwn import *

elf = ELF('./chal')
# libc = ELF('./libc.so.6')
# ld = ELF('./ld-2.35.so')
context.update(binary=elf, log_level='DEBUG')
# p = elf.process()
p = gdb.debug(p, '''
    b *main+
    b *main+751
''')
# gdb.attach(p, '''
# 	b *main+158
# 	b *main+170
# 	b *main+182
# 	''')
# p = remote("139.59.234.167", "13337")

# 0x000000000000187c <+260>:   call   0x13af <_Z13b64_decode_exPKcmPh>
def base642binary(msg):
    p.sendlineafter(b"Hex\n", b"1")
    return

# 0x0000000000001a67 <+751>:   call   0x1717 <_Z10hex_encodePKcmPh>
def binary2hex(msg):
    p.sendlineafter(b"Hex\n", b"2")
    p.sendlineafter(b"enter string:", msg)
    return




p.interactive()
