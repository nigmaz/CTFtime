from pwn import * 
check_buf = "n[}>}C]qRm[" 
result = "" 
 
for i in range(0, len(check_buf)): 
    if i % 2 == 0: 
        for a in range(0, 0xff): 
            if (a | 0xA) - (a & 0xA) == ord(check_buf[i]): 
                result += chr(a) 
    else: 
        for a in range(0, 0xff): 
            if (a | 0xA) + (a & 0xA) == ord(check_buf[i]): 
                result += chr(a) 

print("[+] Bruteforce Input: ", result)


p = remote("127.0.0.1", "1337") 
p.sendline(result.encode()) 
flag = p.recvuntil(b"}")
print(flag)

